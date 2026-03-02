from __future__ import annotations

import hashlib
import uuid
from datetime import date, datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import settings
from deps import get_db
from models import (
    Community_Phone_Verification,
    Community_User,
    Notification,
    Phone,
    Point,
    Referral,
)

from .logic import _apply_user_grade_upgrade
from .notifications import notify_admin_acknowledged_event
from .phone import _is_valid_korean_phone, _normalize_phone
from .referral_code import assign_referral_code

router = APIRouter()

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES


class LoginRequest2(BaseModel):
    username: str
    password: str
    push_token: str | None = None


class LoginResponse(BaseModel):
    user_id: int
    token: str


class SignupRequest_C(BaseModel):
    username: str = Field(min_length=2, max_length=50)
    password: str = Field(min_length=2, max_length=255)
    password_confirm: str = Field(min_length=2, max_length=255)
    name: str | None = Field(default=None, max_length=50)
    phone_number: str | None = Field(default=None, max_length=20)
    phone_verification_id: str | None = Field(default=None, max_length=80)
    region: str | None = Field(default=None, max_length=100)
    referral_code: str | None = Field(default=None, max_length=20)
    # community_users 신규 필드(2026-01)
    marketing_consent: bool = False
    custom_industry_codes: list[str] = Field(default_factory=list)
    custom_region_codes: list[str] = Field(default_factory=list)
    # 지역현장: 선호지역(세부지역 포함)
    area_region_codes: list[str] = Field(default_factory=list)
    # 맞춤현장: 모집(총괄/본부장/팀장/팀원/기타)
    custom_role_codes: list[str] = Field(default_factory=list)


@router.post("/community/signup")
def community_signup(req: SignupRequest_C, db: Session = Depends(get_db)):
    if db.query(Community_User).filter(Community_User.username == req.username).first():
        return {"status": 1}

    if req.password != req.password_confirm:
        return {"status": 2}

    if req.name is None:
        return {"status": 3}

    if req.phone_number is None:
        return {"status": 4}

    # 휴대폰 인증 강제
    digits = _normalize_phone(req.phone_number)
    if not _is_valid_korean_phone(digits):
        raise HTTPException(status_code=400, detail="invalid phone_number")

    if not req.phone_verification_id:
        return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}
    try:
        vid = uuid.UUID(req.phone_verification_id)
    except Exception:
        return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}

    vrow = db.query(Community_Phone_Verification).filter(Community_Phone_Verification.id == vid).first()
    now = datetime.now(tz=timezone.utc)
    if (
        (not vrow)
        or (vrow.phone_number != digits)
        or (vrow.verified_at is None)
        or (vrow.expires_at is not None and vrow.expires_at <= now)
    ):
        return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}

    # community_users 테이블 기준 "동일 휴대폰 번호" 중복 가입 차단
    # (과거 데이터에 하이픈이 포함되어 있을 수 있어 숫자만 비교)
    try:
        dialect = db.get_bind().dialect.name
    except Exception:
        dialect = ""

    if dialect == "postgresql":
        phone_already_registered = (
            db.query(Community_User.id)
            .filter(func.regexp_replace(Community_User.phone_number, r"[^0-9]", "", "g") == digits)
            .first()
            is not None
        )
    else:
        rows = db.query(Community_User).filter(Community_User.phone_number.isnot(None)).all()
        phone_already_registered = any(_normalize_phone(u.phone_number or "") == digits for u in rows)

    if phone_already_registered:
        return {"status": 10, "detail": "이미 등록된 휴대폰 번호가 있습니다."}

    if req.region is None:
        return {"status": 3}

    # phone 테이블 기준 "기존에 사용된 번호"인지 확인 (추천인 시스템 차단용)
    phone_already_saved = db.query(Phone.id).filter(Phone.phone == digits).first() is not None

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()

    user = Community_User(
        username=req.username,
        password_hash=pw_hash,
        name=req.name,
        phone_number=digits,
        region=req.region,
        signup_date=date.today(),
        # 정책(2026-01): 일반회원 기본 등급은 -1
        user_grade=-1,
        marketing_consent=bool(req.marketing_consent),
        custom_industry_codes=list(req.custom_industry_codes or []),
        custom_region_codes=list(req.custom_region_codes or []),
        area_region_codes=list(getattr(req, "area_region_codes", None) or []),
        custom_role_codes=list(getattr(req, "custom_role_codes", None) or []),
    )
    db.add(user)
    db.flush()

    # referral_code 생성 및 할당
    try:
        assign_referral_code(db, user, req.phone_number)
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        print(f"[ERROR] referral_code 할당 중 예상치 못한 오류: {e}")
        raise HTTPException(status_code=500, detail="회원가입 처리 중 오류가 발생했습니다")

    # phone 테이블에 번호 영구 저장 (중복이면 삽입 스킵)
    if not phone_already_saved:
        db.add(Phone(phone=digits))

    SIGNUP_BONUS = 500
    REFERRAL_BONUS_REFERRED = 1000 # - 타인의 의해 추천받은 회원
    REFERRAL_BONUS_REFERRER = 5000  # - 추천하고 가입한 회원
    signup_bonus_amount = 0
    referral_bonus_referred_amount = 0
    referral_bonus_referrer_amount = 0

    input_code = (req.referral_code or "").strip()

    # 정책:
    # - 추천인코드 미기입 시에만 가입 포인트 500P 지급
    # - 추천인코드 기입 + (phone 테이블에 없는 번호)일 때만 추천인 시스템(추천인 5000P / 피추천인 1000P) 적용
    # - 추천인코드 기입했더라도, phone 테이블에 이미 저장된 번호면 추천인 시스템은 "완전 미적용"(코드 검증/포인트/원장/알림 모두 스킵)
    if not input_code:
        signup_bonus_amount = SIGNUP_BONUS
        user.point_balance = int(user.point_balance or 0) + SIGNUP_BONUS
        db.add(Point(user_id=user.id, reason="signup_bonus", amount=SIGNUP_BONUS))

    # 추천인코드가 있을 때: phone 중복이면 "추천인 시스템 완전 미적용"
    if input_code and (not phone_already_saved):
        # 본인 코드로 추천 방지(가입 직후 생성된 코드와 동일할 가능성도 있어 체크)
        if user.referral_code and input_code == user.referral_code:
            db.rollback()
            return {"status": 6, "detail": "본인 추천인코드는 사용할 수 없습니다."}

        referrer = db.query(Community_User).filter(Community_User.referral_code == input_code).first()
        if not referrer:
            db.rollback()
            return {"status": 6, "detail": "추천인코드가 올바르지 않습니다."}

        try:
            db.add(
                Referral(
                    referrer_user_id=referrer.id,
                    referred_user_id=user.id,
                    referrer_code=input_code,
                )
            )
            db.flush()  # 아래 추천인 수 집계에 방금 추가한 Referral이 포함되도록

            referred_bonus = int(REFERRAL_BONUS_REFERRED)
            referrer_bonus = int(REFERRAL_BONUS_REFERRER)
            referral_bonus_referred_amount = referred_bonus
            referral_bonus_referrer_amount = referrer_bonus

            # 추천인 포인트 적립
            referrer.point_balance = int(referrer.point_balance or 0) + referrer_bonus
            db.add(
                Point(
                    user_id=referrer.id,
                    reason="referral_bonus_referrer",
                    amount=referrer_bonus,
                )
            )

            # --- 추천인 수 기반 자동 등급 동기화(등급 상승 시 보상 지급) ---
            ref_cnt = db.query(func.count(Referral.id)).filter(Referral.referrer_user_id == referrer.id).scalar() or 0
            _apply_user_grade_upgrade(db, referrer, int(ref_cnt))

            # 피추천인 포인트 적립
            user.point_balance = int(user.point_balance or 0) + referred_bonus
            db.add(
                Point(
                    user_id=user.id,
                    reason="referral_bonus_referred",
                    amount=referred_bonus,
                )
            )

            # 추천인에게 "미확인 알림" 누적(앱 실행 시 Alert로 보여주기 위함)
            db.add(
                Notification(
                    user_id=int(referrer.id),
                    type="referral",
                    title="추천인 가입 포인트 지급",
                    body=f"{user.username}님이 추천인코드로 가입하여 {referrer_bonus}점이 지급되었습니다.",
                    data={
                        "referred_username": user.username,
                        "amount": referrer_bonus,
                        "reason": "referral_bonus_referrer",
                    },
                    is_read=False,
                )
            )

        except IntegrityError as e:
            # 사용자 요청에 따라 referral/point 테이블 제약조건을 제거하므로
            # 여기서는 "1회 제한" 같은 메시지를 내지 않고, DB 오류로만 처리합니다.
            db.rollback()

            pgcode = getattr(getattr(e, "orig", None), "pgcode", None)

            # FK violation (23503): 대부분 referral/point 테이블 FK가 users(id)를 참조하는데
            # 앱은 community_users(id)를 넣는 경우 발생
            if pgcode == "23503":
                return {
                    "status": 8,
                    "detail": "DB 제약조건(FK) 오류로 추천인 포인트 지급에 실패했습니다. referral/point 테이블 FK가 community_users(id)를 참조하는지 확인해주세요.",
                }

            return {"status": 8, "detail": "추천인 처리 중 DB 오류가 발생했습니다."}

    db.commit()
    db.refresh(user)

    # 회원가입 푸쉬 알림(관리자 대상: admin_acknowledged=True) - 실패해도 회원가입 성공 처리
    try:
        notify_admin_acknowledged_event(
            db,
            title="회원가입 알림",
            body=f"새 회원 가입: {user.username}",
            data={"event": "signup", "username": user.username},
        )
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        print("[WARN] notify_admin_acknowledged_event(signup) failed:", e)

    return {
        "status": 0,
        "signup_bonus_amount": signup_bonus_amount,
        "referral_bonus_referred_amount": referral_bonus_referred_amount,
        "referral_bonus_referrer_amount": referral_bonus_referrer_amount,
    }


@router.post("/community/login", response_model=LoginResponse)
def community_login(req: LoginRequest2, db: Session = Depends(get_db)):
    user = db.query(Community_User).filter(Community_User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()
    if user.password_hash != pw_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if req.push_token:
        user.push_token = req.push_token
        db.commit()

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": str(user.id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

    return LoginResponse(user_id=user.id, token=token)

