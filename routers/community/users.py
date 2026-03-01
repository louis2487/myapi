from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from deps import get_db
from models import Community_Post, Community_User, Post_Like, Referral

from .logic import _apply_user_grade_upgrade
from .notifications import notify_admin_acknowledged_event
from .phone import _normalize_phone, _require_verified_phone

router = APIRouter()


@router.get("/community/user/{username}")
def get_user(username: str, db: Session = Depends(get_db)):
    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1}

    signup_date_str = user.signup_date.isoformat() if user.signup_date else None
    popup_last_seen_at_str = (
        user.popup_last_seen_at.isoformat() if getattr(user, "popup_last_seen_at", None) else None
    )
    last_attendance_date_str = (
        user.last_attendance_date.isoformat() if getattr(user, "last_attendance_date", None) else None
    )

    return {
        "status": 0,
        "user": {
            "username": username,
            "name": user.name,
            "phone_number": user.phone_number,
            "region": user.region,
            "signup_date": signup_date_str,
            "point_balance": user.point_balance if user.point_balance is not None else 0,
            "cash_balance": user.cash_balance if user.cash_balance is not None else 0,
            "admin_acknowledged": user.admin_acknowledged if user.admin_acknowledged is not None else False,
            "referral_code": user.referral_code,
            "custom_industry_codes": list(getattr(user, "custom_industry_codes", None) or []),
            "custom_region_codes": list(getattr(user, "custom_region_codes", None) or []),
            "area_region_codes": list(getattr(user, "area_region_codes", None) or []),
            "custom_role_codes": list(getattr(user, "custom_role_codes", None) or []),
            "popup_last_seen_at": popup_last_seen_at_str,
            "last_attendance_date": last_attendance_date_str,
            "marketing_consent": bool(getattr(user, "marketing_consent", False)),
        },
    }


class UserUpdateRequest(BaseModel):
    username: str | None = Field(default=None, min_length=2, max_length=50)  # 새 아이디
    password: str | None = Field(default=None, min_length=2, max_length=255)
    password_confirm: str | None = Field(default=None, min_length=2, max_length=255)
    name: str | None = Field(default=None, max_length=50)  # 실명
    phone_number: str | None = Field(default=None, max_length=20)
    phone_verification_id: str | None = Field(default=None, max_length=80)
    region: str | None = Field(default=None, max_length=100)
    # community_users 신규 필드(2026-01)
    marketing_consent: bool | None = None
    custom_industry_codes: list[str] | None = None
    custom_region_codes: list[str] | None = None
    area_region_codes: list[str] | None = None
    custom_role_codes: list[str] | None = None


@router.put("/community/user/{username}")
def update_user(username: str, req: UserUpdateRequest, db: Session = Depends(get_db)):
    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1}  # 유저 없음

    old_username = None

    # 닉네임 변경
    if req.username is not None and req.username != username:
        new_username = req.username
        exists = db.query(Community_User).filter(Community_User.username == new_username).first()
        if exists:
            return {"status": 2}  # 닉네임 중복

        old_username = username
        user.username = new_username
        db.flush()

        db.query(Post_Like).filter(Post_Like.username == old_username).update(
            {"username": new_username},
            synchronize_session=False,
        )

    if req.password is not None:
        if req.password_confirm is None:
            return {"status": 3}
        if req.password != req.password_confirm:
            return {"status": 4}
        user.password_hash = hashlib.sha256(req.password.encode()).hexdigest()

    if req.name is not None:
        user.name = req.name

    if req.phone_number is not None:
        # phone_number는 digits 형태로 저장(하이픈 제거)
        new_digits = _normalize_phone(req.phone_number)
        old_digits = _normalize_phone(user.phone_number or "")

        # 실제 변경인 경우에만 휴대폰 인증을 강제
        if new_digits != old_digits:
            if not req.phone_verification_id:
                return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}
            try:
                verified_digits = _require_verified_phone(db, req.phone_number, req.phone_verification_id)
            except Exception:
                return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}
            user.phone_number = verified_digits
        else:
            # 변경이 아니면 기존 값을 유지하되, 혹시 하이픈 포함 값이 들어있다면 정규화
            user.phone_number = old_digits if old_digits else user.phone_number

    if req.region is not None:
        user.region = req.region

    if req.marketing_consent is not None:
        user.marketing_consent = bool(req.marketing_consent)

    if req.custom_industry_codes is not None:
        user.custom_industry_codes = list(req.custom_industry_codes or [])

    if req.custom_region_codes is not None:
        user.custom_region_codes = list(req.custom_region_codes or [])

    if getattr(req, "area_region_codes", None) is not None:
        user.area_region_codes = list(req.area_region_codes or [])

    if getattr(req, "custom_role_codes", None) is not None:
        user.custom_role_codes = list(req.custom_role_codes or [])

    db.commit()
    db.refresh(user)

    return {"status": 0, "username": user.username, "old_username": old_username}


@router.delete("/community/user/{username}")
def delete_user(username: str, db: Session = Depends(get_db)):
    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1}

    deleted_username = user.username
    db.delete(user)
    db.commit()

    # 회원 탈퇴 푸쉬 알림(관리자 대상: admin_acknowledged=True) - 실패해도 탈퇴 성공 처리
    try:
        notify_admin_acknowledged_event(
            db,
            title="회원탈퇴 알림",
            body=f"회원 탈퇴: {deleted_username}",
            data={"event": "withdraw", "username": deleted_username},
        )
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        print("[WARN] notify_admin_acknowledged_event(withdraw) failed:", e)

    return {"status": 0}


@router.get("/community/mypage/{username}")
def get_mypage(username: str, db: Session = Depends(get_db)):
    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1}

    rows = (
        db.query(Community_Post.post_type, func.count(Community_Post.id).label("cnt"))
        .filter(Community_Post.user_id == user.id, Community_Post.post_type.in_([1, 3, 4, 6]))
        .group_by(Community_Post.post_type)
        .all()
    )

    counts = {1: 0, 3: 0, 4: 0, 6: 0}
    for post_type, cnt in rows:
        counts[post_type] = cnt

    referral_count = db.query(func.count(Referral.id)).filter(Referral.referrer_user_id == user.id).scalar() or 0

    # --- 추천인 수 기반 자동 등급 동기화(등급 상승 시 보상 지급) ---
    if _apply_user_grade_upgrade(db, user, int(referral_count)):
        db.commit()
        db.refresh(user)

    signup_date_str = user.signup_date.isoformat() if user.signup_date else None

    return {
        "status": 0,
        "signup_date": signup_date_str,
        # user_grade: -1-일반회원 / 0-아마추어 / 1-세미프로 / 2-프로 / 3-마스터 / 4-레전드
        "user_grade": int(user.user_grade) if getattr(user, "user_grade", None) is not None else -1,
        "is_owner": bool(getattr(user, "is_owner", False)),
        "posts": {"type1": counts[1], "type3": counts[3], "type4": counts[4], "type6": counts[6]},
        "point_balance": user.point_balance if user.point_balance is not None else 0,
        "cash_balance": user.cash_balance if user.cash_balance is not None else 0,
        "admin_acknowledged": user.admin_acknowledged if user.admin_acknowledged is not None else False,
        "referral_code": user.referral_code,
        "referral_count": int(referral_count),
    }

