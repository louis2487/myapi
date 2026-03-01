from __future__ import annotations

import hashlib
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from deps import get_db
from models import Community_Phone_Verification, Community_User

router = APIRouter()

# -------------------- Aligo SMS (community phone verification) --------------------
ALIGO_API_KEY = os.getenv("ALIGO_API_KEY", "").strip()
ALIGO_USER_ID = os.getenv("ALIGO_USER_ID", "").strip()
ALIGO_SENDER = os.getenv("ALIGO_SENDER", "").strip()
# 기본값 N(실발송). 필요 시 Y로 설정
ALIGO_TESTMODE_YN = os.getenv("ALIGO_TESTMODE_YN", "N").strip().upper()  # 'Y' / 'N'

PHONE_VERIFICATION_TTL_SECONDS = int(os.getenv("PHONE_VERIFICATION_TTL_SECONDS", "300"))  # default 5m
PHONE_VERIFICATION_MAX_ATTEMPTS = int(os.getenv("PHONE_VERIFICATION_MAX_ATTEMPTS", "5"))


def _normalize_phone(value: str) -> str:
    return re.sub(r"[^0-9]", "", (value or "").strip())


def _is_valid_korean_phone(digits: str) -> bool:
    # 최소한의 검증: 10~11자리 숫자
    return digits.isdigit() and (10 <= len(digits) <= 11)


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _generate_6digit_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _send_aligo_sms(receiver_digits: str, message: str) -> dict:
    """
    알리고 SMS 발송. 실패 시 HTTPException 발생.
    """
    if not (ALIGO_API_KEY and ALIGO_USER_ID and ALIGO_SENDER):
        raise HTTPException(status_code=500, detail="ALIGO not configured (ALIGO_API_KEY/ALIGO_USER_ID/ALIGO_SENDER)")

    payload = {
        "key": ALIGO_API_KEY,
        "user_id": ALIGO_USER_ID,
        "sender": ALIGO_SENDER,
        "receiver": receiver_digits,
        "msg": message,
        "msg_type": "SMS",
    }
    if ALIGO_TESTMODE_YN in {"Y", "N"}:
        payload["testmode_yn"] = ALIGO_TESTMODE_YN

    try:
        r = requests.post("https://apis.aligo.in/send/", data=payload, timeout=10)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"SMS provider error: {e}")

    try:
        data = r.json()
    except Exception:
        data = {"raw": r.text}

    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"SMS provider http error: {r.status_code}")

    result_code = str(data.get("result_code", ""))
    if result_code and result_code != "1":
        detail = data.get("message") or data.get("msg") or data.get("error") or data
        raise HTTPException(status_code=400, detail=f"SMS send failed: {detail}")

    return data


class PhoneSendRequest(BaseModel):
    phone_number: str = Field(min_length=8, max_length=30)


class PhoneSendResponse(BaseModel):
    status: int
    verification_id: str | None = None
    expires_in_sec: int | None = None


class PhoneVerifyRequest(BaseModel):
    verification_id: str = Field(min_length=10, max_length=80)
    code: str = Field(min_length=4, max_length=10)


class PhoneVerifyResponse(BaseModel):
    status: int
    verified: bool = False


class FindUsernameRequest(BaseModel):
    phone_number: str = Field(min_length=8, max_length=30)
    phone_verification_id: str = Field(min_length=10, max_length=80)


class FindUsernameResponse(BaseModel):
    status: int
    items: list[str] = Field(default_factory=list)


class ResetPasswordRequest(BaseModel):
    username: str = Field(min_length=2, max_length=50)
    phone_number: str = Field(min_length=8, max_length=30)
    phone_verification_id: str = Field(min_length=10, max_length=80)
    new_password: str = Field(min_length=2, max_length=255)
    new_password_confirm: str = Field(min_length=2, max_length=255)


class ResetPasswordResponse(BaseModel):
    status: int
    detail: str | None = None


def _require_verified_phone(db: Session, phone_number: str, phone_verification_id: str) -> str:
    """
    인증 완료된 휴대폰(verification_id + phone 매칭, 만료/검증 체크)을 강제하고
    정규화된 phone digits를 반환합니다.
    """
    digits = _normalize_phone(phone_number)
    if not _is_valid_korean_phone(digits):
        raise HTTPException(status_code=400, detail="invalid phone_number")

    try:
        vid = uuid.UUID(phone_verification_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid phone_verification_id")

    vrow = db.query(Community_Phone_Verification).filter(Community_Phone_Verification.id == vid).first()
    now = datetime.now(tz=timezone.utc)
    if (
        (not vrow)
        or (vrow.phone_number != digits)
        or (vrow.verified_at is None)
        or (vrow.expires_at is not None and vrow.expires_at <= now)
    ):
        raise HTTPException(status_code=400, detail="phone verification required")
    return digits


@router.post("/community/phone/send", response_model=PhoneSendResponse)
def community_phone_send(req: PhoneSendRequest, db: Session = Depends(get_db)):
    digits = _normalize_phone(req.phone_number)
    if not _is_valid_korean_phone(digits):
        raise HTTPException(status_code=400, detail="invalid phone_number")

    code = _generate_6digit_code()
    now = datetime.now(tz=timezone.utc)
    expires_at = now + timedelta(seconds=PHONE_VERIFICATION_TTL_SECONDS)

    row = Community_Phone_Verification(
        phone_number=digits,
        code_hash=_hash_code(code),
        expires_at=expires_at,
    )
    db.add(row)
    db.flush()  # id 생성

    msg = f"[분양프로] 인증번호는 {code} 입니다."
    try:
        _send_aligo_sms(digits, msg)
    except Exception:
        db.rollback()
        raise

    db.commit()
    db.refresh(row)

    return {
        "status": 0,
        "verification_id": str(row.id),
        "expires_in_sec": PHONE_VERIFICATION_TTL_SECONDS,
    }


@router.post("/community/phone/verify", response_model=PhoneVerifyResponse)
def community_phone_verify(req: PhoneVerifyRequest, db: Session = Depends(get_db)):
    try:
        vid = uuid.UUID(req.verification_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid verification_id")

    row = db.query(Community_Phone_Verification).filter(Community_Phone_Verification.id == vid).first()
    if not row:
        return {"status": 1, "verified": False}

    now = datetime.now(tz=timezone.utc)
    if row.verified_at is not None:
        return {"status": 0, "verified": True}
    if row.expires_at is not None and row.expires_at <= now:
        return {"status": 2, "verified": False}

    attempts = int(getattr(row, "attempts", 0) or 0)
    if attempts >= PHONE_VERIFICATION_MAX_ATTEMPTS:
        return {"status": 3, "verified": False}

    if _hash_code(req.code.strip()) != row.code_hash:
        row.attempts = attempts + 1
        db.add(row)
        db.commit()
        return {"status": 4, "verified": False}

    row.verified_at = now
    db.add(row)
    db.commit()
    return {"status": 0, "verified": True}


@router.post("/community/account/find-username", response_model=FindUsernameResponse)
def community_find_username(req: FindUsernameRequest, db: Session = Depends(get_db)):
    digits = _require_verified_phone(db, req.phone_number, req.phone_verification_id)

    # 기존 데이터가 하이픈 포함으로 저장되어 있을 수 있어, DB/파이썬에서 숫자만 비교
    try:
        dialect = db.get_bind().dialect.name
    except Exception:
        dialect = ""

    if dialect == "postgresql":
        users = (
            db.query(Community_User)
            .filter(func.regexp_replace(Community_User.phone_number, r"[^0-9]", "", "g") == digits)
            .all()
        )
    else:
        rows = db.query(Community_User).filter(Community_User.phone_number.isnot(None)).all()
        users = [u for u in rows if _normalize_phone(u.phone_number or "") == digits]

    if not users:
        return {"status": 1, "items": []}

    items = [u.username for u in users if u and u.username]
    return {"status": 0, "items": items}


@router.post("/community/account/reset-password", response_model=ResetPasswordResponse)
def community_reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    if req.new_password != req.new_password_confirm:
        return {"status": 2, "detail": "비밀번호와 비밀번호 확인이 일치하지 않습니다."}

    digits = _require_verified_phone(db, req.phone_number, req.phone_verification_id)

    user = db.query(Community_User).filter(Community_User.username == req.username).first()
    if not user:
        return {"status": 1, "detail": "사용자를 찾을 수 없습니다."}

    # 기존 데이터(하이픈 포함) 고려하여 숫자만 비교
    if _normalize_phone(user.phone_number or "") != digits:
        return {"status": 3, "detail": "휴대폰 번호가 일치하지 않습니다."}

    user.password_hash = hashlib.sha256(req.new_password.encode()).hexdigest()
    db.add(user)
    db.commit()
    return {"status": 0}

