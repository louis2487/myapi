from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime
from typing import List, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from deps import get_db
from models import ParkingLocation

router = APIRouter()

_SCHEMA_READY = False
_USERS_SCHEMA_READY = False

_PBKDF2_ITERATIONS = 210_000


def _ensure_parking_schema(db: Session):
    """
    create_all은 기존 테이블을 ALTER 하지 않으므로, 컬럼 추가가 필요한 경우 보정합니다.
    - floor 컬럼 추가
    """
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    try:
        col = db.execute(
            text(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'parking_locations'
                  AND column_name = 'floor'
                LIMIT 1
                """
            )
        ).scalar()
        if not col:
            db.execute(text("ALTER TABLE parking_locations ADD COLUMN floor VARCHAR(8)"))
            db.execute(text("UPDATE parking_locations SET floor = 'B1' WHERE floor IS NULL"))
            db.commit()
    except Exception:
        # 스키마 보정 실패 시에도 API 전체가 죽지 않도록 보호
        db.rollback()
    finally:
        _SCHEMA_READY = True


def _ensure_parking_users_schema(db: Session):
    global _USERS_SCHEMA_READY
    if _USERS_SCHEMA_READY:
        return
    try:
        # Postgres 기준 (BIGSERIAL + now())
        db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS parking_users (
                    id BIGSERIAL PRIMARY KEY,
                    username VARCHAR(30) NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    signup_date TIMESTAMP NOT NULL DEFAULT now()
                );
                """
            )
        )
        # 신규 컬럼: floor (B2~B5 등)
        db.execute(text("ALTER TABLE parking_users ADD COLUMN IF NOT EXISTS floor VARCHAR(20)"))
        # 신규 컬럼: grade (normal/owner)
        db.execute(text("ALTER TABLE parking_users ADD COLUMN IF NOT EXISTS grade VARCHAR(10)"))
        # 신규 컬럼: pillar_number (기둥 위치)
        db.execute(text("ALTER TABLE parking_users ADD COLUMN IF NOT EXISTS pillar_number VARCHAR(20)"))
        # 기존 데이터 보정(컬럼이 방금 추가되었거나 null/이상치가 있는 경우)
        db.execute(
            text(
                """
                UPDATE parking_users
                SET grade = 'normal'
                WHERE grade IS NULL
                   OR grade NOT IN ('normal', 'owner')
                """
            )
        )
        # NOT NULL + DEFAULT
        db.execute(text("ALTER TABLE parking_users ALTER COLUMN grade SET DEFAULT 'normal'"))
        db.execute(text("ALTER TABLE parking_users ALTER COLUMN grade SET NOT NULL"))
        # 체크 제약(이미 있으면 스킵)
        exists = (
            db.execute(
                text(
                    """
                    SELECT 1
                    FROM pg_constraint
                    WHERE conname = 'parking_users_grade_check'
                    LIMIT 1
                    """
                )
            ).scalar()
        )
        if not exists:
            db.execute(
                text(
                    """
                    ALTER TABLE parking_users
                    ADD CONSTRAINT parking_users_grade_check
                    CHECK (grade IN ('normal', 'owner'))
                    """
                )
            )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        _USERS_SCHEMA_READY = True


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    padded = s + "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8"))


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${_b64(salt)}${_b64(dk)}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt_s, hash_s = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iter_s)
        salt = _b64d(salt_s)
        expected = _b64d(hash_s)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def _get_parking_user_row(db: Session, username: str):
    return (
        db.execute(
            text(
                """
                SELECT id, username, password_hash, signup_date, floor, grade, pillar_number
                FROM parking_users
                WHERE username = :u
                LIMIT 1
                """
            ),
            {"u": username},
        )
        .mappings()
        .first()
    )


def _require_parking_user(db: Session, username: str, password: str):
    row = _get_parking_user_row(db, username)
    if not row or not _verify_password(password, str(row["password_hash"])):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    return row


def _normalize_floor(floor: str | None) -> str:
    f = (floor or "B1").strip().upper()
    if f in {"B1", "B2", "B3", "B4", "B5"}:
        return f
    raise HTTPException(status_code=400, detail="Invalid floor. Use B1~B5.")


def _normalize_zone(zone: str) -> str:
    z = zone.strip().upper()
    if z in {"A", "B", "C", "D", "E"}:
        return z
    raise HTTPException(status_code=400, detail="Invalid zone. Use A~E.")


class ParkingLocationUpsertIn(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=80)
    lot_id: str | None = Field(default=None, max_length=80)
    floor: str | None = Field(default=None, max_length=8)
    zone: str = Field(..., min_length=1, max_length=16)
    spot: str | None = Field(default=None, max_length=32)
    note: str | None = Field(default=None, max_length=2000)
    parked_at: datetime | None = None


class ParkingLocationOut(BaseModel):
    id: int
    device_id: str
    lot_id: str | None
    floor: str | None
    zone: str
    spot: str | None
    note: str | None
    parked_at: datetime
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ParkingAuthIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=30)
    password: str = Field(..., min_length=2, max_length=200)


class ParkingUserOut(BaseModel):
    id: int
    username: str
    signup_date: datetime
    floor: str | None = None
    pillar_number: str | None = None
    grade: Literal["normal", "owner"] = "normal"


class ParkingUserFloorIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=30)
    password: str = Field(..., min_length=2, max_length=200)
    floor: str = Field(..., min_length=1, max_length=20)


class ParkingUserPillarIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=30)
    password: str = Field(..., min_length=2, max_length=200)
    pillar_number: str | None = Field(default=None, max_length=20)


@router.get("/parking/location", response_model=ParkingLocationOut | None)
def get_current_location(
    device_id: str = Query(..., min_length=1, max_length=80),
    db: Session = Depends(get_db),
):
    _ensure_parking_schema(db)
    row = (
        db.query(ParkingLocation)
        .filter(ParkingLocation.device_id == device_id, ParkingLocation.is_active == True)  # noqa: E712
        .order_by(ParkingLocation.updated_at.desc(), ParkingLocation.created_at.desc())
        .first()
    )
    return row


@router.get("/parking/location/history", response_model=List[ParkingLocationOut])
def get_location_history(
    device_id: str = Query(..., min_length=1, max_length=80),
    limit: int = Query(30, ge=1, le=200),
    db: Session = Depends(get_db),
):
    _ensure_parking_schema(db)
    rows = (
        db.query(ParkingLocation)
        .filter(ParkingLocation.device_id == device_id)
        .order_by(ParkingLocation.parked_at.desc(), ParkingLocation.id.desc())
        .limit(limit)
        .all()
    )
    return rows


@router.post("/parking/location", response_model=ParkingLocationOut)
def save_location(req: ParkingLocationUpsertIn, db: Session = Depends(get_db)):
    _ensure_parking_schema(db)
    floor = _normalize_floor(req.floor)
    zone = _normalize_zone(req.zone)
    spot = req.spot.strip() if isinstance(req.spot, str) and req.spot.strip() else None
    lot_id = req.lot_id.strip() if isinstance(req.lot_id, str) and req.lot_id.strip() else None
    note = req.note.strip() if isinstance(req.note, str) and req.note.strip() else None

    # 이전 "현재 위치" 비활성화 (히스토리 보존)
    (
        db.query(ParkingLocation)
        .filter(ParkingLocation.device_id == req.device_id, ParkingLocation.is_active == True)  # noqa: E712
        .update({ParkingLocation.is_active: False})
    )

    row_kwargs = dict(
        device_id=req.device_id,
        lot_id=lot_id,
        floor=floor,
        zone=zone,
        spot=spot,
        note=note,
        is_active=True,
    )
    if req.parked_at is not None:
        row_kwargs["parked_at"] = req.parked_at

    row = ParkingLocation(**row_kwargs)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.delete("/parking/location")
def clear_current_location(
    device_id: str = Query(..., min_length=1, max_length=80),
    db: Session = Depends(get_db),
):
    _ensure_parking_schema(db)
    (
        db.query(ParkingLocation)
        .filter(ParkingLocation.device_id == device_id, ParkingLocation.is_active == True)  # noqa: E712
        .update({ParkingLocation.is_active: False})
    )
    db.commit()
    return {"status": "ok"}


@router.post("/parking/auth/login", response_model=ParkingUserOut)
def parking_login(req: ParkingAuthIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    row = _get_parking_user_row(db, username)
    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    if not _verify_password(req.password, str(row["password_hash"])):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    return {
        "id": int(row["id"]),
        "username": str(row["username"]),
        "signup_date": row["signup_date"],
        "floor": row.get("floor"),
        "pillar_number": row.get("pillar_number"),
        "grade": row.get("grade") or "normal",
    }


@router.post("/parking/auth/signup", response_model=ParkingUserOut, status_code=status.HTTP_201_CREATED)
def parking_signup(req: ParkingAuthIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    row = _get_parking_user_row(db, username)
    if row:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists.")

    ph = _hash_password(req.password)
    created = (
        db.execute(
            text(
                """
                INSERT INTO parking_users (username, password_hash)
                VALUES (:u, :ph)
                RETURNING id, username, signup_date, floor, grade, pillar_number
                """
            ),
            {"u": username, "ph": ph},
        )
        .mappings()
        .first()
    )
    db.commit()
    if not created:
        raise HTTPException(status_code=500, detail="Signup failed.")

    return {
        "id": int(created["id"]),
        "username": str(created["username"]),
        "signup_date": created["signup_date"],
        "floor": created.get("floor"),
        "pillar_number": created.get("pillar_number"),
        "grade": created.get("grade") or "normal",
    }


@router.post("/parking/auth/me", response_model=ParkingUserOut)
def parking_me(req: ParkingAuthIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    user = _require_parking_user(db, username, req.password)
    return {
        "id": int(user["id"]),
        "username": str(user["username"]),
        "signup_date": user["signup_date"],
        "floor": user.get("floor"),
        "pillar_number": user.get("pillar_number"),
        "grade": user.get("grade") or "normal",
    }


@router.put("/parking/auth/me/floor", response_model=ParkingUserOut)
def parking_set_floor(req: ParkingUserFloorIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    user = _require_parking_user(db, username, req.password)
    floor = req.floor.strip().upper()
    if floor not in {"B2", "B3", "B4", "B5"}:
        raise HTTPException(status_code=400, detail="Invalid floor. Use B2~B5.")

    row = (
        db.execute(
            text(
                """
                UPDATE parking_users
                SET floor = :f
                WHERE id = :id
                RETURNING id, username, signup_date, floor, grade, pillar_number
                """
            ),
            {"f": floor, "id": int(user["id"])},
        )
        .mappings()
        .first()
    )
    db.commit()
    if not row:
        raise HTTPException(status_code=404, detail="User not found.")
    return {
        "id": int(row["id"]),
        "username": str(row["username"]),
        "signup_date": row["signup_date"],
        "floor": row.get("floor"),
        "pillar_number": row.get("pillar_number"),
        "grade": row.get("grade") or "normal",
    }


@router.put("/parking/auth/me/pillar-number", response_model=ParkingUserOut)
def parking_set_pillar_number(req: ParkingUserPillarIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    user = _require_parking_user(db, username, req.password)
    raw = (req.pillar_number or "").strip()
    pillar_number: str | None
    if not raw:
        pillar_number = None
    else:
        if not raw.isdigit():
            raise HTTPException(status_code=400, detail="Invalid pillar_number. Use digits only.")
        pillar_number = raw

    row = (
        db.execute(
            text(
                """
                UPDATE parking_users
                SET pillar_number = :p
                WHERE id = :id
                RETURNING id, username, signup_date, floor, grade, pillar_number
                """
            ),
            {"p": pillar_number, "id": int(user["id"])},
        )
        .mappings()
        .first()
    )
    db.commit()
    if not row:
        raise HTTPException(status_code=404, detail="User not found.")
    return {
        "id": int(row["id"]),
        "username": str(row["username"]),
        "signup_date": row["signup_date"],
        "floor": row.get("floor"),
        "pillar_number": row.get("pillar_number"),
        "grade": row.get("grade") or "normal",
    }

