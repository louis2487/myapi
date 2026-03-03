from __future__ import annotations

from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from deps import get_db
from models import ParkingLocation

router = APIRouter()

_SCHEMA_READY = False


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

