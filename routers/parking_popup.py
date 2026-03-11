from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from deps import get_db
from models import Parking_UI_Config
from routers.parking import _ensure_parking_users_schema, _require_parking_user

router = APIRouter()


class ParkingPopupConfig(BaseModel):
    enabled: bool = True
    image_url: str | None = Field(default=None, max_length=1024)
    link_url: str | None = Field(default=None, max_length=1024)
    width_percent: int = Field(default=92, ge=40, le=100)
    height: int = Field(default=360, ge=200, le=900)
    resize_mode: Literal["contain", "cover", "stretch"] = "contain"


class ParkingUIConfigPayload(BaseModel):
    popup: ParkingPopupConfig = Field(default_factory=ParkingPopupConfig)


class ParkingUIConfigUpdateIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=30)
    password: str = Field(..., min_length=2, max_length=200)
    config: ParkingUIConfigPayload


def _default_ui_config_dict() -> dict:
    return {
        "popup": {
            "enabled": True,
            "image_url": None,
            "link_url": None,
            "width_percent": 92,
            "height": 360,
            "resize_mode": "contain",
        }
    }


def _normalize_ui_config(raw: dict | None) -> dict:
    base = _default_ui_config_dict()
    if not isinstance(raw, dict):
        return base
    popup = raw.get("popup") if isinstance(raw.get("popup"), dict) else {}
    base["popup"]["enabled"] = bool(popup.get("enabled", base["popup"]["enabled"]))
    img = popup.get("image_url", None)
    base["popup"]["image_url"] = str(img).strip() if isinstance(img, str) and str(img).strip() else None
    link = popup.get("link_url", None)
    base["popup"]["link_url"] = str(link).strip() if isinstance(link, str) and str(link).strip() else None

    try:
        base["popup"]["width_percent"] = int(popup.get("width_percent", base["popup"]["width_percent"]))
    except Exception:
        base["popup"]["width_percent"] = 92
    if base["popup"]["width_percent"] < 40:
        base["popup"]["width_percent"] = 40
    if base["popup"]["width_percent"] > 100:
        base["popup"]["width_percent"] = 100

    try:
        base["popup"]["height"] = int(popup.get("height", base["popup"]["height"]))
    except Exception:
        base["popup"]["height"] = 360
    if base["popup"]["height"] < 200:
        base["popup"]["height"] = 200
    if base["popup"]["height"] > 900:
        base["popup"]["height"] = 900

    rm = popup.get("resize_mode", base["popup"]["resize_mode"])
    rm_s = str(rm).strip().lower() if isinstance(rm, str) else "contain"
    base["popup"]["resize_mode"] = rm_s if rm_s in ("contain", "cover", "stretch") else "contain"
    return base


@router.get("/parking/ui-config")
def parking_get_ui_config(db: Session = Depends(get_db)):
    """
    스마트파킹 UI 설정 조회(팝업 등).
    - 인증 불필요(읽기 전용)
    """
    try:
        row = db.query(Parking_UI_Config).filter(Parking_UI_Config.id == 1).first()
        cfg = _normalize_ui_config(getattr(row, "config", None) if row else None)
        return {"status": 0, "config": cfg}
    except Exception:
        return {"status": 8, "config": _default_ui_config_dict()}


@router.put("/parking/admin/ui-config")
def parking_update_ui_config(req: ParkingUIConfigUpdateIn, db: Session = Depends(get_db)):
    """
    관리자용 UI 설정 저장.
    - parking_users.grade == 'owner'만 허용
    """
    _ensure_parking_users_schema(db)
    user = _require_parking_user(db, req.username, req.password)
    if (user.get("grade") or "normal") != "owner":
        raise HTTPException(status_code=403, detail="Owner only.")

    cfg_dict = _normalize_ui_config(req.config.model_dump())
    try:
        row = (
            db.query(Parking_UI_Config)
            .filter(Parking_UI_Config.id == 1)
            .with_for_update()
            .first()
        )
        if not row:
            row = Parking_UI_Config(id=1, config=cfg_dict)
            db.add(row)
        else:
            row.config = cfg_dict
            db.add(row)
        db.commit()
        db.refresh(row)
        return {"status": 0, "config": _normalize_ui_config(getattr(row, "config", None))}
    except Exception:
        db.rollback()
        return {"status": 8, "config": cfg_dict, "message": "save_failed"}

