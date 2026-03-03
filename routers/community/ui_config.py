from __future__ import annotations

from typing import List, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from deps import get_db
from models import Community_UI_Config

router = APIRouter()


# ==================== Community: UI Config (banner/popup) ====================
class UIConfigBannerItem(BaseModel):
    image_url: str = Field(min_length=1, max_length=1024)
    link_url: str | None = Field(default=None, max_length=1024)
    # click action (optional)
    # - link: open link_url (default)
    # - referral_modal: open referral modal in app
    click_action: Literal["link", "referral_modal"] | None = None
    # per-banner rendering options (optional; server will normalize/fill defaults)
    width_percent: int | None = Field(default=None, ge=40, le=100)
    # px(dp) based width (preferred; if set, client can render fixed width)
    width_px: int | None = Field(default=None, ge=120, le=1200)
    height: int | None = Field(default=None, ge=60, le=260)
    resize_mode: Literal["contain", "cover", "stretch"] | None = None


class UIConfigBanner(BaseModel):
    enabled: bool = True
    interval_posts: int = Field(default=10, ge=1, le=200)
    items: List[UIConfigBannerItem] = Field(default_factory=list)
    height: int = Field(default=110, ge=60, le=260)
    resize_mode: Literal["contain", "cover", "stretch"] = "contain"


class UIConfigTopBanner(BaseModel):
    enabled: bool = True
    # 첫화면 상단 배너는 2개 슬롯만 사용
    items: List[UIConfigBannerItem] = Field(default_factory=list)
    height: int = Field(default=70, ge=60, le=260)
    resize_mode: Literal["contain", "cover", "stretch"] = "contain"


class UIConfigPopup(BaseModel):
    enabled: bool = True
    image_url: str | None = Field(default=None, max_length=1024)
    link_url: str | None = Field(default=None, max_length=1024)
    width_percent: int = Field(default=92, ge=40, le=100)
    height: int = Field(default=360, ge=200, le=900)
    resize_mode: Literal["contain", "cover", "stretch"] = "contain"


class UIConfigTitleSearch(BaseModel):
    """
    제목검색 화면에서 상단에 노출할 추천 현장(게시글) 목록.
    - recommended_post_ids: post_id 목록
    """
    enabled: bool = True
    recommended_post_ids: List[int] = Field(default_factory=list)


class UIConfigPayload(BaseModel):
    banner: UIConfigBanner = Field(default_factory=UIConfigBanner)
    top_banner: UIConfigTopBanner = Field(default_factory=UIConfigTopBanner)
    popup: UIConfigPopup = Field(default_factory=UIConfigPopup)
    title_search: UIConfigTitleSearch = Field(default_factory=UIConfigTitleSearch)


def _default_ui_config_dict() -> dict:
    return {
        "banner": {
            "enabled": True,
            "interval_posts": 10,
            "items": [],
            "height": 110,
            "resize_mode": "contain",
        },
        "top_banner": {
            "enabled": True,
            "items": [],
            "height": 70,
            "resize_mode": "contain",
        },
        "popup": {
            "enabled": True,
            "image_url": None,
            "link_url": None,
            "width_percent": 92,
            "height": 360,
            "resize_mode": "contain",
        },
        "title_search": {
            "enabled": True,
            "recommended_post_ids": [],
        },
    }


def _normalize_ui_config(raw: dict | None) -> dict:
    base = _default_ui_config_dict()
    if not isinstance(raw, dict):
        return base
    banner = raw.get("banner") if isinstance(raw.get("banner"), dict) else {}
    top_banner = raw.get("top_banner") if isinstance(raw.get("top_banner"), dict) else {}
    popup = raw.get("popup") if isinstance(raw.get("popup"), dict) else {}
    title_search = raw.get("title_search") if isinstance(raw.get("title_search"), dict) else {}

    base["banner"]["enabled"] = bool(banner.get("enabled", base["banner"]["enabled"]))
    try:
        base["banner"]["interval_posts"] = int(banner.get("interval_posts", base["banner"]["interval_posts"]))
    except Exception:
        base["banner"]["interval_posts"] = 10
    if base["banner"]["interval_posts"] < 1:
        base["banner"]["interval_posts"] = 1
    if base["banner"]["interval_posts"] > 200:
        base["banner"]["interval_posts"] = 200

    # banner: size options
    try:
        base["banner"]["height"] = int(banner.get("height", base["banner"]["height"]))
    except Exception:
        base["banner"]["height"] = 110
    if base["banner"]["height"] < 60:
        base["banner"]["height"] = 60
    if base["banner"]["height"] > 260:
        base["banner"]["height"] = 260

    rm = banner.get("resize_mode", base["banner"]["resize_mode"])
    rm_s = str(rm).strip().lower() if isinstance(rm, str) else "contain"
    base["banner"]["resize_mode"] = rm_s if rm_s in ("contain", "cover", "stretch") else "contain"

    items = banner.get("items")
    norm_items: list[dict] = []
    if isinstance(items, list):
        for it in items[:30]:
            if not isinstance(it, dict):
                continue
            img = str(it.get("image_url") or "").strip()
            if not img:
                continue

            link = it.get("link_url", None)
            link_s = str(link).strip() if isinstance(link, str) else None

            ca = it.get("click_action", None)
            ca_s = str(ca).strip().lower() if isinstance(ca, str) else None
            click_action = ca_s if ca_s in ("link", "referral_modal") else None

            # per-item sizing (fallback to banner defaults)
            try:
                wp = int(it.get("width_percent", 100))
            except Exception:
                wp = 100
            if wp < 40:
                wp = 40
            if wp > 100:
                wp = 100

            # per-item width in px(dp): optional
            try:
                wpx_raw = it.get("width_px", None)
                wpx = int(wpx_raw) if wpx_raw is not None and str(wpx_raw).strip() != "" else None
            except Exception:
                wpx = None
            if wpx is not None:
                if wpx < 120:
                    wpx = 120
                if wpx > 1200:
                    wpx = 1200

            try:
                h = int(it.get("height", base["banner"]["height"]))
            except Exception:
                h = int(base["banner"]["height"])
            if h < 60:
                h = 60
            if h > 260:
                h = 260

            irm = it.get("resize_mode", base["banner"]["resize_mode"])
            irm_s = str(irm).strip().lower() if isinstance(irm, str) else str(base["banner"]["resize_mode"])
            irm_s = irm_s if irm_s in ("contain", "cover", "stretch") else "contain"

            norm_items.append(
                {
                    "image_url": img,
                    "link_url": link_s or None,
                    "click_action": click_action,
                    "width_percent": wp,
                    "width_px": wpx,
                    "height": h,
                    "resize_mode": irm_s,
                }
            )
    base["banner"]["items"] = norm_items

    # top_banner: first screen top 2 slots
    base["top_banner"]["enabled"] = bool(top_banner.get("enabled", base["top_banner"]["enabled"]))

    # top_banner: size options
    try:
        base["top_banner"]["height"] = int(top_banner.get("height", base["top_banner"]["height"]))
    except Exception:
        base["top_banner"]["height"] = 70
    if base["top_banner"]["height"] < 60:
        base["top_banner"]["height"] = 60
    if base["top_banner"]["height"] > 260:
        base["top_banner"]["height"] = 260

    trm = top_banner.get("resize_mode", base["top_banner"]["resize_mode"])
    trm_s = str(trm).strip().lower() if isinstance(trm, str) else "contain"
    base["top_banner"]["resize_mode"] = trm_s if trm_s in ("contain", "cover", "stretch") else "contain"

    top_items = top_banner.get("items")
    norm_top_items: list[dict] = []
    if isinstance(top_items, list):
        for it in top_items[:2]:
            if not isinstance(it, dict):
                continue
            img = str(it.get("image_url") or "").strip()
            if not img:
                continue

            link = it.get("link_url", None)
            link_s = str(link).strip() if isinstance(link, str) else None

            ca = it.get("click_action", None)
            ca_s = str(ca).strip().lower() if isinstance(ca, str) else None
            click_action = ca_s if ca_s in ("link", "referral_modal") else None

            try:
                wp = int(it.get("width_percent", 100))
            except Exception:
                wp = 100
            if wp < 40:
                wp = 40
            if wp > 100:
                wp = 100

            try:
                wpx_raw = it.get("width_px", None)
                wpx = int(wpx_raw) if wpx_raw is not None and str(wpx_raw).strip() != "" else None
            except Exception:
                wpx = None
            if wpx is not None:
                if wpx < 120:
                    wpx = 120
                if wpx > 1200:
                    wpx = 1200

            try:
                h = int(it.get("height", base["top_banner"]["height"]))
            except Exception:
                h = int(base["top_banner"]["height"])
            if h < 60:
                h = 60
            if h > 260:
                h = 260

            irm = it.get("resize_mode", base["top_banner"]["resize_mode"])
            irm_s = str(irm).strip().lower() if isinstance(irm, str) else str(base["top_banner"]["resize_mode"])
            irm_s = irm_s if irm_s in ("contain", "cover", "stretch") else "contain"

            norm_top_items.append(
                {
                    "image_url": img,
                    "link_url": link_s or None,
                    "click_action": click_action,
                    "width_percent": wp,
                    "width_px": wpx,
                    "height": h,
                    "resize_mode": irm_s,
                }
            )
    base["top_banner"]["items"] = norm_top_items

    base["popup"]["enabled"] = bool(popup.get("enabled", base["popup"]["enabled"]))
    img = popup.get("image_url", None)
    base["popup"]["image_url"] = str(img).strip() if isinstance(img, str) and str(img).strip() else None
    link = popup.get("link_url", None)
    base["popup"]["link_url"] = str(link).strip() if isinstance(link, str) and str(link).strip() else None

    # popup: size options
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

    prm = popup.get("resize_mode", base["popup"]["resize_mode"])
    prm_s = str(prm).strip().lower() if isinstance(prm, str) else "contain"
    base["popup"]["resize_mode"] = prm_s if prm_s in ("contain", "cover", "stretch") else "contain"

    # title_search: recommended posts by id
    base["title_search"]["enabled"] = bool(title_search.get("enabled", base["title_search"]["enabled"]))
    ids_raw = title_search.get("recommended_post_ids", [])
    ids: list[int] = []
    if isinstance(ids_raw, list):
        for v in ids_raw:
            try:
                n = int(v)
            except Exception:
                continue
            if n > 0:
                ids.append(n)
    # uniq keep order
    seen = set()
    uniq_ids: list[int] = []
    for n in ids:
        if n in seen:
            continue
        seen.add(n)
        uniq_ids.append(n)
    base["title_search"]["recommended_post_ids"] = uniq_ids
    return base


@router.get("/community/ui-config")
def community_get_ui_config(db: Session = Depends(get_db)):
    """
    앱 UI 설정 조회(배너/팝업 등).
    - 인증 불필요(읽기 전용)
    """
    try:
        row = db.query(Community_UI_Config).filter(Community_UI_Config.id == 1).first()
        cfg = _normalize_ui_config(getattr(row, "config", None) if row else None)
        return {"status": 0, "config": cfg}
    except Exception:
        return {"status": 8, "config": _default_ui_config_dict()}


@router.put("/community/admin/ui-config")
def community_update_ui_config(
    payload: UIConfigPayload,
    db: Session = Depends(get_db),
):
    """
    관리자용 UI 설정 저장.
    - 인증 없이 저장(요청사항)
    """
    cfg_dict = _normalize_ui_config(payload.model_dump())
    try:
        row = (
            db.query(Community_UI_Config)
            .filter(Community_UI_Config.id == 1)
            .with_for_update()
            .first()
        )
        if not row:
            row = Community_UI_Config(id=1, config=cfg_dict)
            db.add(row)
        else:
            row.config = cfg_dict
            db.add(row)
        db.commit()
        db.refresh(row)
        return {"status": 0, "config": _normalize_ui_config(getattr(row, "config", None))}
    except Exception:
        db.rollback()
        return {"status": 8, "config": cfg_dict}

