from __future__ import annotations

import base64
import imghdr
import os
import re
import uuid
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


router = APIRouter()


class UploadBase64Request(BaseModel):
    filename: str | None = None
    base64: str


def _strip_data_url(b64: str) -> str:
    return re.sub(r"^data:.*;base64,", "", b64 or "")


def _ensure_ext(path: Path, raw_bytes: bytes) -> Path:
    if path.suffix:
        return path
    kind = imghdr.what(None, h=raw_bytes)  # 'jpeg' | 'png' ...
    ext = {"jpeg": ".jpg", "png": ".png", "gif": ".gif"}.get(kind, ".jpg")
    return path.with_suffix(ext)


def _is_mounted(app: FastAPI, path: str) -> bool:
    for r in getattr(app, "routes", []):
        if getattr(r, "path", None) == path:
            return True
    return False


def mount_static(app: FastAPI) -> Path:
    static_dir = Path(os.getenv("STATIC_DIR", "/data/uploads")).resolve()
    static_dir.mkdir(parents=True, exist_ok=True)
    print("### STATIC_DIR =", static_dir)
    print("### STATIC_DIR exists?", static_dir.exists())
    # 기존: /static 유지
    if not _is_mounted(app, "/static"):
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    # 지시서/운영 호환: /uploads alias 추가 (/static과 같은 디렉토리)
    if not _is_mounted(app, "/uploads"):
        app.mount("/uploads", StaticFiles(directory=str(static_dir)), name="uploads")
    return static_dir


@router.post("/upload/base64")
def upload_base64(payload: UploadBase64Request):
    if not payload.base64:
        raise HTTPException(status_code=400, detail="base64 required")

    raw_b64 = _strip_data_url(payload.base64)
    try:
        image_bytes = base64.b64decode(raw_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid base64")

    name = (payload.filename or f"{uuid.uuid4()}.jpg").strip()
    name = name.replace("\\", "/").split("/")[-1]

    static_dir = Path(os.getenv("STATIC_DIR", "/data/uploads")).resolve()
    static_dir.mkdir(parents=True, exist_ok=True)
    save_path = _ensure_ext(static_dir / name, image_bytes)

    print("SAVE TO:", save_path)
    with open(save_path, "wb") as f:
        f.write(image_bytes)

    # 운영/도메인 변경에 대비해 base url을 환경변수로 제어
    public_base_url = os.getenv("PUBLIC_BASE_URL", "https://api.smartgauge.co.kr").rstrip("/")
    public_url = f"{public_base_url}/static/{save_path.name}"
    return {"url": public_url}

