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


def mount_static(app: FastAPI) -> Path:
    static_dir = Path(os.getenv("STATIC_DIR", "/data/uploads")).resolve()
    static_dir.mkdir(parents=True, exist_ok=True)
    print("### STATIC_DIR =", static_dir)
    print("### STATIC_DIR exists?", static_dir.exists())
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
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

    public_url = f"https://api.smartgauge.co.kr/static/{save_path.name}"
    return {"url": public_url}

