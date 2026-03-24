from __future__ import annotations

import base64
import imghdr
import os
import re
import threading
import uuid
from pathlib import Path

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

from fastapi import APIRouter, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


router = APIRouter()


class UploadBase64Request(BaseModel):
    filename: str | None = None
    base64: str


class ReplicatingStaticFiles(StaticFiles):
    def __init__(
        self,
        *,
        directory: str,
        sync_target_url: str = "",
        sync_timeout_sec: float = 2.5,
    ):
        super().__init__(directory=directory)
        self.root_dir = Path(directory).resolve()
        self.sync_target_url = sync_target_url.strip()
        self.sync_timeout_sec = sync_timeout_sec

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)

        method = str(scope.get("method", "GET")).upper()
        if method == "GET" and response.status_code == 200 and self.sync_target_url:
            self._replicate_in_background(path)
        return response

    def _replicate_in_background(self, relative_path: str) -> None:
        source_path = self._resolve_static_path(relative_path)
        if not source_path or not source_path.is_file():
            return
        if requests is None:
            return
        t = threading.Thread(target=self._send_to_peer, args=(source_path,), daemon=True)
        t.start()

    def _resolve_static_path(self, relative_path: str) -> Path | None:
        clean = (relative_path or "").lstrip("/").replace("\\", "/")
        target = (self.root_dir / clean).resolve()
        try:
            target.relative_to(self.root_dir)
        except Exception:
            return None
        return target

    def _send_to_peer(self, source_path: Path) -> None:
        if not self.sync_target_url or requests is None:
            return
        try:
            with source_path.open("rb") as f:
                res = requests.post(
                    self.sync_target_url,
                    data={"filename": source_path.name},
                    files={"file": (source_path.name, f, "application/octet-stream")},
                    timeout=self.sync_timeout_sec,
                )
            if res.status_code >= 400:
                print(f"[image-replication] failed: {source_path.name} -> {res.status_code}")
        except Exception as e:
            print(f"[image-replication] exception: {source_path.name} -> {e}")


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


def _sanitize_filename(name: str) -> str:
    return (name or "").strip().replace("\\", "/").split("/")[-1]


def mount_static(app: FastAPI) -> Path:
    static_dir = Path(os.getenv("STATIC_DIR", "/data/uploads")).resolve()
    static_dir.mkdir(parents=True, exist_ok=True)
    print("### STATIC_DIR =", static_dir)
    print("### STATIC_DIR exists?", static_dir.exists())
    sync_target_url = os.getenv("IMAGE_SYNC_TARGET_URL", "https://api.daewon469.com/image/send")
    sync_timeout_sec = float(os.getenv("IMAGE_SYNC_TIMEOUT_SEC", "2.5"))
    # 기존: /static 유지
    if not _is_mounted(app, "/static"):
        app.mount(
            "/static",
            ReplicatingStaticFiles(
                directory=str(static_dir),
                sync_target_url=sync_target_url,
                sync_timeout_sec=sync_timeout_sec,
            ),
            name="static",
        )
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


@router.post("/image/send")
async def image_send(
    file: UploadFile = File(...),
    filename: str | None = Form(None),
):
    name = _sanitize_filename(filename or file.filename or "")
    if not name:
        raise HTTPException(status_code=400, detail="filename required")

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="empty file")

    static_dir = Path(os.getenv("STATIC_DIR", "/data/uploads")).resolve()
    static_dir.mkdir(parents=True, exist_ok=True)
    save_path = _ensure_ext(static_dir / name, image_bytes)

    already_exists = save_path.exists()
    if not already_exists:
        with open(save_path, "wb") as f:
            f.write(image_bytes)

    public_base_url = os.getenv("PUBLIC_BASE_URL", "https://api.smartgauge.co.kr").rstrip("/")
    return {
        "saved": not already_exists,
        "exists": already_exists,
        "filename": save_path.name,
        "url": f"{public_base_url}/static/{save_path.name}",
    }

