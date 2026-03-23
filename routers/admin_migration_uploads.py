from __future__ import annotations

import os
import threading
import time
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request

import settings
from services.upload_migration_service import get_uploads_root_dir, list_upload_files


router = APIRouter(prefix="/admin/migration/uploads", tags=["admin-migration"])

# ---------------------------------------------------------------------------
# 백그라운드 파일 스캔 상태 (in-memory singleton)
# ---------------------------------------------------------------------------
_scan_lock = threading.Lock()
_scan_state: dict[str, Any] = {
    "status": "idle",   # idle | scanning | done | error
    "result": None,
    "error": None,
    "started_at": None,
    "finished_at": None,
}


def _check_token(x_migration_token: str | None) -> None:
    token = (getattr(settings, "MIGRATION_TOKEN", "") or "").strip()
    if token and x_migration_token != token:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ---------------------------------------------------------------------------
# 기존: 동기 파일 목록 (유지, 소규모일 때 사용 가능)
# ---------------------------------------------------------------------------

@router.get("/files")
def list_upload_files_api(request: Request, x_migration_token: str | None = Header(default=None)):
    """
    (임시) 업로드 파일 목록 반환 API
    - /data/uploads(STATIC_DIR) 아래를 재귀 탐색
    - 상대경로(files)만 반환
    - B 서버가 이 API를 호출해 순차 다운로드/저장에 사용

    보안:
    - 환경변수 MIGRATION_TOKEN이 설정된 경우, 요청 헤더 x_migration_token 값이 일치해야 합니다.
    """
    _check_token(x_migration_token)

    root_dir = get_uploads_root_dir()
    files = list_upload_files(root_dir)

    # base_url은 "B가 A에 접근한 도메인"을 기준으로 만들어주는 게 가장 안전합니다.
    # (커스텀 도메인/railway.app 도메인 어떤 것으로 접근하든 일관되게 동작)
    fallback_base_url = str(request.base_url).rstrip("/") + "/uploads"
    base_url = (os.getenv("PUBLIC_UPLOADS_BASE_URL") or fallback_base_url).strip().rstrip("/")
    return {"base_url": base_url, "count": len(files), "files": files}


# ---------------------------------------------------------------------------
# 신규: 백그라운드 파일 스캔 (대량 파일일 때 504 방지)
# ---------------------------------------------------------------------------

def _do_file_scan() -> None:
    """백그라운드에서 파일 목록 스캔."""
    global _scan_state
    print("[FILE-SCAN] 파일 목록 스캔 시작…")
    try:
        root_dir = get_uploads_root_dir()
        files = list_upload_files(root_dir)
        print(f"[FILE-SCAN] ✅ 스캔 완료: {len(files)}개 파일 발견")

        base_url = (os.getenv("PUBLIC_UPLOADS_BASE_URL") or "").strip().rstrip("/")

        with _scan_lock:
            _scan_state["status"] = "done"
            _scan_state["result"] = {
                "base_url": base_url,
                "count": len(files),
                "files": files,
            }
            _scan_state["error"] = None
            _scan_state["finished_at"] = time.time()
    except Exception as e:
        err_msg = str(e) or e.__class__.__name__
        print(f"[FILE-SCAN] ❌ 스캔 실패: {err_msg}")
        with _scan_lock:
            _scan_state["status"] = "error"
            _scan_state["result"] = None
            _scan_state["error"] = err_msg
            _scan_state["finished_at"] = time.time()


@router.post("/start-file-scan")
def start_file_scan(
    background_tasks: BackgroundTasks,
    x_migration_token: str | None = Header(default=None),
):
    """
    파일 목록 스캔을 백그라운드로 시작합니다.
    - 이미 스캔 중이면 현재 상태만 반환
    - 완료/에러 후 재호출하면 새 스캔 시작
    """
    _check_token(x_migration_token)

    with _scan_lock:
        if _scan_state["status"] == "scanning":
            return {
                "status": "scanning",
                "message": "이미 스캔이 진행 중입니다.",
                "started_at": _scan_state["started_at"],
            }

        _scan_state["status"] = "scanning"
        _scan_state["result"] = None
        _scan_state["error"] = None
        _scan_state["started_at"] = time.time()
        _scan_state["finished_at"] = None

    background_tasks.add_task(_do_file_scan)
    return {
        "status": "scanning",
        "message": "파일 스캔을 시작했습니다.",
        "started_at": _scan_state["started_at"],
    }


@router.get("/file-scan-status")
def get_file_scan_status(
    x_migration_token: str | None = Header(default=None),
):
    """
    파일 스캔 상태를 반환합니다 (가벼운 응답, 파일 목록 미포함).
    - status: idle | scanning | done | error
    - done일 때 total(파일 수)만 반환
    """
    _check_token(x_migration_token)

    with _scan_lock:
        resp: dict[str, Any] = {
            "status": _scan_state["status"],
            "started_at": _scan_state["started_at"],
            "finished_at": _scan_state["finished_at"],
        }
        if _scan_state["status"] == "done" and _scan_state["result"]:
            resp["total"] = _scan_state["result"].get("count", 0)
            resp["base_url"] = _scan_state["result"].get("base_url", "")
        elif _scan_state["status"] == "error":
            resp["error"] = _scan_state["error"]

    return resp


@router.get("/file-scan-page")
def get_file_scan_page(
    offset: int = 0,
    limit: int = 6,
    x_migration_token: str | None = Header(default=None),
):
    """
    캐시된 스캔 결과에서 offset~offset+limit 구간의 파일 목록을 반환합니다.
    - 스캔이 완료(done)되지 않았으면 409 반환
    - 가볍고 빠른 응답 (6개씩)
    """
    _check_token(x_migration_token)

    with _scan_lock:
        if _scan_state["status"] != "done" or not _scan_state["result"]:
            raise HTTPException(
                status_code=409,
                detail={"error": "scan_not_ready", "status": _scan_state["status"]},
            )
        all_files = _scan_state["result"].get("files") or []
        base_url = _scan_state["result"].get("base_url", "")

    total = len(all_files)
    page = all_files[offset: offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "count": len(page),
        "has_more": (offset + limit) < total,
        "files": page,
        "base_url": base_url,
    }
