from __future__ import annotations

import os
from fastapi import APIRouter, Header, HTTPException, Request

import settings
from services.upload_migration_service import get_uploads_root_dir, list_upload_files


router = APIRouter(prefix="/admin/migration/uploads", tags=["admin-migration"])


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
    token = (getattr(settings, "MIGRATION_TOKEN", "") or "").strip()
    if token and x_migration_token != token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    root_dir = get_uploads_root_dir()
    files = list_upload_files(root_dir)

    # base_url은 “B가 A에 접근한 도메인”을 기준으로 만들어주는 게 가장 안전합니다.
    # (커스텀 도메인/railway.app 도메인 어떤 것으로 접근하든 일관되게 동작)
    fallback_base_url = str(request.base_url).rstrip("/") + "/uploads"
    base_url = (os.getenv("PUBLIC_UPLOADS_BASE_URL") or fallback_base_url).strip().rstrip("/")
    return {"base_url": base_url, "count": len(files), "files": files}

