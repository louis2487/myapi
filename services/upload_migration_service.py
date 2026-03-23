from __future__ import annotations

import os
from pathlib import Path


def get_uploads_root_dir() -> Path:
    # 프로젝트 기존 업로드/정적 파일 루트는 STATIC_DIR(/data/uploads) 사용
    return Path(os.getenv("STATIC_DIR", "/data/uploads")).resolve()


def list_upload_files(root_dir: Path) -> list[str]:
    """
    root_dir 아래의 파일을 재귀적으로 탐색하여, root_dir 기준 상대 경로(포지کس 스타일) 목록을 반환합니다.
    - 디렉토리는 제외
    - 정렬(sorted) 보장
    """
    root = root_dir.resolve()
    if not root.exists():
        return []

    files: list[str] = []
    for p in root.rglob("*"):
        try:
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if not rel:
                continue
            files.append(rel)
        except Exception:
            # 어떤 파일/경로가 깨져 있어도 전체가 실패하지 않도록 무시
            continue

    return sorted(files)

