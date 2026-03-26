from pathlib import Path

from fastapi import APIRouter, Response
from fastapi.responses import FileResponse

router = APIRouter()
PROJECT_ROOT = Path(__file__).resolve().parent.parent


@router.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    """
    브라우저의 /favicon.ico 요청을 처리한다.
    - favicon.ico 우선
    - 없으면 favicon.ico.png 대체
    - 둘 다 없으면 204 반환(불필요한 404 로그 방지)
    """
    candidates = (
        PROJECT_ROOT / "favicon.ico",
        PROJECT_ROOT / "favicon.ico.png",
    )
    for icon_path in candidates:
        if icon_path.exists():
            media_type = "image/x-icon" if icon_path.suffix.lower() == ".ico" else "image/png"
            return FileResponse(path=icon_path, media_type=media_type)

    return Response(status_code=204)
