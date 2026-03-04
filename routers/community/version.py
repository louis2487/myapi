from __future__ import annotations

import os
import re
from typing import List, Literal, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

router = APIRouter()

# 최소 지원 버전(하드코딩)
# - 운영에서 .env 누락/오타로 의도치 않게 min_supported가 비는 것을 방지합니다.
# - 최신 버전(latest)은 환경변수로 계속 제어할 수 있습니다.
HARD_MIN_SUPPORTED_VERSION = "1.0.9"


class AppVersionOut(BaseModel):
    status: int = 0
    platform: Literal["android", "ios"]
    current_version: Optional[str] = None
    latest_version: str
    min_supported_version: str
    force_update: bool
    store_url: Optional[str] = None
    message: Optional[str] = None


def _version_parts(v: str) -> List[int]:
    """
    "1.2.3" 형태 버전을 비교 가능한 숫자 배열로 변환합니다.
    - 숫자 이외 문자는 무시(예: "1.0.0-beta" -> 1.0.0)
    """
    s = (v or "").strip()
    if not s:
        return [0]
    parts = s.split(".")
    nums: List[int] = []
    for p in parts:
        m = re.match(r"(\d+)", (p or "").strip())
        nums.append(int(m.group(1)) if m else 0)
    # trailing 0 정리(1.0.0 == 1)
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    return nums or [0]


def _is_version_lt(a: str, b: str) -> bool:
    pa = _version_parts(a)
    pb = _version_parts(b)
    n = max(len(pa), len(pb))
    for i in range(n):
        av = pa[i] if i < len(pa) else 0
        bv = pb[i] if i < len(pb) else 0
        if av < bv:
            return True
        if av > bv:
            return False
    return False


@router.get("/community/app/version", response_model=AppVersionOut)
def community_app_version(
    platform: Literal["android", "ios"] = Query(...),
    current_version: Optional[str] = Query(None),
):
    """
    앱 시작 시 버전 체크(강제 업데이트용).
    - 최신 버전이 아니면 force_update=True
    환경변수:
      - APP_ANDROID_LATEST_VERSION / APP_ANDROID_MIN_SUPPORTED_VERSION / APP_ANDROID_STORE_URL / APP_ANDROID_PACKAGE
      - APP_IOS_LATEST_VERSION / APP_IOS_MIN_SUPPORTED_VERSION / APP_IOS_STORE_URL
      - APP_FORCE_UPDATE_MESSAGE
    """
    msg = (os.getenv("APP_FORCE_UPDATE_MESSAGE", "") or "").strip() or "최신 버전으로 업데이트 후 이용해 주세요."

    if platform == "android":
        latest = (os.getenv("APP_ANDROID_LATEST_VERSION", "") or "").strip()
        min_supported = (os.getenv("APP_ANDROID_MIN_SUPPORTED_VERSION", "") or "").strip() or HARD_MIN_SUPPORTED_VERSION
        pkg = (os.getenv("APP_ANDROID_PACKAGE", "") or "").strip() or "com.smartgauge.bunyangpro"
        store_url = (os.getenv("APP_ANDROID_STORE_URL", "") or "").strip() or f"market://details?id={pkg}"
    else:
        latest = (os.getenv("APP_IOS_LATEST_VERSION", "") or "").strip()
        min_supported = (os.getenv("APP_IOS_MIN_SUPPORTED_VERSION", "") or "").strip() or HARD_MIN_SUPPORTED_VERSION
        store_url = (os.getenv("APP_IOS_STORE_URL", "") or "").strip() or None

    # 값이 비어있으면 안전한 기본값으로 보정
    # - 운영에서 환경변수 설정이 누락되면, 의도치 않게 전 사용자 강제업데이트가 걸릴 수 있어
    #   기본값은 "현재 버전 == 최신"으로 간주합니다.
    if not latest and not min_supported:
        latest = current_version or "0.0.0"
        min_supported = latest
    else:
        latest = latest or min_supported
        min_supported = min_supported or latest

    # 하드코딩된 최소 지원 버전이 최신 버전보다 높으면 최신을 최소로 끌어올림
    # (client에서 latest를 기준으로 비교하는 로직과의 일관성 유지)
    if _is_version_lt(latest, min_supported):
        latest = min_supported

    force_update = False
    if current_version:
        # 요구사항: 최신 버전이 아니면 강제 업데이트
        if _is_version_lt(current_version, latest):
            force_update = True

    return {
        "status": 0,
        "platform": platform,
        "current_version": current_version,
        "latest_version": latest,
        "min_supported_version": min_supported,
        "force_update": force_update,
        "store_url": store_url,
        "message": msg,
    }

