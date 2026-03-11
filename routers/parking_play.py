from __future__ import annotations

import os
import re
from typing import List, Literal, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

router = APIRouter()

# 최소 지원 버전(하드코딩, Android만)
# - 운영에서 Railway env 누락/오타로 min_supported가 비는 것을 방지합니다.
HARD_ANDROID_MIN_SUPPORTED_VERSION = "1.0.0"


class ParkingAppVersionOut(BaseModel):
    status: int = 0
    platform: Literal["android", "ios"]
    current_version: Optional[str] = None
    latest_version: str
    min_supported_version: str
    force_update: bool
    store_url: Optional[str] = None
    message: Optional[str] = None


def _version_parts(v: str) -> List[int]:
    s = (v or "").strip()
    if not s:
        return [0]
    parts = s.split(".")
    nums: List[int] = []
    for p in parts:
        m = re.match(r"(\d+)", (p or "").strip())
        nums.append(int(m.group(1)) if m else 0)
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


@router.get("/parking/app/version", response_model=ParkingAppVersionOut)
def parking_app_version(
    platform: Literal["android", "ios"] = Query(...),
    current_version: Optional[str] = Query(None),
):
    """
    주차(스마트파킹) 앱 시작 시 버전 체크(강제 업데이트용).
    Railway 환경변수:
      - PARKING_ANDROID_LATEST_VERSION / PARKING_ANDROID_MIN_SUPPORTED_VERSION
      - (옵션) PARKING_ANDROID_STORE_URL / PARKING_IOS_STORE_URL
      - (옵션) PARKING_FORCE_UPDATE_MESSAGE
    """
    msg = (os.getenv("PARKING_FORCE_UPDATE_MESSAGE", "") or "").strip() or "최신 버전으로 업데이트 후 이용해 주세요."

    if platform == "android":
        latest = (os.getenv("PARKING_ANDROID_LATEST_VERSION", "") or "").strip()
        min_supported = (
            (os.getenv("PARKING_ANDROID_MIN_SUPPORTED_VERSION", "") or "").strip() or HARD_ANDROID_MIN_SUPPORTED_VERSION
        )
        store_url = (
            (os.getenv("PARKING_ANDROID_STORE_URL", "") or "").strip()
            or "https://play.google.com/store/apps/details?id=com.smartgauge.smartparking"
        )
    else:
        latest = (os.getenv("PARKING_IOS_LATEST_VERSION", "") or "").strip()
        # iOS는 환경변수를 따로 운영하지 않는 경우가 많아, 값이 없으면 강제 업데이트를 걸지 않도록 기본값을 비웁니다.
        min_supported = (os.getenv("PARKING_IOS_MIN_SUPPORTED_VERSION", "") or "").strip()
        store_url = (os.getenv("PARKING_IOS_STORE_URL", "") or "").strip() or None

    if not latest and not min_supported:
        latest = current_version or "0.0.0"
        min_supported = latest
    else:
        latest = latest or min_supported
        min_supported = min_supported or latest

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

