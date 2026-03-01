from __future__ import annotations

from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))


def to_kst_iso(dt: datetime | None) -> str | None:
    # tzinfo 없으면 UTC로 간주 후 KST(UTC+9)로 변환
    if not dt:
        return None
    try:
        if getattr(dt, "tzinfo", None) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(KST).isoformat()
    except Exception:
        try:
            return dt.isoformat()
        except Exception:
            return None


def kst_today_bounds_utc():
    """
    한국시간(KST) 기준 '오늘'의 시작/끝을 UTC datetime으로 반환.
    """
    now_kst = datetime.now(tz=KST)
    start_kst = datetime.combine(now_kst.date(), datetime.min.time(), tzinfo=KST)
    end_kst = start_kst + timedelta(days=1)
    return start_kst.astimezone(timezone.utc), end_kst.astimezone(timezone.utc)

