from __future__ import annotations

import os
from datetime import timedelta, timezone

from fastapi import FastAPI

from .service import run_daily_reports

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


_scheduler = None


def _kst_tzinfo():
    if ZoneInfo:
        try:
            return ZoneInfo("Asia/Seoul")
        except Exception:
            pass
    # 고정 오프셋(KST=UTC+9) 폴백: tzdata 미설치/환경 차이에서도 항상 KST 기준 유지
    return timezone(timedelta(hours=9))


def register_research_startup(app: FastAPI) -> None:
    @app.on_event("startup")
    async def _startup() -> None:
        enabled = (os.getenv("RESEARCH_SCHEDULER_ENABLED") or "1").strip().lower() not in (
            "0",
            "false",
            "no",
        )
        if not enabled:
            return

        global _scheduler
        if _scheduler is not None:
            return

        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.cron import CronTrigger

        tz = _kst_tzinfo()
        _scheduler = AsyncIOScheduler(timezone=tz)
        _scheduler.add_job(
            run_daily_reports,
            CronTrigger(hour=6, minute=0, timezone=tz),
            id="research_daily_0600",
            replace_existing=True,
            kwargs={"force": False},
        )
        _scheduler.start()

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        global _scheduler
        if _scheduler is None:
            return
        try:
            _scheduler.shutdown(wait=False)
        finally:
            _scheduler = None

