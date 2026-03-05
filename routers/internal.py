from __future__ import annotations

import os
from datetime import timedelta, timezone

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from sqlalchemy.orm import Session

from deps import get_db
from rss_service import fetch_rss_and_save
from settings import SECRET_RSS_TOKEN

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


router = APIRouter()


@router.get("/internal/rss-refresh")
def rss_refresh(x_internal_token: str = Header(None), db: Session = Depends(get_db)):
    if x_internal_token != SECRET_RSS_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    fetch_rss_and_save(db)
    return {"status": "ok"}


_rss_scheduler = None


def _kst_tzinfo():
    if ZoneInfo:
        try:
            return ZoneInfo("Asia/Seoul")
        except Exception:
            pass
    return timezone(timedelta(hours=9))


def _rss_refresh_job() -> None:
    from database import SessionLocal

    db = SessionLocal()
    try:
        fetch_rss_and_save(db)
    except Exception:
        try:
            db.rollback()
        finally:
            raise
    finally:
        db.close()


def register_rss_startup(app: FastAPI) -> None:
    @app.on_event("startup")
    async def _startup() -> None:
        enabled = (os.getenv("RSS_SCHEDULER_ENABLED") or "1").strip().lower() not in (
            "0",
            "false",
            "no",
        )
        if not enabled:
            return

        hour = int(os.getenv("RSS_SCHEDULER_HOUR") or "6")
        minute = int(os.getenv("RSS_SCHEDULER_MINUTE") or "5")

        global _rss_scheduler
        if _rss_scheduler is not None:
            return

        from apscheduler.executors.pool import ThreadPoolExecutor
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.cron import CronTrigger

        tz = _kst_tzinfo()
        _rss_scheduler = AsyncIOScheduler(
            timezone=tz,
            executors={"default": ThreadPoolExecutor(max_workers=2)},
        )
        _rss_scheduler.add_job(
            _rss_refresh_job,
            CronTrigger(hour=hour, minute=minute, timezone=tz),
            id="mk_rss_daily",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            misfire_grace_time=3600,
        )
        _rss_scheduler.start()

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        global _rss_scheduler
        if _rss_scheduler is None:
            return
        try:
            _rss_scheduler.shutdown(wait=False)
        finally:
            _rss_scheduler = None
