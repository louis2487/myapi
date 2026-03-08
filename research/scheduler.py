from __future__ import annotations

import os
from datetime import timedelta, timezone

from fastapi import FastAPI

from .service import run_daily_reports

from sqlalchemy import text
from database import engine

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


_scheduler = None


def ensure_research_schema() -> None:
    """
    research_users / research_questions / research_reports 스키마 보정.
    - create_all은 기존 테이블의 컬럼 추가를 하지 않으므로, 필요한 컬럼/제약을 best-effort로 보정합니다.
    - 권한/환경에 따라 실패할 수 있어, 실패 시에는 예외를 그대로 올려 원인 파악을 돕습니다.
    """
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE research_questions ADD COLUMN IF NOT EXISTS user_id BIGINT"))
        conn.execute(text("ALTER TABLE research_reports ADD COLUMN IF NOT EXISTS user_id BIGINT"))

        # FK 제약은 IF NOT EXISTS가 없어 DO 블록으로 중복만 무시합니다.
        conn.execute(
            text(
                """
DO $$
BEGIN
  ALTER TABLE research_reports
    ADD CONSTRAINT fk_research_reports_user
    FOREIGN KEY (user_id) REFERENCES research_users(id);
EXCEPTION WHEN duplicate_object THEN
  NULL;
END $$;
"""
            )
        )
        conn.execute(
            text(
                """
DO $$
BEGIN
  ALTER TABLE research_questions
    ADD CONSTRAINT fk_research_questions_user
    FOREIGN KEY (user_id) REFERENCES research_users(id);
EXCEPTION WHEN duplicate_object THEN
  NULL;
END $$;
"""
            )
        )


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
        ensure_research_schema()
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
            CronTrigger(hour=6, minute=00, timezone=tz),
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

