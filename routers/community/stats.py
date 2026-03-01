from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from deps import get_db
from models import Community_Post, Community_User

from .time_utils import KST, kst_today_bounds_utc

router = APIRouter()


@router.get("/community/stats/today")
def community_today_stats(db: Session = Depends(get_db)):
    """
    고객센터 '오늘의 현황' 용 집계.
    - 전체 회원 / 오늘 신규회원
    - 전체 방문자수(누적) / 오늘 방문자수(근사치: 오늘 popup_last_seen_at 갱신)
    - 전체 구인글/오늘 구인글 (post_type=1)
    - 전체 광고글/오늘 광고글 (post_type=4)
    - 전체 수다글/오늘 수다글 (post_type=3)
    - 기존 호환을 위해 new_sites/realtime_visitors도 함께 내려줍니다.
    """
    try:
        now_kst = datetime.now(tz=KST)
        today_kst = now_kst.date()
        start_utc, end_utc = kst_today_bounds_utc()

        # posts: today
        today_job_posts = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.created_at >= start_utc,
                Community_Post.created_at < end_utc,
            )
            .scalar()
            or 0
        )

        today_ad_posts = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 4,
                Community_Post.status == "published",
                Community_Post.created_at >= start_utc,
                Community_Post.created_at < end_utc,
            )
            .scalar()
            or 0
        )

        today_chat_posts = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 3,
                Community_Post.status == "published",
                Community_Post.created_at >= start_utc,
                Community_Post.created_at < end_utc,
            )
            .scalar()
            or 0
        )

        # posts: total
        total_job_posts = (
            db.query(func.count(Community_Post.id))
            .filter(Community_Post.post_type == 1, Community_Post.status == "published")
            .scalar()
            or 0
        )

        total_ad_posts = (
            db.query(func.count(Community_Post.id))
            .filter(Community_Post.post_type == 4, Community_Post.status == "published")
            .scalar()
            or 0
        )

        total_chat_posts = (
            db.query(func.count(Community_Post.id))
            .filter(Community_Post.post_type == 3, Community_Post.status == "published")
            .scalar()
            or 0
        )

        new_users = (
            db.query(func.count(Community_User.id))
            .filter(Community_User.signup_date == today_kst)
            .scalar()
            or 0
        )

        today_visitors = (
            db.query(func.count(Community_User.id))
            .filter(
                Community_User.popup_last_seen_at.isnot(None),
                Community_User.popup_last_seen_at >= start_utc,
                Community_User.popup_last_seen_at < end_utc,
            )
            .scalar()
            or 0
        )

        total_visitors = (
            db.query(func.count(Community_User.id))
            .filter(Community_User.popup_last_seen_at.isnot(None))
            .scalar()
            or 0
        )

        total_users = db.query(func.count(Community_User.id)).scalar() or 0

        return {
            "status": 0,
            "date": today_kst.isoformat(),
            # required fields (new)
            "total_users": int(total_users),
            "new_users": int(new_users),
            "total_visitors": int(total_visitors),
            "today_visitors": int(today_visitors),
            "total_job_posts": int(total_job_posts),
            "today_job_posts": int(today_job_posts),
            "total_ad_posts": int(total_ad_posts),
            "today_ad_posts": int(today_ad_posts),
            "total_chat_posts": int(total_chat_posts),
            "today_chat_posts": int(today_chat_posts),
            # backward compatible aliases
            "new_sites": int(today_job_posts),
            "realtime_visitors": int(today_visitors),
        }
    except Exception:
        return {
            "status": 8,
            "date": None,
            "total_users": 0,
            "new_users": 0,
            "total_visitors": 0,
            "today_visitors": 0,
            "total_job_posts": 0,
            "today_job_posts": 0,
            "total_ad_posts": 0,
            "today_ad_posts": 0,
            "total_chat_posts": 0,
            "today_chat_posts": 0,
            # backward compatible aliases
            "new_sites": 0,
            "realtime_visitors": 0,
        }

