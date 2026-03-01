from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from deps import get_db
from models import Community_User, Point

from .time_utils import KST, kst_today_bounds_utc, to_kst_iso

router = APIRouter()

ATTENDANCE_REASON = "attendance_daily"
ATTENDANCE_AMOUNT = 200


@router.get("/community/points/{username}")
def list_points(username: str, db: Session = Depends(get_db)):
    """
    내 포인트 적립/사용 내역(원장).
    """
    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1, "items": []}

    rows = (
        db.query(Point)
        .filter(Point.user_id == user.id)
        .order_by(Point.created_at.desc(), Point.id.desc())
        .limit(500)
        .all()
    )

    items = [
        {
            "id": p.id,
            "reason": p.reason,
            "amount": int(p.amount),
            "created_at": to_kst_iso(p.created_at),
        }
        for p in rows
    ]

    return {"status": 0, "items": items}


@router.get("/community/points/attendance/status/{username}")
def attendance_status(username: str, db: Session = Depends(get_db)):
    """
    출석체크(일 1회) 수령 여부 조회.
    - KST 기준 '오늘'에 attendance_daily 기록이 있으면 claimed=True
    """
    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1, "claimed": False}

    # 신규 필드(last_attendance_date)가 있으면 우선 사용
    today_kst = datetime.now(tz=KST).date()
    if getattr(user, "last_attendance_date", None) == today_kst:
        return {"status": 0, "claimed": True, "amount": ATTENDANCE_AMOUNT}

    start_utc, end_utc = kst_today_bounds_utc()
    exists = (
        db.query(Point.id)
        .filter(
            Point.user_id == user.id,
            Point.reason == ATTENDANCE_REASON,
            Point.created_at >= start_utc,
            Point.created_at < end_utc,
        )
        .first()
        is not None
    )

    return {"status": 0, "claimed": exists, "amount": ATTENDANCE_AMOUNT}


@router.post("/community/points/attendance/claim/{username}")
def attendance_claim(username: str, db: Session = Depends(get_db)):
    """
    출석체크 포인트 지급 (KST 기준 하루 1회, 200P).
    - point 테이블에 기록되고 /community/points/{username}에서 조회 가능
    """
    # 동시 클릭(중복 지급) 방지: user row를 잠그고 확인 후 지급
    user = db.query(Community_User).filter(Community_User.username == username).with_for_update().first()
    if not user:
        return {"status": 1, "claimed": False}

    today_kst = datetime.now(tz=KST).date()
    if getattr(user, "last_attendance_date", None) == today_kst:
        return {"status": 2, "claimed": True, "amount": 0, "point_balance": int(user.point_balance or 0)}

    start_utc, end_utc = kst_today_bounds_utc()
    already = (
        db.query(Point.id)
        .filter(
            Point.user_id == user.id,
            Point.reason == ATTENDANCE_REASON,
            Point.created_at >= start_utc,
            Point.created_at < end_utc,
        )
        .first()
        is not None
    )
    if already:
        # 과거 방식(point 테이블)로 이미 지급된 경우에도 신규 필드 동기화
        try:
            user.last_attendance_date = today_kst
            db.commit()
            db.refresh(user)
        except Exception:
            db.rollback()
        return {"status": 2, "claimed": True, "amount": 0, "point_balance": int(user.point_balance or 0)}

    user.point_balance = int(user.point_balance or 0) + ATTENDANCE_AMOUNT
    user.last_attendance_date = today_kst
    db.add(Point(user_id=user.id, reason=ATTENDANCE_REASON, amount=ATTENDANCE_AMOUNT))
    db.commit()
    db.refresh(user)

    return {
        "status": 0,
        "claimed": True,
        "amount": ATTENDANCE_AMOUNT,
        "point_balance": int(user.point_balance or 0),
    }

