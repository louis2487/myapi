from __future__ import annotations

from datetime import date, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from deps import get_db
from routers.parking import (
    ParkingCountOut,
    ParkingUserListItemOut,
    _ensure_parking_count_schema,
    _ensure_parking_daily_activity_schema,
    _ensure_parking_users_schema,
    _refresh_parking_count_for_date,
    _require_parking_user,
    _require_owner,
    _today_kst,
)

router = APIRouter()


@router.get("/parking/admin/counts", response_model=List[ParkingCountOut])
def parking_admin_counts(
    username: str = Query(..., min_length=1, max_length=30),
    password: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
):
    _ensure_parking_users_schema(db)
    _ensure_parking_count_schema(db)
    _ensure_parking_daily_activity_schema(db)
    _require_parking_user(db, username.strip(), password)

    today = _today_kst()
    for i in range(limit):
        _refresh_parking_count_for_date(db, today - timedelta(days=i))
    db.commit()

    rows = (
        db.execute(
            text(
                """
                SELECT count_date, dau, total_count, daily_count
                FROM parking_count
                ORDER BY count_date DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        )
        .mappings()
        .all()
    )
    return [
        {
            "count_date": r["count_date"],
            "dau": int(r["dau"] or 0),
            "total_count": int(r["total_count"] or 0),
            "daily_count": int(r["daily_count"] or 0),
        }
        for r in rows
    ]


@router.get("/parking/admin/counts/detail", response_model=ParkingCountOut)
def parking_admin_count_detail(
    count_date: date = Query(...),
    username: str = Query(..., min_length=1, max_length=30),
    password: str = Query(..., min_length=2, max_length=200),
    db: Session = Depends(get_db),
):
    _ensure_parking_users_schema(db)
    _ensure_parking_count_schema(db)
    _ensure_parking_daily_activity_schema(db)
    _require_parking_user(db, username.strip(), password)

    _refresh_parking_count_for_date(db, count_date)
    db.commit()

    row = (
        db.execute(
            text(
                """
                SELECT count_date, dau, total_count, daily_count
                FROM parking_count
                WHERE count_date = :d
                LIMIT 1
                """
            ),
            {"d": count_date},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Count not found.")
    return {
        "count_date": row["count_date"],
        "dau": int(row["dau"] or 0),
        "total_count": int(row["total_count"] or 0),
        "daily_count": int(row["daily_count"] or 0),
    }


@router.get("/parking/admin/users", response_model=List[ParkingUserListItemOut])
def parking_admin_user_list(
    username: str = Query(..., min_length=1, max_length=30),
    password: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    _ensure_parking_users_schema(db)
    _require_owner(db, username.strip(), password)

    rows = (
        db.execute(
            text(
                """
                SELECT username, floor, pillar_number, action_date, signup_date
                FROM parking_users
                ORDER BY signup_date DESC, id DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        )
        .mappings()
        .all()
    )
    return [
        {
            "username": str(r["username"]),
            "floor": r.get("floor"),
            "pillar_number": r.get("pillar_number"),
            "action_date": r.get("action_date"),
            "signup_date": r["signup_date"],
        }
        for r in rows
    ]
