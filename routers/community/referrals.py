from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from deps import get_db
from models import Community_User, Point, Referral

router = APIRouter()


@router.get("/community/referrals/by-referrer/{username}")
def list_referrals_by_referrer(username: str, db: Session = Depends(get_db)):
    """
    내가 추천한 회원 목록(닉네임 기준).
    """
    referrer = db.query(Community_User).filter(Community_User.username == username).first()
    if not referrer:
        return {"status": 1, "items": []}

    rows = (
        db.query(Referral, Community_User.username.label("referred_username"))
        .join(Community_User, Community_User.id == Referral.referred_user_id)
        .filter(Referral.referrer_user_id == referrer.id)
        .order_by(Referral.created_at.desc(), Referral.id.desc())
        .all()
    )

    items = [
        {
            "id": r.Referral.id,
            "referred_username": r.referred_username,
            "created_at": r.Referral.created_at.isoformat() if r.Referral.created_at else None,
        }
        for r in rows
    ]

    return {"status": 0, "items": items}


def _mask_nickname(value: str) -> str:
    """
    닉네임을 앞 2글자만 보여주고 나머지는 '*'로 마스킹합니다.
    예) '홍길동' -> '홍길*', 'ab' -> 'ab', 'a' -> 'a'
    """
    s = (value or "").strip()
    if len(s) <= 2:
        return s
    return s[:2] + ("*" * (len(s) - 2))


@router.get("/community/referrals/ranking")
def referral_ranking(db: Session = Depends(get_db)):
    """
    추천인 기준 랭킹.
    응답 형식: 순위 / 닉네임(2글자 + 마스킹) / 추천인 수
    - 순위는 제한 없이(서버에서 limit 걸지 않음) 반환합니다.
    """
    rows = (
        db.query(
            Community_User.id.label("user_id"),
            Community_User.username.label("username"),
            func.count(Referral.id).label("referral_count"),
        )
        .join(Referral, Referral.referrer_user_id == Community_User.id)
        .group_by(Community_User.id, Community_User.username)
        .order_by(func.count(Referral.id).desc(), Community_User.id.asc())
        .all()
    )

    items = [
        {
            "rank": idx,
            "nickname": _mask_nickname(r.username or ""),
            "referral_count": int(r.referral_count or 0),
        }
        for idx, r in enumerate(rows, start=1)
    ]

    return {"status": 0, "items": items}


@router.get("/community/referrals/network/{username}")
def referral_network(
    username: str,
    max_depth: int = Query(20),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """
    내 아래로 추천인 인맥(트리/다단계) 조회.
    - nickname은 Community_User.username을 그대로 사용
    - cursor는 offset 문자열("0", "100") 기반
    - total_count는 root 제외, 하위 인맥 distinct 기준
    - 100명 달성 시 1회 보상(100만 포인트) 지급
    """
    try:
        root = db.query(Community_User).filter(Community_User.username == username).first()
        if not root:
            return {
                "status": 1,
                "root_username": username,
                "total_count": 0,
                "items": [],
                "next_cursor": None,
                "reward": {"threshold": 100, "amount": 1_000_000, "granted": False},
            }

        # 방어적 파싱/제한
        try:
            offset = int((cursor or "0").strip() or "0")
        except Exception:
            offset = 0
        if offset < 0:
            offset = 0

        try:
            md = int(max_depth or 20)
        except Exception:
            md = 20
        if md < 1:
            md = 1
        # 과도한 재귀로 DB 부하가 커지는 것을 방지(Contract 변경 없이 내부 제한)
        md = min(md, 200)

        cte_base = """
WITH RECURSIVE downline AS (
    SELECT
        r.referred_user_id AS descendant_id,
        1 AS depth,
        ARRAY[r.referrer_user_id, r.referred_user_id] AS path
    FROM referral r
    WHERE r.referrer_user_id = :root_id
    UNION ALL
    SELECT
        r.referred_user_id AS descendant_id,
        d.depth + 1 AS depth,
        d.path || r.referred_user_id AS path
    FROM referral r
    JOIN downline d ON r.referrer_user_id = d.descendant_id
    WHERE d.depth < :max_depth
      AND NOT (r.referred_user_id = ANY(d.path))
)
"""

        total_sql = cte_base + """
SELECT COUNT(*) AS total_count
FROM (SELECT DISTINCT descendant_id FROM downline) s
"""

        total_row = db.execute(text(total_sql), {"root_id": int(root.id), "max_depth": md}).first()
        total_count = int(getattr(total_row, "total_count", 0) or 0)

        items_sql = cte_base + """
, dedup AS (
    SELECT descendant_id, MIN(depth) AS depth
    FROM downline
    GROUP BY descendant_id
)
SELECT
    u.username AS nickname,
    d.depth AS depth,
    u.signup_date AS joined_at
FROM dedup d
JOIN community_users u ON u.id::bigint = d.descendant_id
ORDER BY d.depth ASC, u.signup_date ASC NULLS LAST, u.username ASC
OFFSET :offset
LIMIT :limit
"""

        rows = db.execute(
            text(items_sql),
            {"root_id": int(root.id), "max_depth": md, "offset": int(offset), "limit": int(limit)},
        ).fetchall()

        items = [
            {
                "nickname": r.nickname,
                "depth": int(r.depth or 0),
                "joined_at": r.joined_at.isoformat() if getattr(r, "joined_at", None) else None,
            }
            for r in rows
        ]

        next_cursor = str(offset + int(limit)) if (offset + int(limit)) < total_count else None

        # --- 100명 달성 보상(1회성, 동시요청 중복 지급 방지) ---
        reward_granted = False
        if total_count >= 100:
            try:
                # user row lock으로 동일 유저의 보상 지급을 직렬화
                locked = (
                    db.query(Community_User).filter(Community_User.id == root.id).with_for_update().first()
                )
                if locked:
                    already = (
                        db.query(Point.id)
                        .filter(Point.user_id == locked.id, Point.reason == "referral_network_100")
                        .first()
                        is not None
                    )
                    if already:
                        reward_granted = True
                    else:
                        locked.point_balance = int(getattr(locked, "point_balance", 0) or 0) + 1_000_000
                        db.add(Point(user_id=locked.id, reason="referral_network_100", amount=1_000_000))
                        db.add(locked)
                        db.commit()
                        reward_granted = True
            except Exception:
                db.rollback()
                # 보상 지급 중 오류가 나더라도 Contract에 맞춰 status=8로 반환
                return {"status": 8}

        return {
            "status": 0,
            "root_username": str(root.username),
            "total_count": total_count,
            "items": items,
            "next_cursor": next_cursor,
            "reward": {"threshold": 100, "amount": 1_000_000, "granted": bool(reward_granted)},
        }
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return {"status": 8}


@router.get("/community/referrals/status")
def referral_status_by_date(
    limit: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
):
    """
    추천 현황(일자별 집계) 목록.
    - 반환: date(YYYY-MM-DD), referral_count
    - created_at은 Asia/Seoul 기준 날짜로 집계합니다.
    """
    try:
        sql = """
SELECT
  to_char(((r.created_at AT TIME ZONE 'Asia/Seoul')::date), 'YYYY-MM-DD') AS date,
  COUNT(*)::bigint AS referral_count
FROM referral r
GROUP BY ((r.created_at AT TIME ZONE 'Asia/Seoul')::date)
ORDER BY ((r.created_at AT TIME ZONE 'Asia/Seoul')::date) DESC
LIMIT :limit
"""
        rows = db.execute(text(sql), {"limit": int(limit)}).fetchall()
        items = [
            {
                "date": str(getattr(r, "date", "") or ""),
                "referral_count": int(getattr(r, "referral_count", 0) or 0),
            }
            for r in rows
        ]
        return {"status": 0, "items": items}
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return {"status": 8, "items": []}


@router.get("/community/referrals/status/{date}")
def referral_status_detail_by_date(date: str, db: Session = Depends(get_db)):
    """
    추천 현황(특정 날짜 상세).
    - date: YYYY-MM-DD
    - 반환 items: (추천 받은 회원 username, 추천한 회원 username, 추천 받은 회원의 전화번호, 추천 받은 날짜)
      -> (A_username, B_username, A_phone_number, date)
    """
    d = (date or "").strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
        return {"status": 1, "items": []}

    try:
        sql = """
SELECT
  a.username AS "A_username",
  b.username AS "B_username",
  a.phone_number AS "A_phone_number",
  b.phone_number AS "B_phone_number",
  to_char(((r.created_at AT TIME ZONE 'Asia/Seoul')::date), 'YYYY-MM-DD') AS date
FROM referral r
JOIN community_users a ON a.id::bigint = r.referred_user_id
JOIN community_users b ON b.id::bigint = r.referrer_user_id
WHERE ((r.created_at AT TIME ZONE 'Asia/Seoul')::date) = (:date)::date
ORDER BY r.created_at DESC, r.id DESC
"""
        rows = db.execute(text(sql), {"date": d}).fetchall()
        items = [
            {
                "A_username": getattr(r, "A_username", None),
                "B_username": getattr(r, "B_username", None),
                "A_phone_number": getattr(r, "A_phone_number", None),
                "B_phone_number": getattr(r, "B_phone_number", None),
                "date": str(getattr(r, "date", "") or d),
            }
            for r in rows
        ]
        return {"status": 0, "items": items}
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return {"status": 8, "items": []}
