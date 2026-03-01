from __future__ import annotations

import os
import tempfile
from datetime import date, datetime, timedelta, timezone

import openpyxl
from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import FileResponse
from sqlalchemy import func, or_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from deps import get_db
from models import Community_Post, Community_User, Community_User_Restriction, Point, Referral
from routers.notify import create_notification, send_push

router = APIRouter()


@router.get("/community/users/export")
def export_users(db: Session = Depends(get_db)):
    """
    커뮤니티 사용자 목록을 엑셀(xlsx)로 내보냅니다.
    - 인증 없이 다운로드 가능
    - Windows 환경에서도 파일이 손상되지 않도록, temp 파일 핸들 락을 피합니다.
    """
    users = db.query(Community_User).order_by(Community_User.id.asc()).all()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Users"

    ws.append(
        [
            "ID",
            "Username",
            "Name",
            "Phone",
            "Region",
            "Signup Date",
            "Is Owner",
            "User Grade",
            "Point Balance",
            "Cash Balance",
            "Marketing Consent",
            "Referral Code",
        ]
    )

    for u in users:
        ws.append(
            [
                u.id,
                u.username,
                u.name,
                u.phone_number,
                u.region,
                u.signup_date.isoformat() if getattr(u, "signup_date", None) else None,
                bool(getattr(u, "is_owner", False)),
                int(getattr(u, "user_grade", -1) or -1),
                int(getattr(u, "point_balance", 0) or 0),
                int(getattr(u, "cash_balance", 0) or 0),
                bool(getattr(u, "marketing_consent", False)),
                getattr(u, "referral_code", None),
            ]
        )

    # Windows에서 NamedTemporaryFile 핸들 락 이슈를 피하기 위해 mkstemp 사용
    fd, tmp_path = tempfile.mkstemp(suffix=".xlsx")
    os.close(fd)
    wb.save(tmp_path)
    try:
        wb.close()
    except Exception:
        pass

    download_name = f"users_{date.today().isoformat()}.xlsx"
    media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return FileResponse(
        tmp_path,
        filename=download_name,
        media_type=media_type,
        background=BackgroundTask(lambda p=tmp_path: os.path.exists(p) and os.remove(p)),
    )


def _dt_to_iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    try:
        if getattr(dt, "tzinfo", None) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        try:
            return dt.isoformat()
        except Exception:
            return None


def _load_restrictions_for_user(db: Session, user_id: int) -> dict[int, datetime | None]:
    rows = (
        db.query(Community_User_Restriction)
        .filter(Community_User_Restriction.user_id == user_id, Community_User_Restriction.post_type.in_([1, 3, 4]))
        .all()
    )
    out: dict[int, datetime | None] = {1: None, 3: None, 4: None}
    for r in rows:
        try:
            out[int(r.post_type)] = r.restricted_until
        except Exception:
            continue
    return out


@router.get("/community/admin/users")
def community_admin_list_users(
    cursor: str | None = Query(None),
    limit: int | None = Query(50),
    q: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """
    Contract:
      GET /community/admin/users?cursor?&limit?&q?
      response: { status, items:[{nickname,name,signup_date,admin_acknowledged}], next_cursor }
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    try:
        lim = int(limit or 50)
        if lim <= 0:
            lim = 50
        if lim > 200:
            lim = 200

        # cursor: offset 문자열("0", "50") 기반
        try:
            offset = int((cursor or "0").strip() or "0")
        except Exception:
            offset = 0
        if offset < 0:
            offset = 0

        qry = db.query(Community_User).order_by(
            Community_User.signup_date.desc().nullslast(),
            # 같은 날짜 내에서는 id 내림차순으로 최신 가입자를 위로
            Community_User.id.desc(),
            Community_User.username.asc(),
        )

        q_text = (q or "").strip()
        if q_text:
            pat = f"%{q_text}%"
            qry = qry.filter(or_(Community_User.username.ilike(pat), Community_User.name.ilike(pat)))

        rows = qry.offset(offset).limit(lim + 1).all()
        items = rows[:lim]
        next_cursor = str(offset + lim) if len(rows) > lim else None

        return {
            "status": 0,
            "items": [
                {
                    "id": int(u.id) if getattr(u, "id", None) is not None else None,
                    "nickname": u.username,
                    "name": u.name,
                    "signup_date": u.signup_date.isoformat() if getattr(u, "signup_date", None) else None,
                    "admin_acknowledged": bool(getattr(u, "admin_acknowledged", False)),
                }
                for u in items
            ],
            "next_cursor": next_cursor,
        }
    except Exception:
        return {"status": 8, "items": [], "next_cursor": None}


@router.get("/community/admin/users/{nickname}")
def community_admin_get_user(
    nickname: str,
    actor_nickname: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """
    Contract:
      GET /community/admin/users/{nickname}?actor_nickname=...
      response:
        status
        user: { nickname,name,phone_number,signup_date,point_balance,cash_balance,user_grade,is_owner,admin_acknowledged,referral_count,posts:{type1,type3,type4} }
        restrictions: Array<{ post_type, restricted_until }>
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    try:
        user = db.query(Community_User).filter(Community_User.username == nickname).first()
        if not user:
            return {"status": 1}

        def _post_item(p: Community_Post) -> dict:
            return {
                "id": int(p.id),
                "title": str(getattr(p, "title", "") or ""),
                "created_at": _dt_to_iso(getattr(p, "created_at", None)),
                "status": str(getattr(p, "status", None) or "") if getattr(p, "status", None) is not None else None,
            }

        rows = (
            db.query(Community_Post.post_type, func.count(Community_Post.id).label("cnt"))
            .filter(Community_Post.user_id == user.id, Community_Post.post_type.in_([1, 3, 4]))
            .group_by(Community_Post.post_type)
            .all()
        )
        counts = {1: 0, 3: 0, 4: 0}
        for pt, cnt in rows:
            try:
                counts[int(pt)] = int(cnt)
            except Exception:
                continue

        referral_count = db.query(func.count(Referral.id)).filter(Referral.referrer_user_id == user.id).scalar() or 0

        # (추가) 해당 회원이 "추천한" 대상 목록
        try:
            referred_rows = (
                db.query(
                    Referral,
                    Community_User.username.label("referred_username"),
                    Community_User.referral_code.label("referred_referral_code"),
                )
                .join(Community_User, Community_User.id == Referral.referred_user_id)
                .filter(Referral.referrer_user_id == user.id)
                .order_by(Referral.created_at.desc().nullslast(), Referral.id.desc())
                .limit(200)
                .all()
            )
            referred_items = [
                {
                    "id": int(r.Referral.id),
                    "referred_username": str(r.referred_username or ""),
                    "referred_referral_code": r.referred_referral_code,
                    "created_at": _dt_to_iso(getattr(r.Referral, "created_at", None)),
                }
                for r in referred_rows
            ]
        except Exception:
            referred_items = []

        # (추가) 이 회원을 "추천한" 사람(추천인)
        referred_by_user_id = None
        referred_by_username = None
        referred_by_referrer_code = None
        referred_by_created_at = None
        try:
            ref_row = (
                db.query(Referral)
                .filter(Referral.referred_user_id == user.id)
                .order_by(Referral.created_at.desc().nullslast(), Referral.id.desc())
                .first()
            )
            if ref_row:
                try:
                    referred_by_user_id = int(getattr(ref_row, "referrer_user_id", None))
                except Exception:
                    referred_by_user_id = None
                referred_by_referrer_code = getattr(ref_row, "referrer_code", None)
                referred_by_created_at = _dt_to_iso(getattr(ref_row, "created_at", None))

                if referred_by_user_id is not None:
                    referrer_user = db.query(Community_User).filter(Community_User.id == referred_by_user_id).first()
                    referred_by_username = str(getattr(referrer_user, "username", None)) if referrer_user else None
        except Exception:
            pass

        restrictions_map = _load_restrictions_for_user(db, int(user.id))

        # (추가) 작성 글 목록(읽기 전용): 타입별 최근 N개
        def _list_posts_by_type(pt: int, lim: int = 20) -> list[dict]:
            try:
                posts = (
                    db.query(Community_Post)
                    .filter(Community_Post.user_id == user.id, Community_Post.post_type == pt)
                    .order_by(Community_Post.created_at.desc(), Community_Post.id.desc())
                    .limit(lim)
                    .all()
                )
                return [_post_item(p) for p in posts]
            except Exception:
                return []

        return {
            "status": 0,
            "user": {
                "nickname": user.username,
                "name": user.name,
                "phone_number": getattr(user, "phone_number", None),
                "signup_date": user.signup_date.isoformat() if getattr(user, "signup_date", None) else None,
                "point_balance": int(user.point_balance or 0),
                "cash_balance": int(user.cash_balance or 0),
                "user_grade": int(getattr(user, "user_grade", 0) or 0),
                "is_owner": bool(getattr(user, "is_owner", False)),
                "admin_acknowledged": bool(getattr(user, "admin_acknowledged", False)),
                "referral_code": getattr(user, "referral_code", None),
                "referral_count": int(referral_count),
                "referred_by_user_id": referred_by_user_id,
                "referred_by_username": referred_by_username,
                "referred_by_referrer_code": referred_by_referrer_code,
                "referred_by_created_at": referred_by_created_at,
                "posts": {"type1": counts[1], "type3": counts[3], "type4": counts[4]},
            },
            "restrictions": [
                {"post_type": 1, "restricted_until": _dt_to_iso(restrictions_map[1])},
                {"post_type": 3, "restricted_until": _dt_to_iso(restrictions_map[3])},
                {"post_type": 4, "restricted_until": _dt_to_iso(restrictions_map[4])},
            ],
            "referred_items": referred_items,
            "post_items": {"type1": _list_posts_by_type(1, 20), "type3": _list_posts_by_type(3, 20), "type4": _list_posts_by_type(4, 20)},
        }
    except Exception:
        return {"status": 8}


@router.post("/community/admin/users/{nickname}/restrictions")
def community_admin_update_user_restrictions(
    nickname: str,
    body: dict = Body(default_factory=dict),
    db: Session = Depends(get_db),
):
    """
    Contract:
      POST /community/admin/users/{nickname}/restrictions
      body: { actor_nickname, changes:[{post_type,days}], reason? }
      response: { status, restrictions:[{post_type,restricted_until}] }
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    actor_nickname = body.get("actor_nickname")
    changes = body.get("changes")
    reason = body.get("reason")

    if not isinstance(changes, list) or len(changes) == 0:
        return {"status": 1, "restrictions": []}

    try:
        user = db.query(Community_User).filter(Community_User.username == nickname).first()
        if not user:
            return {"status": 1, "restrictions": []}

        actor = None
        if isinstance(actor_nickname, str) and actor_nickname.strip():
            actor = db.query(Community_User).filter(Community_User.username == actor_nickname.strip()).first()

        now = datetime.now(timezone.utc)
        for ch in changes:
            try:
                post_type = int(ch.get("post_type"))
                days = int(ch.get("days"))
            except Exception:
                continue
            if post_type not in (1, 3, 4):
                continue
            if days < 0:
                continue

            restricted_until = None if days == 0 else (now + timedelta(days=days))

            stmt = (
                insert(Community_User_Restriction)
                .values(
                    user_id=int(user.id),
                    post_type=post_type,
                    restricted_until=restricted_until,
                    reason=(str(reason) if reason is not None else None),
                    created_by_user_id=None,
                )
                .on_conflict_do_update(
                    index_elements=["user_id", "post_type"],
                    set_={
                        "restricted_until": restricted_until,
                        "reason": (str(reason) if reason is not None else None),
                        "created_by_user_id": (int(actor.id) if actor else None),
                        "created_at": func.now(),
                    },
                )
            )
            db.execute(stmt)

        db.commit()

        restrictions_map = _load_restrictions_for_user(db, int(user.id))
        return {
            "status": 0,
            "restrictions": [
                {"post_type": 1, "restricted_until": _dt_to_iso(restrictions_map[1])},
                {"post_type": 3, "restricted_until": _dt_to_iso(restrictions_map[3])},
                {"post_type": 4, "restricted_until": _dt_to_iso(restrictions_map[4])},
            ],
        }
    except Exception:
        db.rollback()
        return {"status": 8, "restrictions": []}


@router.post("/community/admin/users/{nickname}/notify")
def community_admin_notify_user(
    nickname: str,
    body: dict = Body(default_factory=dict),
    db: Session = Depends(get_db),
):
    """
    Contract:
      POST /community/admin/users/{nickname}/notify
      body: { actor_nickname, title, body }
      response: { status, notification_id? }
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    actor_nickname = body.get("actor_nickname")
    title = body.get("title")
    msg = body.get("body")

    if not isinstance(title, str) or not title.strip():
        return {"status": 1}
    if not isinstance(msg, str) or not msg.strip():
        return {"status": 1}

    try:
        user = db.query(Community_User).filter(Community_User.username == nickname).first()
        if not user:
            return {"status": 1}

        data = {"source": "admin", "actor_nickname": actor_nickname}
        noti = create_notification(
            db,
            user_id=int(user.id),
            title=title.strip(),
            body=msg.strip(),
            type="system",
            data=data,
        )

        if getattr(user, "push_token", None):
            send_push(getattr(user, "push_token"), title.strip(), msg.strip(), data)

        return {"status": 0, "notification_id": int(getattr(noti, "id", 0) or 0)}
    except Exception:
        db.rollback()
        return {"status": 8}


@router.post("/community/owner/users/{nickname}/points")
def community_owner_grant_points(
    nickname: str,
    body: dict = Body(default_factory=dict),
    db: Session = Depends(get_db),
):
    """
    Contract:
      POST /community/owner/users/{nickname}/points
      body: { actor_nickname, amount(양수), reason(필수) }
      response: { status, point_balance }
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    amount = body.get("amount")
    reason = body.get("reason")

    try:
        amt = int(amount)
    except Exception:
        return {"status": 1, "point_balance": 0}
    if amt <= 0:
        return {"status": 1, "point_balance": 0}
    if not isinstance(reason, str) or not reason.strip():
        return {"status": 1, "point_balance": 0}

    try:
        user = db.query(Community_User).filter(Community_User.username == nickname).with_for_update().first()
        if not user:
            return {"status": 1, "point_balance": 0}

        user.point_balance = int(user.point_balance or 0) + amt
        db.add(Point(user_id=int(user.id), reason=reason.strip(), amount=amt))
        db.commit()
        db.refresh(user)

        return {"status": 0, "point_balance": int(user.point_balance or 0)}
    except Exception:
        db.rollback()
        return {"status": 8, "point_balance": 0}


@router.post("/community/owner/users/{nickname}/admin-acknowledged")
def community_owner_set_admin_acknowledged(
    nickname: str,
    body: dict = Body(default_factory=dict),
    db: Session = Depends(get_db),
):
    """
    오너 권한에서 관리자 권한 수정(부여/회수).
    body: { actor_nickname, admin_acknowledged?: true|false }  (미지정 시 true)
    response: { status, admin_acknowledged }
    status: 0|1|3|8
    """
    enabled_raw = body.get("admin_acknowledged", None)

    enabled = True
    if enabled_raw is None:
        enabled = True
    elif isinstance(enabled_raw, bool):
        enabled = enabled_raw
    elif isinstance(enabled_raw, (int, float)):
        try:
            enabled = bool(int(enabled_raw))
        except Exception:
            return {"status": 1, "admin_acknowledged": False}
    elif isinstance(enabled_raw, str):
        s = enabled_raw.strip().lower()
        if s in ("1", "true", "t", "yes", "y", "on"):
            enabled = True
        elif s in ("0", "false", "f", "no", "n", "off"):
            enabled = False
        else:
            return {"status": 1, "admin_acknowledged": False}
    else:
        return {"status": 1, "admin_acknowledged": False}

    try:
        user = db.query(Community_User).filter(Community_User.username == nickname).with_for_update().first()
        if not user:
            return {"status": 1, "admin_acknowledged": False}

        user.admin_acknowledged = bool(enabled)
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"status": 0, "admin_acknowledged": bool(getattr(user, "admin_acknowledged", False))}
    except Exception:
        db.rollback()
        return {"status": 8, "admin_acknowledged": False}

