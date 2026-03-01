from __future__ import annotations

import requests
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text as sql_text
from sqlalchemy.orm import Session

from deps import get_db
from models import Community_User, Notification


router = APIRouter()


class MyNotifyRequest(BaseModel):
    title: str
    body: str
    data: dict = {}
    type: str = "system"


def create_notification(
    db: Session,
    user_id: int,
    title: str,
    body: str,
    type: str = "system",
    data: dict | None = None,
    commit: bool = True,
):
    noti = Notification(user_id=user_id, title=title, body=body, type=type, data=data or {})
    db.add(noti)
    if commit:
        db.commit()
        db.refresh(noti)
    return noti


def get_user_id_by_username(db: Session, username: str) -> int:
    row = (
        db.query(Community_User.id)
        .filter(Community_User.username == (username or "").strip())
        .first()
    )
    if not row or row[0] is None:
        raise HTTPException(status_code=404, detail="User not found")
    return int(row[0])


def send_push(token, title, body, data=None, badge=1):
    message = {
        "to": token,
        "sound": "default",
        "title": title,
        "body": body,
        "data": data or {},
        "badge": badge,
        "priority": "high",
        "channelId": "default",
    }

    resp = requests.post(
        "https://exp.host/--/api/v2/push/send",
        json=message,
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    try:
        print("Expo push response:", resp.json())
    except Exception:
        print("Push response parse failed:", resp.text)


@router.post("/notify/my/{username}")
def notify_my(username: str, req: MyNotifyRequest, db: Session = Depends(get_db)):
    user_id = get_user_id_by_username(db, username)

    noti = create_notification(
        db,
        user_id=user_id,
        title=req.title,
        body=req.body,
        type=req.type,
        data=req.data,
    )

    token_row = db.execute(
        "SELECT push_token FROM community_users WHERE id = :uid", {"uid": user_id}
    ).fetchone()

    if token_row and token_row[0]:
        send_push(token_row[0], req.title, req.body, req.data)

    return {"status": "ok", "notification_id": noti.id}


@router.get("/notify/my/{username}/unread")
def get_unread_notifications(username: str, db: Session = Depends(get_db)):
    user_id = get_user_id_by_username(db, username)
    rows = (
        db.query(Notification)
        .filter(Notification.user_id == user_id, Notification.is_read == False)
        .order_by(Notification.id.desc())
        .all()
    )
    return rows


@router.get("/notify/my/{username}/unread/count")
def unread_count_by_username(username: str, db: Session = Depends(get_db)):
    user_id = get_user_id_by_username(db, username)
    count = (
        db.query(Notification)
        .filter(Notification.user_id == user_id, Notification.is_read == False)
        .count()
    )
    return {"unread_count": count}


@router.post("/notify/read/{notification_id}")
def mark_notification_read(notification_id: int, db: Session = Depends(get_db)):
    db.query(Notification).filter(Notification.id == notification_id).update(
        {"is_read": True}
    )
    db.commit()
    return {"status": "ok"}


def _notification_to_dict(n: Notification) -> dict:
    return {
        "id": int(getattr(n, "id", 0) or 0),
        "title": getattr(n, "title", None),
        "body": getattr(n, "body", None),
        "type": getattr(n, "type", None),
        "data": getattr(n, "data", None) or {},
        "is_read": bool(getattr(n, "is_read", False)),
        "created_at": getattr(n, "created_at", None).isoformat() if getattr(n, "created_at", None) else None,
    }


@router.get("/notify/my/{username}")
def get_all_notifications(username: str, db: Session = Depends(get_db)):
    """
    회원이 받은 알림 전체 내역(읽음/미읽음 포함).
    - legacy: 앱은 기존에 /unread만 사용했음
    """
    user_id = get_user_id_by_username(db, username)
    rows = (
        db.query(Notification)
        .filter(Notification.user_id == user_id)
        .order_by(Notification.id.desc())
        .all()
    )
    return [_notification_to_dict(r) for r in rows]


@router.post("/notify/my/{username}/read-all")
def mark_all_notifications_read_by_user(username: str, db: Session = Depends(get_db)):
    """
    회원 알림을 서버에서 일괄 읽음 처리.
    - 기존 클라이언트는 id들을 순회 호출했음
    """
    user_id = get_user_id_by_username(db, username)
    updated = (
        db.query(Notification)
        .filter(Notification.user_id == user_id, Notification.is_read == False)
        .update({"is_read": True})
    )
    db.commit()
    return {"status": "ok", "updated": int(updated or 0)}


@router.get("/notify/sent/{actor_nickname}")
def get_admin_sent_notifications(
    actor_nickname: str,
    limit: int = Query(300, ge=1, le=3000),
    db: Session = Depends(get_db),
):
    """
    관리자가 회원에게 보낸 알림 내역.
    - 권한 체크는 클라이언트에서만 제어(기존 정책 유지)
    - community_admin_notify_user에서 data에 {source:'admin', actor_nickname}를 저장한 것을 기준으로 조회합니다.
    """
    actor = (actor_nickname or "").strip()
    if not actor:
        raise HTTPException(status_code=400, detail="actor_nickname is required")

    # Postgres JSON operator 기반(프로젝트 사용 DB 특성상 PostgreSQL 전제)
    rows = db.execute(
        sql_text(
            """
            SELECT
              n.id,
              u.username AS target_username,
              n.title,
              n.body,
              n.type,
              n.data,
              n.is_read,
              n.created_at
            FROM notifications n
            JOIN community_users u ON u.id = n.user_id
            WHERE (n.data->>'source') = 'admin'
              AND (n.data->>'actor_nickname') = :actor
            ORDER BY n.id DESC
            LIMIT :limit
            """
        ),
        {"actor": actor, "limit": int(limit)},
    ).fetchall()

    items: list[dict] = []
    for r in rows:
        created_at = None
        try:
            created_at = r.created_at.isoformat() if getattr(r, "created_at", None) else None
        except Exception:
            created_at = None
        items.append(
            {
                "id": int(r.id or 0),
                "target_username": r.target_username,
                "title": r.title,
                "body": r.body,
                "type": r.type,
                "data": r.data or {},
                "is_read": bool(r.is_read),
                "created_at": created_at,
            }
        )

    return {"status": "ok", "items": items}

