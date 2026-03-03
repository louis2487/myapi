from __future__ import annotations

from sqlalchemy import or_
from sqlalchemy.orm import Session

from models import Community_User, Notification
from routers.notify import create_notification, send_push


def notify_admin_post(db: Session, title: str, body: str, post_id: int, target_user_id: int, post_type: int = 3):
    noti = create_notification(
        db,
        user_id=target_user_id,
        title=title,
        body=body,
        type="post",
        data={"post_id": post_id, "post_type": post_type},
    )

    user = db.query(Community_User).filter(Community_User.id == target_user_id).first()

    if user and user.push_token:
        send_push(user.push_token, title, body, {"post_id": post_id, "post_type": post_type})

    return noti


def notify_owners_post(
    db: Session,
    *,
    post_id: int,
    post_type: int,
    author_username: str,
    post_title: str,
    exclude_user_id: int | None = None,
):
    """
    오너(is_owner=True)에게 "글(문의 등) 등록" 푸쉬 + 미확인 알림 저장.
    - 알림 실패는 글 등록 결과에 영향을 주지 않도록 호출부에서 try/except 처리 권장.
    """
    pt = int(post_type)
    label = "글"
    if pt == 6:
        label = "문의글"
    elif pt == 7:
        label = "대행문의"

    title = f"새 {label}이 등록되었습니다"
    body = f"{author_username}님이 새로운 {label}을 작성했습니다: {post_title}"
    data = {"post_id": int(post_id), "post_type": int(pt)}

    owners = db.query(Community_User).filter(Community_User.is_owner.is_(True)).all()
    for o in owners:
        if exclude_user_id is not None and int(getattr(o, "id", 0) or 0) == int(exclude_user_id):
            continue
        try:
            create_notification(
                db,
                user_id=int(o.id),
                title=title,
                body=body,
                type="post",
                data=data,
                commit=True,
            )
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            continue

        try:
            token = getattr(o, "push_token", None)
            if token:
                send_push(token, title, body, data)
        except Exception:
            pass


def notify_admin_acknowledged_post(
    db: Session,
    *,
    post_id: int,
    post_type: int,
    author_username: str,
    post_title: str,
    exclude_user_id: int | None = None,
    include_owners: bool = False,
):
    """
    구인/수다/광고 글 등록 시 관리자(admin_acknowledged=True)에게 푸쉬 + 미확인 알림 저장.
    - 알림 실패는 글 등록 결과에 영향을 주지 않도록 호출부에서 try/except 처리 권장.
    """
    pt = int(post_type)
    label = "글"
    if pt == 1:
        label = "구인글"
    elif pt == 3:
        label = "수다글"
    elif pt == 4:
        label = "광고글"
    elif pt == 6:
        label = "문의글"

    title = f"새 {label}이 등록되었습니다"
    body = f"{author_username}님이 새로운 {label}을 작성했습니다: {post_title}"
    data = {"post_id": int(post_id), "post_type": int(pt)}

    if include_owners:
        targets = (
            db.query(Community_User)
            .filter(or_(Community_User.admin_acknowledged.is_(True), Community_User.is_owner.is_(True)))
            .all()
        )
    else:
        targets = db.query(Community_User).filter(Community_User.admin_acknowledged.is_(True)).all()

    # 중복 대상 제거(예: owner이면서 admin_acknowledged인 경우)
    uniq: dict[int, Community_User] = {}
    for u in targets:
        try:
            uid = int(getattr(u, "id", 0) or 0)
        except Exception:
            continue
        if uid:
            uniq[uid] = u

    for a in uniq.values():
        if exclude_user_id is not None and int(getattr(a, "id", 0) or 0) == int(exclude_user_id):
            continue
        try:
            create_notification(
                db,
                user_id=int(a.id),
                title=title,
                body=body,
                type="post",
                data=data,
                commit=True,
            )
        except Exception:
            # 세션이 실패 상태가 되면 다음 루프에서 계속 실패하므로 롤백
            try:
                db.rollback()
            except Exception:
                pass
            continue

        try:
            token = getattr(a, "push_token", None)
            if token:
                send_push(token, title, body, data)
        except Exception:
            pass


def notify_all_push_post(
    db: Session,
    *,
    post_id: int,
    post_type: int,
    author_username: str,
    post_title: str,
):
    """
    공지사항 등 "전체 푸쉬"가 필요한 글에 대해,
    push_token이 있는 전체 사용자에게 푸쉬 + 알림 저장.
    """
    pt = int(post_type)
    label = "글"
    if pt == 5:
        label = "공지사항"

    title = f"새 {label}이 등록되었습니다"
    body = f"{post_title}"
    data = {"post_id": int(post_id), "post_type": int(pt)}

    # "전체"의 기준: push_token이 있는 사용자(푸쉬 수신 가능)
    targets = (
        db.query(Community_User.id, Community_User.push_token)
        .filter(Community_User.push_token.isnot(None), Community_User.push_token != "")
        .all()
    )

    # 알림 저장(한 번에 커밋)
    try:
        for uid, _token in targets:
            db.add(Notification(user_id=int(uid), title=title, body=body, type="post", data=data))
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    # 푸쉬 발송(best-effort)
    for _uid, token in targets:
        try:
            if token:
                send_push(token, title, body, data)
        except Exception:
            pass


def notify_owners_event(db: Session, title: str, body: str, data: dict | None = None):
    """
    회원가입/탈퇴 등 시스템 이벤트를 오너(is_owner=True)에게 푸쉬 + 미확인 알림 저장.
    """
    owners = db.query(Community_User).filter(Community_User.is_owner.is_(True)).all()
    payload = data or {}
    for o in owners:
        try:
            create_notification(
                db,
                user_id=int(o.id),
                title=title,
                body=body,
                type="system",
                data=payload,
                commit=True,
            )
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            continue

        try:
            token = getattr(o, "push_token", None)
            if token:
                send_push(token, title, body, payload)
        except Exception:
            pass


def notify_admin_acknowledged_event(db: Session, title: str, body: str, data: dict | None = None):
    """
    회원가입/탈퇴 등 시스템 이벤트를 관리자(admin_acknowledged=True)에게 푸쉬 + 미확인 알림 저장.
    - 요구사항(2026-02-06): is_owner가 아닌 admin_acknowledged=True 기준으로 알림 대상 선정
    """
    admins = db.query(Community_User).filter(Community_User.admin_acknowledged.is_(True)).all()
    payload = data or {}
    for a in admins:
        try:
            create_notification(
                db,
                user_id=int(a.id),
                title=title,
                body=body,
                type="system",
                data=payload,
                commit=True,
            )
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            continue

        try:
            token = getattr(a, "push_token", None)
            if token:
                send_push(token, title, body, payload)
        except Exception:
            pass

