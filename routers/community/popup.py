from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from deps import get_db, get_current_community_user
from models import Community_User

router = APIRouter()


@router.post("/community/popup/seen")
def mark_popup_seen(
    me: Community_User = Depends(get_current_community_user),
    db: Session = Depends(get_db),
):
    """
    팝업(공지/이벤트 등) 마지막 확인 시각 저장.
    - community_users.popup_last_seen_at 갱신
    """
    user = (
        db.query(Community_User)
        .filter(Community_User.id == me.id)
        .with_for_update()
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.popup_last_seen_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return {
        "status": 0,
        "popup_last_seen_at": user.popup_last_seen_at.isoformat() if user.popup_last_seen_at else None,
    }

