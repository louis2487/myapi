from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from deps import get_db
from models import Cash, Community_User

from .time_utils import to_kst_iso

router = APIRouter()


@router.get("/community/cash/{username}")
def list_cash(username: str, db: Session = Depends(get_db)):
    """
    내 캐시 충전/사용 내역(원장).
    """
    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1, "items": []}

    rows = (
        db.query(Cash)
        .filter(Cash.user_id == user.id)
        .order_by(Cash.created_at.desc(), Cash.id.desc())
        .limit(500)
        .all()
    )

    items = [
        {
            "id": c.id,
            "reason": c.reason,
            "amount": int(c.amount),
            "created_at": to_kst_iso(c.created_at),
        }
        for c in rows
    ]

    return {"status": 0, "items": items}

