from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.orm import Session

from database import SessionLocal
from fastapi import Depends, Header, HTTPException, status
import jwt

from models import Community_User
from settings import ALGORITHM, SECRET_KEY


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -------------------- Community auth deps --------------------
def get_current_community_user(
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> Community_User:
    """
    커뮤니티 앱용 JWT 인증 의존성.
    Authorization: Bearer <token>
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(Community_User).filter(Community_User.id == uid).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def try_get_current_community_user(db: Session, authorization: str | None) -> Community_User | None:
    """
    Authorization 헤더가 있을 때만 JWT를 시도하고, 실패 시 None을 반환합니다.
    """
    try:
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        token = authorization.split(" ", 1)[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload.get("sub"))
        return db.query(Community_User).filter(Community_User.id == uid).first()
    except Exception:
        return None


def is_admin_or_owner(u: Community_User | None) -> bool:
    if not u:
        return False
    return bool(getattr(u, "admin_acknowledged", False) or getattr(u, "is_owner", False))


def is_owner(u: Community_User | None) -> bool:
    return bool(u and getattr(u, "is_owner", False))

