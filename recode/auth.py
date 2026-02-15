import jwt
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from models import User
from settings import ALGORITHM, SECRET_KEY


def try_get_current_user(db: Session, authorization: str | None) -> User | None:
    """
    Authorization 헤더가 있을 때만 JWT를 시도하고, 실패 시 None을 반환합니다.
    - /auth/login 토큰(sub=users.id) 전용
    """
    try:
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        token = authorization.split(" ", 1)[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload.get("sub"))
        return db.query(User).filter(User.id == uid).first()
    except Exception:
        return None


def get_current_user(
    db: Session,
    authorization: str | None,
) -> User:
    """
    /auth/login 으로 발급된 JWT(sub=users.id) 기반 인증.
    """
    u = try_get_current_user(db, authorization)
    if not u:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )
    return u

