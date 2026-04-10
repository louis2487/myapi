from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from deps import get_db
from routers.parking import (
    _ensure_parking_daily_activity_schema,
    _ensure_parking_users_schema,
    _record_daily_activity,
    _require_parking_user,
)

router = APIRouter()


class JhrRoleAuthIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=30)
    password: str = Field(..., min_length=2, max_length=200)


class JhrRoleSetIn(JhrRoleAuthIn):
    role: Literal["STUDENT", "CREATOR"]


class JhrRoleOut(BaseModel):
    username: str
    role: Literal["STUDENT", "CREATOR"]


@router.post("/jhr/role", response_model=JhrRoleOut)
def get_jhr_role(req: JhrRoleAuthIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    row = _require_parking_user(db, username, req.password)
    return {
        "username": str(row["username"]),
        "role": str(row.get("role") or "STUDENT"),
    }


@router.put("/jhr/role", response_model=JhrRoleOut)
def set_jhr_role(req: JhrRoleSetIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    _ensure_parking_daily_activity_schema(db)

    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    row = _require_parking_user(db, username, req.password)
    updated = (
        db.execute(
            text(
                """
                UPDATE parking_users
                SET role = :r,
                    action_date = (now() AT TIME ZONE 'Asia/Seoul')
                WHERE id = :id
                RETURNING username, role
                """
            ),
            {"r": req.role, "id": int(row["id"])},
        )
        .mappings()
        .first()
    )
    if not updated:
        db.rollback()
        raise HTTPException(status_code=404, detail="User not found.")

    _record_daily_activity(db, int(row["id"]))
    db.commit()
    return {
        "username": str(updated["username"]),
        "role": str(updated["role"]),
    }
