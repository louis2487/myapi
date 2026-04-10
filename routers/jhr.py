from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
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
_JHR_SCHEMA_READY = False


def _ensure_jhr_schema(db: Session):
    global _JHR_SCHEMA_READY
    if _JHR_SCHEMA_READY:
        return
    try:
        db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS jhr_classes (
                    id BIGSERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    price NUMERIC(12,2) NOT NULL DEFAULT 0,
                    capacity INTEGER NOT NULL,
                    current_count INTEGER NOT NULL DEFAULT 0,
                    start_date TIMESTAMPTZ NOT NULL,
                    end_date TIMESTAMPTZ NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
                    creator_user_id BIGINT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
        )
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS creator_user_id BIGINT"))
        db.execute(
            text(
                """
                UPDATE jhr_classes
                SET creator_user_id = 0
                WHERE creator_user_id IS NULL
                """
            )
        )
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN creator_user_id SET NOT NULL"))
        db.execute(text("ALTER TABLE jhr_classes DROP CONSTRAINT IF EXISTS jhr_classes_status_check"))
        db.execute(
            text(
                """
                ALTER TABLE jhr_classes
                ADD CONSTRAINT jhr_classes_status_check
                CHECK (status IN ('DRAFT', 'OPEN', 'CLOSED'))
                """
            )
        )
        db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS ix_jhr_classes_status_created
                ON jhr_classes (status, created_at DESC)
                """
            )
        )

        db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS jhr_enrollments (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    class_id BIGINT NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    confirmed_at TIMESTAMPTZ NULL,
                    canceled_at TIMESTAMPTZ NULL
                );
                """
            )
        )
        db.execute(text("ALTER TABLE jhr_enrollments DROP CONSTRAINT IF EXISTS jhr_enrollments_status_check"))
        db.execute(
            text(
                """
                ALTER TABLE jhr_enrollments
                ADD CONSTRAINT jhr_enrollments_status_check
                CHECK (status IN ('PENDING', 'CONFIRMED', 'CANCELLED'))
                """
            )
        )
        db.execute(
            text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS uq_jhr_enrollments_user_class
                ON jhr_enrollments (user_id, class_id)
                """
            )
        )
        db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS ix_jhr_enrollments_class_status
                ON jhr_enrollments (class_id, status)
                """
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        _JHR_SCHEMA_READY = True


class JhrRoleAuthIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=30)
    password: str = Field(..., min_length=2, max_length=200)


class JhrRoleSetIn(JhrRoleAuthIn):
    role: Literal["STUDENT", "CREATOR"]


class JhrRoleOut(BaseModel):
    username: str
    role: Literal["STUDENT", "CREATOR"]


class JhrClassCreateIn(JhrRoleAuthIn):
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(default="", max_length=5000)
    price: Decimal = Field(default=0, ge=0)
    capacity: int = Field(..., ge=1, le=100000)
    start_date: datetime
    end_date: datetime
    status: Literal["DRAFT", "OPEN", "CLOSED"] = "DRAFT"


class JhrClassUpdateIn(JhrRoleAuthIn):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    price: Decimal | None = Field(default=None, ge=0)
    capacity: int | None = Field(default=None, ge=1, le=100000)
    start_date: datetime | None = None
    end_date: datetime | None = None
    status: Literal["DRAFT", "OPEN", "CLOSED"] | None = None


class JhrClassOut(BaseModel):
    id: int
    title: str
    description: str | None = None
    price: str
    capacity: int
    current_count: int
    start_date: datetime
    end_date: datetime
    status: Literal["DRAFT", "OPEN", "CLOSED"]
    creator_user_id: int
    created_at: datetime
    updated_at: datetime
    is_enrolled: bool = False
    my_enrollment_status: Literal["PENDING", "CONFIRMED", "CANCELLED"] | None = None
    my_enrollment_id: int | None = None


class JhrEnrollmentReqIn(JhrRoleAuthIn):
    class_id: int = Field(..., ge=1)


class JhrEnrollmentActionIn(JhrRoleAuthIn):
    enrollment_id: int = Field(..., ge=1)


class JhrEnrollmentOut(BaseModel):
    id: int
    user_id: int
    class_id: int
    status: Literal["PENDING", "CONFIRMED", "CANCELLED"]
    applied_at: datetime
    confirmed_at: datetime | None = None
    canceled_at: datetime | None = None
    class_title: str | None = None


def _require_creator(db: Session, username: str, password: str):
    user = _require_parking_user(db, username, password)
    if str(user.get("role") or "STUDENT") != "CREATOR":
        raise HTTPException(status_code=403, detail="CREATOR only.")
    return user


def _require_student(db: Session, username: str, password: str):
    user = _require_parking_user(db, username, password)
    if str(user.get("role") or "STUDENT") != "STUDENT":
        raise HTTPException(status_code=403, detail="STUDENT only.")
    return user


def _row_to_class_out(row, my_row=None):
    return {
        "id": int(row["id"]),
        "title": str(row["title"]),
        "description": row.get("description"),
        "price": str(row.get("price") or "0"),
        "capacity": int(row.get("capacity") or 0),
        "current_count": int(row.get("current_count") or 0),
        "start_date": row["start_date"],
        "end_date": row["end_date"],
        "status": str(row["status"]),
        "creator_user_id": int(row.get("creator_user_id") or 0),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "is_enrolled": bool(my_row),
        "my_enrollment_status": (str(my_row["status"]) if my_row else None),
        "my_enrollment_id": (int(my_row["id"]) if my_row else None),
    }


@router.post("/jhr/role", response_model=JhrRoleOut)
def get_jhr_role(req: JhrRoleAuthIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    username = req.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    row = _require_parking_user(db, username, req.password)
    return {"username": str(row["username"]), "role": str(row.get("role") or "STUDENT")}


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
                SET role = :r, action_date = (now() AT TIME ZONE 'Asia/Seoul')
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
    return {"username": str(updated["username"]), "role": str(updated["role"])}


@router.get("/jhr/classes", response_model=list[JhrClassOut])
def list_jhr_classes(
    username: str = Query(..., min_length=1, max_length=30),
    password: str = Query(..., min_length=2, max_length=200),
    status: Literal["DRAFT", "OPEN", "CLOSED"] | None = Query(default=None),
    db: Session = Depends(get_db),
):
    _ensure_parking_users_schema(db)
    _ensure_jhr_schema(db)
    user = _require_parking_user(db, username.strip(), password)
    cond = "WHERE 1=1"
    params: dict[str, object] = {}
    if status is not None:
        cond += " AND c.status = :st"
        params["st"] = status
    rows = (
        db.execute(
            text(
                f"""
                SELECT c.*
                FROM jhr_classes c
                {cond}
                ORDER BY c.created_at DESC, c.id DESC
                """
            ),
            params,
        )
        .mappings()
        .all()
    )
    my_map_rows = (
        db.execute(
            text(
                """
                SELECT id, class_id, status
                FROM jhr_enrollments
                WHERE user_id = :uid
                """
            ),
            {"uid": int(user["id"])},
        )
        .mappings()
        .all()
    )
    my_map = {int(r["class_id"]): r for r in my_map_rows}
    return [_row_to_class_out(r, my_map.get(int(r["id"]))) for r in rows]


@router.get("/jhr/classes/{class_id}", response_model=JhrClassOut)
def get_jhr_class_detail(
    class_id: int,
    username: str = Query(..., min_length=1, max_length=30),
    password: str = Query(..., min_length=2, max_length=200),
    db: Session = Depends(get_db),
):
    _ensure_parking_users_schema(db)
    _ensure_jhr_schema(db)
    user = _require_parking_user(db, username.strip(), password)
    row = (
        db.execute(text("SELECT * FROM jhr_classes WHERE id = :id LIMIT 1"), {"id": class_id})
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Class not found.")
    my_row = (
        db.execute(
            text(
                """
                SELECT id, class_id, status
                FROM jhr_enrollments
                WHERE user_id = :uid AND class_id = :cid
                LIMIT 1
                """
            ),
            {"uid": int(user["id"]), "cid": class_id},
        )
        .mappings()
        .first()
    )
    return _row_to_class_out(row, my_row)


@router.post("/jhr/classes", response_model=JhrClassOut)
def create_jhr_class(req: JhrClassCreateIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    _ensure_jhr_schema(db)
    _ensure_parking_daily_activity_schema(db)
    username = req.username.strip()
    creator = _require_creator(db, username, req.password)
    if req.end_date <= req.start_date:
        raise HTTPException(status_code=400, detail="end_date must be after start_date.")
    created = (
        db.execute(
            text(
                """
                INSERT INTO jhr_classes
                (title, description, price, capacity, current_count, start_date, end_date, status, creator_user_id)
                VALUES (:t, :d, :p, :c, 0, :sd, :ed, :st, :uid)
                RETURNING *
                """
            ),
            {
                "t": req.title.strip(),
                "d": req.description.strip() if req.description else "",
                "p": req.price,
                "c": req.capacity,
                "sd": req.start_date,
                "ed": req.end_date,
                "st": req.status,
                "uid": int(creator["id"]),
            },
        )
        .mappings()
        .first()
    )
    _record_daily_activity(db, int(creator["id"]))
    db.commit()
    if not created:
        raise HTTPException(status_code=500, detail="Failed to create class.")
    return _row_to_class_out(created, None)


@router.put("/jhr/classes/{class_id}", response_model=JhrClassOut)
def update_jhr_class(class_id: int, req: JhrClassUpdateIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    _ensure_jhr_schema(db)
    _ensure_parking_daily_activity_schema(db)
    creator = _require_creator(db, req.username.strip(), req.password)
    row = (
        db.execute(
            text("SELECT * FROM jhr_classes WHERE id = :id FOR UPDATE"),
            {"id": class_id},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Class not found.")
    if int(row.get("creator_user_id") or 0) != int(creator["id"]):
        raise HTTPException(status_code=403, detail="Only class creator can update.")

    next_title = req.title.strip() if req.title is not None else row["title"]
    next_desc = req.description.strip() if req.description is not None else row.get("description")
    next_price = req.price if req.price is not None else row.get("price")
    next_capacity = int(req.capacity) if req.capacity is not None else int(row.get("capacity") or 0)
    next_start = req.start_date if req.start_date is not None else row["start_date"]
    next_end = req.end_date if req.end_date is not None else row["end_date"]
    next_status = req.status if req.status is not None else row["status"]
    current_count = int(row.get("current_count") or 0)

    if next_end <= next_start:
        raise HTTPException(status_code=400, detail="end_date must be after start_date.")
    if next_capacity < current_count:
        raise HTTPException(status_code=400, detail="capacity cannot be less than current_count.")

    updated = (
        db.execute(
            text(
                """
                UPDATE jhr_classes
                SET title = :t,
                    description = :d,
                    price = :p,
                    capacity = :c,
                    start_date = :sd,
                    end_date = :ed,
                    status = :st,
                    updated_at = now()
                WHERE id = :id
                RETURNING *
                """
            ),
            {
                "id": class_id,
                "t": next_title,
                "d": next_desc,
                "p": next_price,
                "c": next_capacity,
                "sd": next_start,
                "ed": next_end,
                "st": next_status,
            },
        )
        .mappings()
        .first()
    )
    _record_daily_activity(db, int(creator["id"]))
    db.commit()
    return _row_to_class_out(updated, None)


@router.post("/jhr/enrollments", response_model=JhrEnrollmentOut)
def create_jhr_enrollment(req: JhrEnrollmentReqIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    _ensure_jhr_schema(db)
    _ensure_parking_daily_activity_schema(db)
    student = _require_student(db, req.username.strip(), req.password)

    class_row = (
        db.execute(text("SELECT * FROM jhr_classes WHERE id = :id LIMIT 1"), {"id": req.class_id})
        .mappings()
        .first()
    )
    if not class_row:
        raise HTTPException(status_code=404, detail="Class not found.")
    if str(class_row["status"]) != "OPEN":
        raise HTTPException(status_code=400, detail="Class is not open for enrollment.")

    exists = (
        db.execute(
            text(
                """
                SELECT *
                FROM jhr_enrollments
                WHERE user_id = :uid AND class_id = :cid
                LIMIT 1
                """
            ),
            {"uid": int(student["id"]), "cid": req.class_id},
        )
        .mappings()
        .first()
    )
    if exists:
        if str(exists["status"]) == "CANCELLED":
            updated = (
                db.execute(
                    text(
                        """
                        UPDATE jhr_enrollments
                        SET status = 'PENDING', applied_at = now(), confirmed_at = NULL, canceled_at = NULL
                        WHERE id = :id
                        RETURNING *
                        """
                    ),
                    {"id": int(exists["id"])},
                )
                .mappings()
                .first()
            )
            _record_daily_activity(db, int(student["id"]))
            db.commit()
            return {
                "id": int(updated["id"]),
                "user_id": int(updated["user_id"]),
                "class_id": int(updated["class_id"]),
                "status": str(updated["status"]),
                "applied_at": updated["applied_at"],
                "confirmed_at": updated["confirmed_at"],
                "canceled_at": updated["canceled_at"],
                "class_title": str(class_row["title"]),
            }
        raise HTTPException(status_code=409, detail="Already enrolled.")

    created = (
        db.execute(
            text(
                """
                INSERT INTO jhr_enrollments (user_id, class_id, status)
                VALUES (:uid, :cid, 'PENDING')
                RETURNING *
                """
            ),
            {"uid": int(student["id"]), "cid": req.class_id},
        )
        .mappings()
        .first()
    )
    _record_daily_activity(db, int(student["id"]))
    db.commit()
    return {
        "id": int(created["id"]),
        "user_id": int(created["user_id"]),
        "class_id": int(created["class_id"]),
        "status": str(created["status"]),
        "applied_at": created["applied_at"],
        "confirmed_at": created["confirmed_at"],
        "canceled_at": created["canceled_at"],
        "class_title": str(class_row["title"]),
    }


@router.put("/jhr/enrollments/confirm", response_model=JhrEnrollmentOut)
def confirm_jhr_enrollment(req: JhrEnrollmentActionIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    _ensure_jhr_schema(db)
    _ensure_parking_daily_activity_schema(db)
    student = _require_student(db, req.username.strip(), req.password)

    enr = (
        db.execute(
            text("SELECT * FROM jhr_enrollments WHERE id = :id FOR UPDATE"),
            {"id": req.enrollment_id},
        )
        .mappings()
        .first()
    )
    if not enr:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    if int(enr["user_id"]) != int(student["id"]):
        raise HTTPException(status_code=403, detail="Not your enrollment.")
    if str(enr["status"]) != "PENDING":
        raise HTTPException(status_code=400, detail="Only PENDING can be confirmed.")

    class_row = (
        db.execute(
            text("SELECT * FROM jhr_classes WHERE id = :id FOR UPDATE"),
            {"id": int(enr["class_id"])},
        )
        .mappings()
        .first()
    )
    if not class_row:
        raise HTTPException(status_code=404, detail="Class not found.")
    if str(class_row["status"]) != "OPEN":
        raise HTTPException(status_code=400, detail="Class is not open for confirmation.")
    if int(class_row["current_count"] or 0) >= int(class_row["capacity"] or 0):
        raise HTTPException(status_code=409, detail="Class capacity exceeded.")

    db.execute(
        text(
            """
            UPDATE jhr_classes
            SET current_count = current_count + 1,
                updated_at = now()
            WHERE id = :id
            """
        ),
        {"id": int(class_row["id"])},
    )
    updated = (
        db.execute(
            text(
                """
                UPDATE jhr_enrollments
                SET status = 'CONFIRMED', confirmed_at = now(), canceled_at = NULL
                WHERE id = :id
                RETURNING *
                """
            ),
            {"id": int(enr["id"])},
        )
        .mappings()
        .first()
    )
    _record_daily_activity(db, int(student["id"]))
    db.commit()
    return {
        "id": int(updated["id"]),
        "user_id": int(updated["user_id"]),
        "class_id": int(updated["class_id"]),
        "status": str(updated["status"]),
        "applied_at": updated["applied_at"],
        "confirmed_at": updated["confirmed_at"],
        "canceled_at": updated["canceled_at"],
        "class_title": str(class_row["title"]),
    }


@router.put("/jhr/enrollments/cancel", response_model=JhrEnrollmentOut)
def cancel_jhr_enrollment(req: JhrEnrollmentActionIn, db: Session = Depends(get_db)):
    _ensure_parking_users_schema(db)
    _ensure_jhr_schema(db)
    _ensure_parking_daily_activity_schema(db)
    student = _require_student(db, req.username.strip(), req.password)

    enr = (
        db.execute(
            text("SELECT * FROM jhr_enrollments WHERE id = :id FOR UPDATE"),
            {"id": req.enrollment_id},
        )
        .mappings()
        .first()
    )
    if not enr:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    if int(enr["user_id"]) != int(student["id"]):
        raise HTTPException(status_code=403, detail="Not your enrollment.")
    if str(enr["status"]) == "CANCELLED":
        raise HTTPException(status_code=400, detail="Already cancelled.")
    if str(enr["status"]) == "CONFIRMED" and enr.get("confirmed_at"):
        confirmed_at = enr["confirmed_at"]
        now_ref = datetime.now(confirmed_at.tzinfo) if getattr(confirmed_at, "tzinfo", None) else datetime.utcnow()
        if now_ref > (confirmed_at + timedelta(days=7)):
            raise HTTPException(status_code=400, detail="Cancellation period exceeded (7 days).")

    class_row = (
        db.execute(
            text("SELECT * FROM jhr_classes WHERE id = :id FOR UPDATE"),
            {"id": int(enr["class_id"])},
        )
        .mappings()
        .first()
    )
    if not class_row:
        raise HTTPException(status_code=404, detail="Class not found.")

    if str(enr["status"]) == "CONFIRMED":
        db.execute(
            text(
                """
                UPDATE jhr_classes
                SET current_count = CASE WHEN current_count > 0 THEN current_count - 1 ELSE 0 END,
                    updated_at = now()
                WHERE id = :id
                """
            ),
            {"id": int(class_row["id"])},
        )

    updated = (
        db.execute(
            text(
                """
                UPDATE jhr_enrollments
                SET status = 'CANCELLED', canceled_at = now()
                WHERE id = :id
                RETURNING *
                """
            ),
            {"id": int(enr["id"])},
        )
        .mappings()
        .first()
    )
    _record_daily_activity(db, int(student["id"]))
    db.commit()
    return {
        "id": int(updated["id"]),
        "user_id": int(updated["user_id"]),
        "class_id": int(updated["class_id"]),
        "status": str(updated["status"]),
        "applied_at": updated["applied_at"],
        "confirmed_at": updated["confirmed_at"],
        "canceled_at": updated["canceled_at"],
        "class_title": str(class_row["title"]),
    }


@router.get("/jhr/enrollments/me", response_model=list[JhrEnrollmentOut])
def list_my_enrollments(
    username: str = Query(..., min_length=1, max_length=30),
    password: str = Query(..., min_length=2, max_length=200),
    db: Session = Depends(get_db),
):
    _ensure_parking_users_schema(db)
    _ensure_jhr_schema(db)
    user = _require_parking_user(db, username.strip(), password)
    rows = (
        db.execute(
            text(
                """
                SELECT e.*, c.title AS class_title
                FROM jhr_enrollments e
                JOIN jhr_classes c ON c.id = e.class_id
                WHERE e.user_id = :uid
                ORDER BY e.applied_at DESC, e.id DESC
                """
            ),
            {"uid": int(user["id"])},
        )
        .mappings()
        .all()
    )
    return [
        {
            "id": int(r["id"]),
            "user_id": int(r["user_id"]),
            "class_id": int(r["class_id"]),
            "status": str(r["status"]),
            "applied_at": r["applied_at"],
            "confirmed_at": r.get("confirmed_at"),
            "canceled_at": r.get("canceled_at"),
            "class_title": r.get("class_title"),
        }
        for r in rows
    ]


@router.get("/jhr/classes/{class_id}/students", response_model=list[JhrEnrollmentOut])
def list_class_students(
    class_id: int,
    username: str = Query(..., min_length=1, max_length=30),
    password: str = Query(..., min_length=2, max_length=200),
    db: Session = Depends(get_db),
):
    _ensure_parking_users_schema(db)
    _ensure_jhr_schema(db)
    creator = _require_creator(db, username.strip(), password)
    class_row = (
        db.execute(text("SELECT * FROM jhr_classes WHERE id = :id LIMIT 1"), {"id": class_id})
        .mappings()
        .first()
    )
    if not class_row:
        raise HTTPException(status_code=404, detail="Class not found.")
    if int(class_row.get("creator_user_id") or 0) != int(creator["id"]):
        raise HTTPException(status_code=403, detail="Only class creator can view students.")

    rows = (
        db.execute(
            text(
                """
                SELECT e.*
                FROM jhr_enrollments e
                WHERE e.class_id = :cid
                ORDER BY e.applied_at DESC, e.id DESC
                """
            ),
            {"cid": class_id},
        )
        .mappings()
        .all()
    )
    return [
        {
            "id": int(r["id"]),
            "user_id": int(r["user_id"]),
            "class_id": int(r["class_id"]),
            "status": str(r["status"]),
            "applied_at": r["applied_at"],
            "confirmed_at": r.get("confirmed_at"),
            "canceled_at": r.get("canceled_at"),
            "class_title": str(class_row["title"]),
        }
        for r in rows
    ]
