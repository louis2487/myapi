from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, Field


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


class JhrClassStatusIn(JhrRoleAuthIn):
    status: Literal["OPEN", "CLOSED"]


class JhrClassStatusChangeIn(JhrClassStatusIn):
    class_id: int = Field(..., ge=1)


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


class JhrClassListOut(BaseModel):
    items: list[JhrClassOut]
    page: int
    limit: int
    total_count: int
    total_pages: int


class JhrEnrollmentReqIn(JhrRoleAuthIn):
    class_id: int = Field(..., ge=1)


class JhrEnrollmentActionIn(JhrRoleAuthIn):
    enrollment_id: int = Field(..., ge=1)


class JhrEnrollmentOut(BaseModel):
    id: int
    user_id: int
    username: str | None = None
    class_id: int
    status: Literal["PENDING", "CONFIRMED", "CANCELLED"]
    applied_at: datetime
    confirmed_at: datetime | None = None
    canceled_at: datetime | None = None
    class_title: str | None = None
