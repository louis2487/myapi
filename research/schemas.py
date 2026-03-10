from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ResearchUserSignupIn(BaseModel):
    password: str = Field(..., min_length=4, max_length=200)


class ResearchUserSignupOut(BaseModel):
    id: int
    end_date: datetime | None = None
    signup_date: datetime

    model_config = ConfigDict(from_attributes=True)


class ResearchUserLoginIn(BaseModel):
    id: int = Field(..., ge=1)
    password: str = Field(..., min_length=1, max_length=200)


class ResearchUserLoginOut(BaseModel):
    ok: bool = True
    id: int
    end_date: datetime | None = None
    expired: bool = False


class ResearchQuestionCreate(BaseModel):
    title: str | None = Field(default=None, max_length=200)
    query: str = Field(..., min_length=3, max_length=8000)
    is_active: bool = True
    category: str = Field(default="business", min_length=1, max_length=50)


class ResearchQuestionPatch(BaseModel):
    title: str | None = Field(default=None, max_length=200)
    query: str | None = Field(default=None, min_length=3, max_length=8000)
    is_active: bool | None = None
    category: str | None = Field(default=None, min_length=1, max_length=50)


class ResearchQuestionOut(BaseModel):
    id: int
    title: str | None
    query: str
    is_active: bool
    category: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ResearchReportOut(BaseModel):
    id: int
    question_id: int
    run_date: date
    status: str
    created_at: datetime
    pdf_path: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ResearchReportDetailOut(ResearchReportOut):
    sections: dict[str, Any] | None = None
    error: str | None = None


class ResearchRunIn(BaseModel):
    question_id: int | None = None
    force: bool = False


class ResearchRunOut(BaseModel):
    reports: list[ResearchReportOut]

