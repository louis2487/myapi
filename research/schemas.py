from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ResearchUserSignupIn(BaseModel):
    username: str | None = Field(default=None, min_length=2, max_length=50)
    password: str = Field(..., min_length=4, max_length=200)


class ResearchUserSignupOut(BaseModel):
    id: int
    username: str | None = None
    end_date: datetime | None = None
    signup_date: datetime

    model_config = ConfigDict(from_attributes=True)


class ResearchUserLoginIn(BaseModel):
    # username 기반 로그인으로 전환(레거시 id 로그인도 허용)
    username: str | None = Field(default=None, min_length=2, max_length=50)
    id: int | None = Field(default=None, ge=1)
    password: str = Field(..., min_length=1, max_length=200)

    @model_validator(mode="after")
    def _require_username_or_id(self):
        if not (self.username or self.id):
            raise ValueError("username or id is required")
        return self


class ResearchUserLoginOut(BaseModel):
    ok: bool = True
    id: int
    username: str | None = None
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
    title: str | None = None
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

