from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ResearchQuestionCreate(BaseModel):
    title: str | None = Field(default=None, max_length=200)
    query: str = Field(..., min_length=3, max_length=8000)
    is_active: bool = True


class ResearchQuestionPatch(BaseModel):
    title: str | None = Field(default=None, max_length=200)
    query: str | None = Field(default=None, min_length=3, max_length=8000)
    is_active: bool | None = None


class ResearchQuestionOut(BaseModel):
    id: int
    title: str | None
    query: str
    is_active: bool
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


class ResearchReportRunOut(ResearchReportOut):
    error: str | None = None


class ResearchRunOut(BaseModel):
    reports: list[ResearchReportRunOut]

