from __future__ import annotations

import os
import base64
import hashlib
import secrets
from datetime import date
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from deps import get_db
from models import ResearchQuestion, ResearchReport, ResearchUser

from .schemas import (
    ResearchQuestionCreate,
    ResearchQuestionOut,
    ResearchQuestionPatch,
    ResearchReportDetailOut,
    ResearchReportOut,
    ResearchRunIn,
    ResearchRunOut,
    ResearchUserLoginIn,
    ResearchUserLoginOut,
    ResearchUserSignupIn,
    ResearchUserSignupOut,
)
from .service import run_research_for_question


router = APIRouter(prefix="/research", tags=["research"])

_PBKDF2_ITERS = 210_000


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERS)
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ITERS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        algo, iters_s, salt_b64, dk_b64 = (password_hash or "").split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(dk_b64.encode("ascii"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return secrets.compare_digest(dk, expected)
    except Exception:
        return False


@router.post("/users/signup", response_model=ResearchUserSignupOut)
def signup(payload: ResearchUserSignupIn, db: Session = Depends(get_db)):
    u = ResearchUser(password_hash=_hash_password(payload.password))
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@router.post("/users/login", response_model=ResearchUserLoginOut)
def login(payload: ResearchUserLoginIn, db: Session = Depends(get_db)):
    u = db.query(ResearchUser).filter(ResearchUser.id == payload.id).first()
    if not u or not _verify_password(payload.password, u.password_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {"ok": True, "id": int(u.id), "end_date": u.end_date}


@router.post("/questions", response_model=ResearchQuestionOut)
def create_question(payload: ResearchQuestionCreate, db: Session = Depends(get_db)):
    q = ResearchQuestion(title=payload.title, query=payload.query, is_active=payload.is_active)
    db.add(q)
    db.commit()
    db.refresh(q)
    return q


@router.get("/questions", response_model=list[ResearchQuestionOut])
def list_questions(
    active_only: bool = Query(False),
    db: Session = Depends(get_db),
):
    q = db.query(ResearchQuestion).order_by(ResearchQuestion.created_at.desc())
    if active_only:
        q = q.filter(ResearchQuestion.is_active == True)  # noqa: E712
    return q.all()


@router.get("/questions/{question_id}", response_model=ResearchQuestionOut)
def get_question(question_id: int, db: Session = Depends(get_db)):
    q = db.query(ResearchQuestion).filter(ResearchQuestion.id == question_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="question not found")
    return q


@router.patch("/questions/{question_id}", response_model=ResearchQuestionOut)
def patch_question(question_id: int, payload: ResearchQuestionPatch, db: Session = Depends(get_db)):
    q = db.query(ResearchQuestion).filter(ResearchQuestion.id == question_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="question not found")
    fields = getattr(payload, "model_fields_set", set())
    if "title" in fields:
        q.title = payload.title
    if "query" in fields:
        if payload.query is None:
            raise HTTPException(status_code=422, detail="query cannot be null")
        q.query = payload.query
    if "is_active" in fields:
        if payload.is_active is None:
            raise HTTPException(status_code=422, detail="is_active cannot be null")
        q.is_active = bool(payload.is_active)
    db.add(q)
    db.commit()
    db.refresh(q)
    return q


@router.delete("/questions/{question_id}")
def delete_question(question_id: int, db: Session = Depends(get_db)):
    q = db.query(ResearchQuestion).filter(ResearchQuestion.id == question_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="question not found")

    deleted_reports = (
        db.query(ResearchReport)
        .filter(ResearchReport.question_id == question_id)
        .delete(synchronize_session=False)
    )
    db.delete(q)
    db.commit()
    return {"deleted": True, "question_id": question_id, "deleted_reports": int(deleted_reports or 0)}


@router.post("/run", response_model=ResearchRunOut)
def run_now(payload: ResearchRunIn, db: Session = Depends(get_db)):
    reports: list[ResearchReport] = []
    if payload.question_id is not None:
        q = db.query(ResearchQuestion).filter(ResearchQuestion.id == payload.question_id).first()
        if not q:
            raise HTTPException(status_code=404, detail="question not found")
        reports.append(run_research_for_question(db=db, question=q, force=payload.force))
    else:
        qs = (
            db.query(ResearchQuestion)
            .filter(ResearchQuestion.is_active == True)  # noqa: E712
            .order_by(ResearchQuestion.created_at.desc())
            .all()
        )
        for q in qs:
            try:
                reports.append(run_research_for_question(db=db, question=q, force=payload.force))
            except Exception:
                continue
    return {"reports": reports}


@router.get("/reports", response_model=list[ResearchReportOut])
def list_reports(
    question_id: int | None = Query(default=None),
    run_date: date | None = Query(default=None),
    db: Session = Depends(get_db),
):
    q = db.query(ResearchReport).order_by(ResearchReport.created_at.desc())
    if question_id is not None:
        q = q.filter(ResearchReport.question_id == question_id)
    if run_date is not None:
        q = q.filter(ResearchReport.run_date == run_date)
    return q.all()


@router.get("/reports/{report_id}", response_model=ResearchReportDetailOut)
def get_report(report_id: int, db: Session = Depends(get_db)):
    r = db.query(ResearchReport).filter(ResearchReport.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="report not found")
    return r


@router.get("/reports/latest", response_model=ResearchReportOut)
def latest_report(question_id: int = Query(...), db: Session = Depends(get_db)):
    r = (
        db.query(ResearchReport)
        .filter(ResearchReport.question_id == question_id, ResearchReport.status == "completed")
        .order_by(ResearchReport.run_date.desc(), ResearchReport.created_at.desc())
        .first()
    )
    if not r:
        raise HTTPException(status_code=404, detail="latest report not found")
    return r


@router.get("/reports/{report_id}/pdf")
def download_pdf(report_id: int, db: Session = Depends(get_db)):
    r = db.query(ResearchReport).filter(ResearchReport.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="report not found")
    if not r.pdf_path:
        raise HTTPException(status_code=404, detail="pdf not available")
    path = Path(r.pdf_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="pdf file missing on server")

    # 운영에서 reverse-proxy로 static 서빙할 수도 있어, 다운로드는 그대로 FileResponse로 제공합니다.
    return FileResponse(
        str(path),
        media_type="application/pdf",
        filename=path.name,
    )

