from __future__ import annotations

import os
from datetime import date
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from deps import get_db
from models import ResearchQuestion, ResearchReport

from .schemas import (
    ResearchQuestionCreate,
    ResearchQuestionOut,
    ResearchQuestionPatch,
    ResearchReportDetailOut,
    ResearchReportOut,
    ResearchRunIn,
    ResearchRunOut,
)
from .service import run_research_for_question


router = APIRouter(prefix="/research", tags=["research"])


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


@router.patch("/questions/{question_id}", response_model=ResearchQuestionOut)
def patch_question(question_id: int, payload: ResearchQuestionPatch, db: Session = Depends(get_db)):
    q = db.query(ResearchQuestion).filter(ResearchQuestion.id == question_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="question not found")
    if payload.title is not None:
        q.title = payload.title
    if payload.query is not None:
        q.query = payload.query
    if payload.is_active is not None:
        q.is_active = bool(payload.is_active)
    db.add(q)
    db.commit()
    db.refresh(q)
    return q


@router.post("/run", response_model=ResearchRunOut)
def run_now(payload: ResearchRunIn, db: Session = Depends(get_db)):
    reports: list[ResearchReport] = []
    if payload.question_id is not None:
        q = db.query(ResearchQuestion).filter(ResearchQuestion.id == payload.question_id).first()
        if not q:
            raise HTTPException(status_code=404, detail="question not found")
        # 단일 실행은 실패해도 500으로 죽지 않고, failed 리포트를 반환합니다.
        reports.append(
            run_research_for_question(db=db, question=q, force=payload.force, raise_on_error=False)
        )
    else:
        qs = (
            db.query(ResearchQuestion)
            .filter(ResearchQuestion.is_active == True)  # noqa: E712
            .order_by(ResearchQuestion.created_at.desc())
            .all()
        )
        for q in qs:
            try:
                reports.append(
                    run_research_for_question(
                        db=db,
                        question=q,
                        force=payload.force,
                        raise_on_error=False,
                    )
                )
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

