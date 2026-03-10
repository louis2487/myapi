from __future__ import annotations

import os
import base64
import hashlib
import secrets
import calendar
from datetime import date, datetime, timedelta, timezone
try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Header
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

_ALLOWED_CATEGORIES = {
    "business",
    "shopping",
    "investment",
    "art",
    "cooking",
    "travel",
    "self_development",
    "career",
    "content",
    "relationships",
    "lifestyle",
}


def _normalize_category(v: str | None) -> str:
    s = (v or "").strip()
    if not s:
        return "business"
    if s not in _ALLOWED_CATEGORIES:
        raise HTTPException(status_code=422, detail=f"invalid category: {s}")
    return s


def _kst_tzinfo():
    if ZoneInfo:
        try:
            return ZoneInfo("Asia/Seoul")
        except Exception:
            pass
    return timezone(timedelta(hours=9))


def _now_kst_naive() -> datetime:
    # DB의 research_users.end_date는 timezone 없는 TIMESTAMP로 가정(KST 기준으로 운용).
    # 비교를 위해 "naive datetime"으로 맞춥니다.
    return datetime.now(_kst_tzinfo()).replace(tzinfo=None)


def _add_months(dt: datetime, months: int) -> datetime:
    """
    외부 라이브러리 없이 'n개월 뒤'를 계산합니다.
    (예: 1/31 + 1개월 => 2/28 또는 2/29로 clamp)
    """
    if months == 0:
        return dt
    y = dt.year
    m0 = dt.month - 1
    total = m0 + months
    y += total // 12
    m = (total % 12) + 1
    last_day = calendar.monthrange(y, m)[1]
    d = min(dt.day, last_day)
    return dt.replace(year=y, month=m, day=d)


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


def get_research_user_id(
    db: Session = Depends(get_db),
    x_research_username: str | None = Header(default=None, alias="X-Research-Username"),
    x_research_password: str | None = Header(default=None, alias="X-Research-Password"),
    x_research_user_id: str | None = Header(default=None, alias="X-Research-User-Id"),  # legacy
) -> int:
    """
    신규: username 헤더 기반 인증
    레거시: user id 헤더도 유지(기존 앱 호환)
    """
    if x_research_username:
        username = (x_research_username or "").strip()
        if not username:
            raise HTTPException(status_code=422, detail="invalid username")
        if not x_research_password:
            raise HTTPException(status_code=401, detail="missing password")
        u = db.query(ResearchUser).filter(ResearchUser.username == username).first()
        if not u or not _verify_password(x_research_password, u.password_hash):
            raise HTTPException(status_code=401, detail="invalid credentials")
        return int(u.id)

    if not x_research_user_id:
        raise HTTPException(status_code=401, detail="missing user id")
    try:
        uid = int(x_research_user_id)
    except Exception:
        raise HTTPException(status_code=422, detail="invalid user id")
    if uid <= 0:
        raise HTTPException(status_code=422, detail="invalid user id")
    return uid


@router.post("/users/signup", response_model=ResearchUserSignupOut)
def signup(payload: ResearchUserSignupIn, db: Session = Depends(get_db)):
    now = _now_kst_naive()
    end_date = _add_months(now, 1)
    username = (payload.username or "").strip() or None
    if username:
        exists = db.query(ResearchUser.id).filter(ResearchUser.username == username).first()
        if exists:
            raise HTTPException(status_code=409, detail="username already exists")
    u = ResearchUser(username=username, password_hash=_hash_password(payload.password), end_date=end_date)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@router.post("/users/login", response_model=ResearchUserLoginOut)
def login(payload: ResearchUserLoginIn, db: Session = Depends(get_db)):
    if payload.username:
        u = db.query(ResearchUser).filter(ResearchUser.username == payload.username).first()
    else:
        u = db.query(ResearchUser).filter(ResearchUser.id == payload.id).first()
    if not u or not _verify_password(payload.password, u.password_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")
    end_date = u.end_date
    expired = bool(end_date is not None and _now_kst_naive() > end_date)
    return {"ok": True, "id": int(u.id), "username": u.username, "end_date": end_date, "expired": expired}


@router.post("/questions", response_model=ResearchQuestionOut)
def create_question(
    payload: ResearchQuestionCreate,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    # 유저당 활성 질문 1개 제약 강제
    if payload.is_active:
        (
            db.query(ResearchQuestion)
            .filter(ResearchQuestion.user_id == user_id, ResearchQuestion.is_active == True)  # noqa: E712
            .update({ResearchQuestion.is_active: False}, synchronize_session=False)
        )
    q = ResearchQuestion(
        user_id=user_id,
        title=payload.title,
        query=payload.query,
        is_active=payload.is_active,
        category=_normalize_category(payload.category),
    )
    db.add(q)
    db.commit()
    db.refresh(q)
    return q


@router.get("/questions", response_model=list[ResearchQuestionOut])
def list_questions(
    active_only: bool = Query(False),
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    q = (
        db.query(ResearchQuestion)
        .filter(ResearchQuestion.user_id == user_id)
        .order_by(ResearchQuestion.created_at.desc())
    )
    if active_only:
        q = q.filter(ResearchQuestion.is_active == True)  # noqa: E712
    return q.all()


@router.get("/questions/{question_id}", response_model=ResearchQuestionOut)
def get_question(
    question_id: int,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    q = (
        db.query(ResearchQuestion)
        .filter(ResearchQuestion.id == question_id, ResearchQuestion.user_id == user_id)
        .first()
    )
    if not q:
        raise HTTPException(status_code=404, detail="question not found")
    return q


@router.patch("/questions/{question_id}", response_model=ResearchQuestionOut)
def patch_question(
    question_id: int,
    payload: ResearchQuestionPatch,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    q = (
        db.query(ResearchQuestion)
        .filter(ResearchQuestion.id == question_id, ResearchQuestion.user_id == user_id)
        .first()
    )
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
        next_active = bool(payload.is_active)
        if next_active:
            (
                db.query(ResearchQuestion)
                .filter(
                    ResearchQuestion.user_id == user_id,
                    ResearchQuestion.id != q.id,
                    ResearchQuestion.is_active == True,  # noqa: E712
                )
                .update({ResearchQuestion.is_active: False}, synchronize_session=False)
            )
        q.is_active = next_active
    if "category" in fields:
        q.category = _normalize_category(payload.category)
    db.add(q)
    db.commit()
    db.refresh(q)
    return q


@router.delete("/questions/{question_id}")
def delete_question(
    question_id: int,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    q = (
        db.query(ResearchQuestion)
        .filter(ResearchQuestion.id == question_id, ResearchQuestion.user_id == user_id)
        .first()
    )
    if not q:
        raise HTTPException(status_code=404, detail="question not found")

    # 질문 삭제가 "리포트/PDF 삭제"로 이어지지 않도록,
    # 리포트 레코드는 보존합니다. (리서치 목록에서 PDF 접근 유지)
    deleted_reports = 0
    db.delete(q)
    db.commit()
    return {"deleted": True, "question_id": question_id, "deleted_reports": int(deleted_reports or 0)}


@router.post("/run", response_model=ResearchRunOut)
def run_now(
    payload: ResearchRunIn,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    reports: list[ResearchReport] = []
    if payload.question_id is None:
        raise HTTPException(status_code=422, detail="question_id is required")
    q = (
        db.query(ResearchQuestion)
        .filter(ResearchQuestion.id == payload.question_id, ResearchQuestion.user_id == user_id)
        .first()
    )
    if not q:
        raise HTTPException(status_code=404, detail="question not found")
    reports.append(run_research_for_question(db=db, question=q, user_id=user_id, force=payload.force))
    return {"reports": reports}


@router.get("/reports", response_model=list[ResearchReportOut])
def list_reports(
    question_id: int | None = Query(default=None),
    run_date: date | None = Query(default=None),
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    q = (
        db.query(ResearchReport)
        .filter(ResearchReport.user_id == user_id)
        .order_by(ResearchReport.run_date.desc(), ResearchReport.created_at.desc())
    )
    if question_id is not None:
        q = q.filter(ResearchReport.question_id == question_id)
    if run_date is not None:
        q = q.filter(ResearchReport.run_date == run_date)
    return q.all()


@router.get("/reports/{report_id}", response_model=ResearchReportDetailOut)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    r = (
        db.query(ResearchReport)
        .filter(ResearchReport.id == report_id, ResearchReport.user_id == user_id)
        .first()
    )
    if not r:
        raise HTTPException(status_code=404, detail="report not found")
    return r


@router.get("/reports/latest", response_model=ResearchReportOut)
def latest_report(
    question_id: int = Query(...),
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    r = (
        db.query(ResearchReport)
        .filter(
            ResearchReport.question_id == question_id,
            ResearchReport.user_id == user_id,
            ResearchReport.status == "completed",
        )
        .order_by(ResearchReport.run_date.desc(), ResearchReport.created_at.desc())
        .first()
    )
    if not r:
        raise HTTPException(status_code=404, detail="latest report not found")
    return r


@router.get("/reports/{report_id}/pdf")
def download_pdf(
    report_id: int,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_research_user_id),
):
    r = (
        db.query(ResearchReport)
        .filter(ResearchReport.id == report_id, ResearchReport.user_id == user_id)
        .first()
    )
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

