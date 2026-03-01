from __future__ import annotations

import json
import os
from datetime import date, datetime
try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.orm import Session

from database import SessionLocal
from models import ResearchQuestion, ResearchReport

from .pdf import generate_research_pdf


OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"


def _seoul_today() -> date:
    tz = ZoneInfo("Asia/Seoul") if ZoneInfo else None
    return (datetime.now(tz) if tz else datetime.now()).date()


def _openai_key() -> str:
    key = (os.getenv("GPT_API_key") or "").strip()
    if not key:
        raise RuntimeError("환경변수 GPT_API_key 가 설정되지 않았습니다.")
    return key


def _openai_model() -> str:
    return (os.getenv("OPENAI_MODEL") or "gpt-4.1-mini").strip()


def _extract_json(text: str) -> dict[str, Any]:
    t = (text or "").strip()
    if not t:
        raise ValueError("OpenAI 응답이 비어있습니다.")
    try:
        v = json.loads(t)
        if isinstance(v, dict):
            return v
    except Exception:
        pass

    # 가끔 앞/뒤에 설명이 붙는 경우가 있어, 가장 바깥 {}를 다시 파싱 시도
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        v = json.loads(t[start : end + 1])
        if isinstance(v, dict):
            return v
    raise ValueError("JSON 파싱 실패")


def generate_sections_via_openai(*, question_query: str) -> dict[str, Any]:
    key = _openai_key()
    model = _openai_model()

    schema_hint = {
        "executive_summary": "string",
        "market_situation": "string",
        "problems": "string",
        "opportunities": "string",
        "competitive_analysis": "string",
        "strategy_proposals": "string",
        "risk_assessment": "string",
        "smartgauge_insight": "string",
        "conclusion": "string",
        "sources": [{"title": "string", "url": "string"}],
    }

    system = (
        "당신은 시장/산업 리서치 애널리스트입니다. "
        "반드시 '오직 JSON'만 출력하세요(마크다운, 코드펜스, 설명 금지). "
        "모든 본문은 한국어로 작성하되, 키 이름은 고정된 영어 키를 사용합니다."
    )
    user = (
        "아래 질문에 대한 일일 리서치 리포트를 작성하세요.\n\n"
        f"질문: {question_query}\n\n"
        "요구사항:\n"
        "- 분량: PDF로 약 10페이지가 나오도록 충분히 상세하게(섹션별 6~12개 문장/불릿 혼합)\n"
        "- 각 섹션은 서로 중복을 최소화\n"
        "- 출처는 최소 6개 이상, 가능한 공식/권위있는 자료 위주\n\n"
        "반환 JSON 스키마(예시 타입):\n"
        f"{json.dumps(schema_hint, ensure_ascii=False)}"
    )

    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }

    with httpx.Client(timeout=120) as client:
        r = client.post(
            OPENAI_API_URL,
            headers={"Authorization": f"Bearer {key}"},
            json=payload,
        )
        r.raise_for_status()
        data = r.json()

    content = (
        (((data.get("choices") or [{}])[0].get("message") or {}).get("content")) or ""
    )
    sections = _extract_json(content)

    # 최소 키 보정
    required = [
        "executive_summary",
        "market_situation",
        "problems",
        "opportunities",
        "competitive_analysis",
        "strategy_proposals",
        "risk_assessment",
        "smartgauge_insight",
        "conclusion",
        "sources",
    ]
    for k in required:
        if k not in sections:
            raise ValueError(f"OpenAI 응답에 필수 키가 없습니다: {k}")
    if not isinstance(sections.get("sources"), list):
        sections["sources"] = []
    return sections


def _pdf_output_path(*, question_id: int, run_date: date) -> Path:
    base = Path(__file__).resolve().parent
    return base / "generated" / run_date.isoformat() / f"report_q{question_id}_{run_date.isoformat()}.pdf"


def run_research_for_question(
    *,
    db: Session,
    question: ResearchQuestion,
    run_date: date | None = None,
    force: bool = False,
) -> ResearchReport:
    run_date = run_date or _seoul_today()

    existing = (
        db.query(ResearchReport)
        .filter(ResearchReport.question_id == question.id, ResearchReport.run_date == run_date)
        .first()
    )
    if existing and (existing.status == "completed") and (not force):
        return existing

    report = existing or ResearchReport(question_id=question.id, run_date=run_date)
    report.status = "running"
    report.error = None
    db.add(report)
    db.commit()
    db.refresh(report)

    try:
        sections = generate_sections_via_openai(question_query=question.query)
        out_path = _pdf_output_path(question_id=int(question.id), run_date=run_date)
        pdf_path = generate_research_pdf(
            output_path=out_path,
            run_date=run_date,
            question_title=question.title,
            question_query=question.query,
            sections=sections,
        )
        report.sections = sections
        report.pdf_path = str(pdf_path)
        report.status = "completed"
        db.add(report)
        db.commit()
        db.refresh(report)
        return report
    except Exception as e:
        report.status = "failed"
        report.error = str(e)
        db.add(report)
        db.commit()
        db.refresh(report)
        raise


def run_daily_reports(*, force: bool = False) -> list[int]:
    """
    스케줄러에서 호출하는 엔트리포인트.
    성공적으로 생성/갱신한 report id 목록을 반환합니다.
    """
    db = SessionLocal()
    created: list[int] = []
    try:
        qs = (
            db.query(ResearchQuestion)
            .filter(ResearchQuestion.is_active == True)  # noqa: E712
            .order_by(ResearchQuestion.created_at.desc())
            .all()
        )
        today = _seoul_today()
        for q in qs:
            try:
                r = run_research_for_question(db=db, question=q, run_date=today, force=force)
                created.append(int(r.id))
            except Exception:
                # 개별 실패는 전체 스케줄을 막지 않음
                continue
        return created
    finally:
        db.close()

