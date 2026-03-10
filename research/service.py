from __future__ import annotations

import json
import os
from datetime import date, datetime, timedelta, timezone
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

_CATEGORY_SPECS: dict[str, dict[str, Any]] = {
    "business": {
        "label_ko": "사업",
        "layer1_keys": [
            "executive_summary",
            "market_situation",
            "problems",
            "opportunities",
            "competitive_analysis",
            "strategy_proposals",
            "risk_assessment",
            "insight",
            "optimal_actions",
            "metrics",
            "conclusion",
            "roadmap",
        ],
    },
    "shopping": {
        "label_ko": "쇼핑",
        "layer1_keys": [
            "executive_summary",
            "needs_analysis",
            "budget_situation",
            "comparison_targets",
            "option_analysis",
            "pros_cons",
            "best_fit_choice",
            "alternatives",
            "buying_tips",
            "risk_assessment",
            "insight",
            "optimal_actions",
            "metrics",
            "conclusion",
            "roadmap",
        ],
    },
    "investment": {
        "label_ko": "투자",
        "layer1_keys": [
            "executive_summary",
            "asset_overview",
            "market_situation",
            "bullish_case",
            "bearish_case",
            "risk_assessment",
            "scenario_analysis",
            "time_horizon",
            "key_indicators",
            "insight",
            "optimal_actions",
            "portfolio_fit",
            "conclusion",
            "roadmap",
        ],
    },
    "art": {
        "label_ko": "예술",
        "layer1_keys": [
            "executive_summary",
            "work_overview",
            "background_context",
            "mood_tone",
            "themes",
            "symbolic_elements",
            "style_analysis",
            "emotional_impact",
            "interpretation",
            "creative_insight",
            "optimal_actions",
            "reference_points",
            "conclusion",
            "roadmap",
        ],
    },
    "cooking": {
        "label_ko": "요리",
        "layer1_keys": [
            "executive_summary",
            "cooking_goal",
            "ingredient_situation",
            "cooking_options",
            "flavor_analysis",
            "difficulty_time",
            "recipe_strategy",
            "substitution_options",
            "failure_points",
            "plating_serving",
            "insight",
            "optimal_actions",
            "metrics",
            "conclusion",
            "roadmap",
        ],
    },
    "travel": {
        "label_ko": "여행",
        "layer1_keys": [
            "executive_summary",
            "trip_goal",
            "traveler_profile",
            "destination_options",
            "local_highlights",
            "itinerary_analysis",
            "budget_situation",
            "accommodation_transport",
            "risk_assessment",
            "travel_tips",
            "insight",
            "optimal_actions",
            "metrics",
            "conclusion",
            "roadmap",
        ],
    },
    "self_development": {
        "label_ko": "자기계발",
        "layer1_keys": [
            "executive_summary",
            "current_state",
            "goal_definition",
            "obstacles",
            "opportunities",
            "learning_analysis",
            "strategy_proposals",
            "habit_design",
            "risk_assessment",
            "insight",
            "optimal_actions",
            "metrics",
            "conclusion",
            "roadmap",
        ],
    },
    "career": {
        "label_ko": "커리어",
        "layer1_keys": [
            "executive_summary",
            "current_profile",
            "market_situation",
            "role_options",
            "skill_gap",
            "opportunities",
            "competitive_analysis",
            "strategy_proposals",
            "risk_assessment",
            "insight",
            "optimal_actions",
            "metrics",
            "conclusion",
            "roadmap",
        ],
    },
    "content": {
        "label_ko": "콘텐츠",
        "layer1_keys": [
            "executive_summary",
            "topic_overview",
            "audience_analysis",
            "trend_situation",
            "content_opportunities",
            "competitive_analysis",
            "angle_proposals",
            "structure_strategy",
            "risk_assessment",
            "insight",
            "optimal_actions",
            "metrics",
            "conclusion",
            "roadmap",
        ],
    },
    "relationships": {
        "label_ko": "인간관계",
        "layer1_keys": [
            "executive_summary",
            "situation_summary",
            "stakeholder_analysis",
            "emotional_dynamics",
            "problems",
            "misunderstanding_points",
            "communication_options",
            "strategy_proposals",
            "risk_assessment",
            "insight",
            "optimal_actions",
            "metrics",
            "conclusion",
            "roadmap",
        ],
    },
    "lifestyle": {
        "label_ko": "라이프스타일/의사결정",
        "layer1_keys": [
            "executive_summary",
            "decision_context",
            "current_situation",
            "options",
            "comparison_analysis",
            "short_term_effects",
            "long_term_effects",
            "trade_offs",
            "risk_assessment",
            "insight",
            "optimal_actions",
            "metrics",
            "conclusion",
            "roadmap",
        ],
    },
}


def normalize_category(category: str | None) -> str:
    s = (category or "").strip()
    return s if s in _CATEGORY_SPECS else "business"


def _kst_tzinfo():
    if ZoneInfo:
        try:
            return ZoneInfo("Asia/Seoul")
        except Exception:
            pass
    return timezone(timedelta(hours=9))


def _seoul_today() -> date:
    tz = _kst_tzinfo()
    return datetime.now(tz).date()


def _openai_key() -> str:
    # 배포/로컬 환경마다 키 변수명이 달라지는 경우가 있어 여러 후보를 허용합니다.
    key = (
        os.getenv("OPENAI_API_KEY")
        or os.getenv("GPT_API_KEY")
        or os.getenv("GPT_API_key")
        or ""
    ).strip()
    if not key:
        raise RuntimeError(
            "OpenAI API 키가 설정되지 않았습니다. "
            "환경변수 OPENAI_API_KEY(권장) 또는 GPT_API_KEY/GPT_API_key 를 설정하세요."
        )
    lk = key.lower()
    # 실수로 모델명을 키 변수에 넣는 경우가 있어 명확히 안내합니다.
    if lk.startswith(("gpt-", "o1", "o3", "o4")) or key.upper().startswith("GPT-"):
        raise RuntimeError(
            "OpenAI API 키 환경변수에 모델명이 들어가 있습니다. "
            f"(현재 값: {key}) "
            "OPENAI_API_KEY에는 'sk-'로 시작하는 실제 API 키를 넣고, "
            "모델은 OPENAI_MODEL로 설정하세요."
        )
    # 대부분의 OpenAI API 키는 sk- 로 시작합니다. 형식이 이상하면 빠르게 실패시켜 원인 파악을 돕습니다.
    if not lk.startswith("sk-"):
        raise RuntimeError(
            "OpenAI API 키 형식이 올바르지 않습니다. "
            f"(현재 값: {key}) "
            "OPENAI_API_KEY에는 'sk-'로 시작하는 실제 API 키를 넣어주세요."
        )
    return key


def _openai_model() -> str:
    # 기본값은 범용적으로 사용 가능한 모델로 설정합니다.
    return (os.getenv("OPENAI_MODEL") or "gpt-4o-mini").strip()


def _is_invalid_model_response_body(body: str) -> bool:
    t = (body or "").lower()
    return ("invalid model" in t) or ("model_not_found" in t) or ("model not found" in t)


def _candidate_models(primary: str) -> list[str]:
    # primary를 우선 시도하고, 실패(잘못된 모델) 시 범용 모델로 폴백합니다.
    fallbacks = ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini"]
    out: list[str] = []
    p = (primary or "").strip()
    if p:
        out.append(p)
    for m in fallbacks:
        if m not in out:
            out.append(m)
    return out


def _openai_api_url() -> str:
    return (os.getenv("OPENAI_API_URL") or OPENAI_API_URL).strip()


def _openai_optional_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    org = (os.getenv("OPENAI_ORG_ID") or "").strip()
    project = (os.getenv("OPENAI_PROJECT_ID") or "").strip()
    if org:
        headers["OpenAI-Organization"] = org
    if project:
        headers["OpenAI-Project"] = project
    return headers


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


def generate_sections_via_openai(*, question_query: str, category: str | None = None) -> dict[str, Any]:
    key = _openai_key()
    model = _openai_model()
    api_url = _openai_api_url()

    category = normalize_category(category)
    spec = _CATEGORY_SPECS.get(category) or _CATEGORY_SPECS["business"]
    layer1_keys: list[str] = list(spec.get("layer1_keys") or [])
    label_ko = str(spec.get("label_ko") or category)

    schema_hint: dict[str, Any] = {k: "string" for k in layer1_keys}
    schema_hint["layer2_action"] = {
        "one_thing": "string (오늘 하루 안에 가능한 단 1개 행동)",
        "reason": "string (왜 이 행동이 가장 중요한지)",
        "do_today": ["string", "string", "string"],
        "output_by_tonight": "string (오늘 밤까지 산출물/증거)",
        "judgement_rule": {"good": "string", "bad": "string"},
        "next_move": {"if_good": "string", "if_bad": "string"},
    }
    schema_hint["sources"] = [{"title": "string", "url": "string", "published_date": "string(옵션)"}]

    system = (
        f"당신은 '{label_ko}' 카테고리의 리서치를 작성하는 애널리스트입니다. "
        "반드시 '오직 JSON'만 출력하세요(마크다운, 코드펜스, 설명 금지). "
        "모든 본문은 한국어로 작성하되, 키 이름은 고정된 영어 키를 사용합니다. "
        "반환 JSON에는 아래 스키마에 정의된 키만 포함하고(추가 키 금지), "
        "그리고 반드시 layer2_action을 포함하세요. layer2_action은 Layer1 리포트 내용을 바탕으로, "
        "'오늘 하루' 안에 즉시 실행 가능한 단 하나의 행동으로 정제한 결과여야 합니다. "
        "one_thing은 구체적이고 측정 가능해야 하며(예: 전화 10통, 랜딩페이지 A/B 1개, 고객 5명 인터뷰 등), "
        "do_today는 3개 항목으로, 30~90분 단위로 바로 실행할 수 있게 써주세요."
    )
    user = (
        "아래 질문에 대한 일일 리서치 리포트를 작성하세요.\n\n"
        f"카테고리: {label_ko} ({category})\n"
        f"질문: {question_query}\n\n"
        "요구사항:\n"
        "- 분량: PDF로 약 10페이지가 나오도록 충분히 상세하게(섹션별 6~12개 문장/불릿 혼합)\n"
        "- 각 섹션은 서로 중복을 최소화\n"
        "- 출처는 최소 6개 이상, 가능한 공식/권위있는 자료 위주\n\n"
        "Layer2 액션 설계 규칙:\n"
        "- layer2_action.one_thing: 오늘 안에 끝낼 수 있는 단 1개 행동(실행 가능, 비용/권한 현실적)\n"
        "- layer2_action.reason: 왜 이것이 가장 중요한지(리스크/기회/학습가치 기준)\n"
        "- layer2_action.do_today: 오늘 할 일을 3단계로(각 단계는 30~90분 내 완료)\n"
        "- layer2_action.output_by_tonight: 오늘 밤까지 남길 산출물(문서/시트/스크린샷/결과 수치)\n"
        "- layer2_action.judgement_rule.good/bad: 성공/실패 판정 기준(측정 기준 포함)\n"
        "- layer2_action.next_move.if_good/if_bad: 내일의 다음 행동\n\n"
        "반환 JSON 스키마(예시 타입):\n"
        f"{json.dumps(schema_hint, ensure_ascii=False)}"
    )

    last_error: Exception | None = None
    attempted: list[str] = []
    with httpx.Client(timeout=120) as client:
        for m in _candidate_models(model):
            attempted.append(m)
            payload = {
                "model": m,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
            try:
                r = client.post(
                    api_url,
                    headers={
                        "Authorization": f"Bearer {key}",
                        **_openai_optional_headers(),
                    },
                    json=payload,
                )
                r.raise_for_status()
                data = r.json()
                break
            except httpx.HTTPStatusError as e:
                status = e.response.status_code if e.response is not None else None
                body = ""
                try:
                    body = (e.response.text or "") if e.response is not None else ""
                except Exception:
                    body = ""

                # 잘못된 모델인 경우에만 폴백 재시도
                if status == 400 and _is_invalid_model_response_body(body) and (m != attempted[-1]):
                    last_error = e
                    continue

                hint = ""
                if status == 401:
                    hint = (
                        " (401: API 키가 유효하지 않거나, 배포 환경에 키가 잘못 주입된 경우가 많습니다. "
                        "OPENAI_API_KEY 값을 확인하세요.)"
                    )
                if status == 400 and _is_invalid_model_response_body(body):
                    hint = (
                        " (400: 모델명이 유효하지 않습니다. OPENAI_MODEL을 계정에서 사용 가능한 모델로 설정하세요.)"
                    )
                raise RuntimeError(
                    f"OpenAI 호출 실패(model={m}): HTTP {status}. {body}{hint}"
                ) from e
            except httpx.RequestError as e:
                raise RuntimeError(f"OpenAI 호출 네트워크 오류: {e}") from e
        else:
            # for-else: 어떤 모델도 성공하지 못한 경우
            if last_error is not None:
                raise RuntimeError(
                    "OpenAI 호출 실패: 사용 가능한 모델을 찾지 못했습니다. "
                    f"(시도한 모델: {', '.join(attempted)})"
                ) from last_error
            raise RuntimeError(
                "OpenAI 호출 실패: 알 수 없는 이유로 요청이 실패했습니다. "
                f"(시도한 모델: {', '.join(attempted)})"
            )

    content = (
        (((data.get("choices") or [{}])[0].get("message") or {}).get("content")) or ""
    )
    sections = _extract_json(content)

    # 키 정규화(구버전 호환)
    # - 과거 리포트/모델이 smartgauge_insight를 반환할 수 있어 insight로 흡수합니다.
    if ("insight" not in sections) and ("smartgauge_insight" in sections):
        sections["insight"] = sections.get("smartgauge_insight")

    # 최소 키 보정: 모델 출력이 누락되어도 리포트 생성이 실패하지 않게 기본값 채움
    for k in layer1_keys:
        v = sections.get(k)
        if v is None:
            sections[k] = ""
        elif not isinstance(v, str):
            sections[k] = str(v)
    if not isinstance(sections.get("sources"), list):
        sections["sources"] = []

    # layer2_action 기본 보정(누락/형식 오류에도 리포트 생성이 실패하지 않게)
    l2 = sections.get("layer2_action")
    if not isinstance(l2, dict):
        l2 = {}
    if not isinstance(l2.get("one_thing"), str):
        l2["one_thing"] = ""
    if not isinstance(l2.get("reason"), str):
        l2["reason"] = ""
    if not isinstance(l2.get("do_today"), list):
        l2["do_today"] = ["", "", ""]
    else:
        # 길이를 3으로 맞춤
        arr = [str(x) if isinstance(x, str) else "" for x in l2.get("do_today", [])]
        l2["do_today"] = (arr + ["", "", ""])[:3]
    if not isinstance(l2.get("output_by_tonight"), str):
        l2["output_by_tonight"] = ""
    jr = l2.get("judgement_rule")
    if not isinstance(jr, dict):
        jr = {}
    if not isinstance(jr.get("good"), str):
        jr["good"] = ""
    if not isinstance(jr.get("bad"), str):
        jr["bad"] = ""
    l2["judgement_rule"] = jr
    nm = l2.get("next_move")
    if not isinstance(nm, dict):
        nm = {}
    if not isinstance(nm.get("if_good"), str):
        nm["if_good"] = ""
    if not isinstance(nm.get("if_bad"), str):
        nm["if_bad"] = ""
    l2["next_move"] = nm
    sections["layer2_action"] = l2
    return sections


def _pdf_output_path(*, question_id: int, run_date: date) -> Path:
    base = Path(__file__).resolve().parent
    return base / "generated" / run_date.isoformat() / f"report_q{question_id}_{run_date.isoformat()}.pdf"


def run_research_for_question(
    *,
    db: Session,
    question: ResearchQuestion,
    user_id: int | None = None,
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

    report = existing or ResearchReport(
        question_id=question.id,
        user_id=int(user_id) if user_id is not None else getattr(question, "user_id", None),
        run_date=run_date,
    )
    if report.user_id is None:
        report.user_id = getattr(question, "user_id", None)
    # 질문 title을 리포트에 스냅샷으로 저장(질문 삭제 후에도 표시용)
    if getattr(report, "title", None) in (None, ""):
        qt = (getattr(question, "title", None) or "").strip()
        report.title = qt if qt else f"질문 #{int(getattr(question, 'id', 0) or 0)}"
    report.status = "running"
    report.error = None
    db.add(report)
    db.commit()
    db.refresh(report)

    try:
        sections = generate_sections_via_openai(
            question_query=question.query,
            category=getattr(question, "category", None),
        )
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
            .filter(ResearchQuestion.user_id.isnot(None))
            .order_by(ResearchQuestion.created_at.desc())
            .all()
        )
        today = _seoul_today()
        for q in qs:
            try:
                r = run_research_for_question(
                    db=db,
                    question=q,
                    user_id=int(getattr(q, "user_id", None)) if getattr(q, "user_id", None) is not None else None,
                    run_date=today,
                    force=force,
                )
                created.append(int(r.id))
            except Exception:
                # 개별 실패는 전체 스케줄을 막지 않음
                continue
        return created
    finally:
        db.close()

