from __future__ import annotations

import os
from datetime import date as _date
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer


_SECTION_TITLES_KO: dict[str, str] = {
    "executive_summary": "핵심 요약",
    "market_situation": "시장 현황",
    "problems": "문제점",
    "opportunities": "기회 요인",
    "competitive_analysis": "경쟁 분석",
    "strategy_proposals": "전략 제안",
    "risk_assessment": "리스크 평가",
    "insight": "인사이트",
    "optimal_actions": "최적 실행안",
    "metrics": "핵심 지표/판단 기준",
    "conclusion": "결론",
    "roadmap": "로드맵",
    "needs_analysis": "사용자 니즈 분석",
    "budget_situation": "예산 상황",
    "comparison_targets": "비교 대상",
    "option_analysis": "선택지 분석",
    "pros_cons": "장단점",
    "best_fit_choice": "최적 선택",
    "alternatives": "대안 옵션",
    "buying_tips": "구매 팁",
    "asset_overview": "자산 개요",
    "bullish_case": "상승 논리",
    "bearish_case": "하락 논리",
    "scenario_analysis": "시나리오 분석",
    "time_horizon": "기간별 관점",
    "key_indicators": "핵심 지표",
    "portfolio_fit": "포트폴리오 적합성",
    "work_overview": "작품 개요",
    "background_context": "배경 맥락",
    "mood_tone": "분위기와 톤",
    "themes": "핵심 주제",
    "symbolic_elements": "상징 요소",
    "style_analysis": "스타일 분석",
    "emotional_impact": "감정적 영향",
    "interpretation": "해석",
    "creative_insight": "창작 인사이트",
    "reference_points": "참고 포인트",
    "cooking_goal": "요리 목적",
    "ingredient_situation": "재료 상황",
    "cooking_options": "가능한 메뉴",
    "flavor_analysis": "맛 방향 분석",
    "difficulty_time": "난이도와 소요시간",
    "recipe_strategy": "조리 전략",
    "substitution_options": "대체 재료",
    "failure_points": "실패 포인트",
    "plating_serving": "플레이팅 및 제공 팁",
    "trip_goal": "여행 목적",
    "traveler_profile": "여행자 성향",
    "destination_options": "목적지 후보",
    "local_highlights": "지역 핵심 요소",
    "itinerary_analysis": "일정 분석",
    "accommodation_transport": "숙소·이동 분석",
    "travel_tips": "여행 팁",
    "current_state": "현재 상태",
    "goal_definition": "목표 정의",
    "obstacles": "장애 요인",
    "learning_analysis": "학습 분석",
    "habit_design": "습관 설계",
    "current_profile": "현재 프로필",
    "role_options": "직무 선택지",
    "skill_gap": "역량 격차",
    "topic_overview": "주제 개요",
    "audience_analysis": "타겟 분석",
    "trend_situation": "트렌드 현황",
    "content_opportunities": "기회 요인",
    "angle_proposals": "방향성 제안",
    "structure_strategy": "구성 전략",
    "situation_summary": "상황 요약",
    "stakeholder_analysis": "관계자 분석",
    "emotional_dynamics": "감정 흐름",
    "misunderstanding_points": "오해 포인트",
    "communication_options": "소통 선택지",
    "decision_context": "결정 맥락",
    "current_situation": "현재 상황",
    "options": "선택지",
    "comparison_analysis": "비교 분석",
    "short_term_effects": "단기 영향",
    "long_term_effects": "장기 영향",
    "trade_offs": "트레이드오프",
    "layer2_action": "오늘 바로 가능한 행동",
    "sources": "출처",
}

_CATEGORY_ORDERS: dict[str, list[str]] = {
    "business": [
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
    "shopping": [
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
    "investment": [
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
    "art": [
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
    "cooking": [
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
    "travel": [
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
    "self_development": [
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
    "career": [
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
    "content": [
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
    "relationships": [
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
    "lifestyle": [
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
}


def _pick_order_keys(sections: dict[str, Any]) -> list[str]:
    keys = set((sections or {}).keys())
    best = "business"
    best_score = -1
    for cat, order in _CATEGORY_ORDERS.items():
        score = len(keys.intersection(order))
        if score > best_score:
            best = cat
            best_score = score
    return list(_CATEGORY_ORDERS.get(best) or _CATEGORY_ORDERS["business"])


def _layer2_to_text(v: Any) -> str:
    if not isinstance(v, dict):
        return ""
    one = (v.get("one_thing") or "").strip() if isinstance(v.get("one_thing"), str) else ""
    reason = (v.get("reason") or "").strip() if isinstance(v.get("reason"), str) else ""
    do_today = v.get("do_today")
    do_lines: list[str] = []
    if isinstance(do_today, list):
        for i, x in enumerate(do_today, start=1):
            if isinstance(x, str) and x.strip():
                do_lines.append(f"{i}) {x.strip()}")
    out_by = (v.get("output_by_tonight") or "").strip() if isinstance(v.get("output_by_tonight"), str) else ""
    jr = v.get("judgement_rule") if isinstance(v.get("judgement_rule"), dict) else {}
    good = (jr.get("good") or "").strip() if isinstance(jr.get("good"), str) else ""
    bad = (jr.get("bad") or "").strip() if isinstance(jr.get("bad"), str) else ""
    nm = v.get("next_move") if isinstance(v.get("next_move"), dict) else {}
    if_good = (nm.get("if_good") or "").strip() if isinstance(nm.get("if_good"), str) else ""
    if_bad = (nm.get("if_bad") or "").strip() if isinstance(nm.get("if_bad"), str) else ""

    parts: list[str] = []
    if one:
        parts.append(f"단 한 가지:\n{one}")
    if reason:
        parts.append(f"이유:\n{reason}")
    if do_lines:
        parts.append("실행 방법:\n" + "\n".join(do_lines))
    if out_by:
        parts.append(f"오늘 밤까지 산출물:\n{out_by}")
    if good or bad:
        t = []
        if good:
            t.append(f"- 성공: {good}")
        if bad:
            t.append(f"- 실패: {bad}")
        parts.append("판단 기준:\n" + "\n".join(t))
    if if_good or if_bad:
        t = []
        if if_good:
            t.append(f"- 성공하면: {if_good}")
        if if_bad:
            t.append(f"- 실패하면: {if_bad}")
        parts.append("다음 행동:\n" + "\n".join(t))
    return "\n\n".join(parts).strip()


def _try_register_korean_font() -> str:
    """
    ReportLab 기본 폰트는 한글이 깨질 수 있어, OS에 있는 한글 폰트를 우선 사용합니다.
    - Windows: Malgun Gothic
    """
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    except Exception:
        return "Helvetica"

    candidates = []

    # 운영 환경에서 폰트 경로를 직접 주입할 수 있게 합니다.
    env_font = (os.getenv("KOREAN_FONT_PATH") or "").strip()
    if env_font:
        candidates.append(env_font)

    # Windows (로컬 개발)
    candidates += [
        r"C:\Windows\Fonts\malgun.ttf",
        r"C:\Windows\Fonts\malgunsl.ttf",
    ]

    # macOS (개발용)
    candidates += [
        "/System/Library/Fonts/AppleSDGothicNeo.ttc",
        "/Library/Fonts/AppleGothic.ttf",
    ]

    # Linux (배포용: Noto/Nanum 계열이 설치된 경우)
    candidates += [
        "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
        "/usr/share/fonts/truetype/nanum/NanumSquareR.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJKkr-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansCJKkr-Regular.otf",
        "/usr/share/fonts/opentype/noto/NotoSansKR-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSansKR-Regular.otf",
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                font_name = "SmartResearchKorean"
                pdfmetrics.registerFont(TTFont(font_name, p))
                return font_name
            except Exception:
                continue

    # OS 폰트를 못 찾는 배포 환경에서도 한글이 깨지지 않도록 CID 폰트를 시도합니다.
    # (ReportLab 내장 매핑 기반. 환경에 따라 가장 안정적인 것을 선택)
    for cid_name in ("HYGothic-Medium", "HYSMyeongJo-Medium"):
        try:
            pdfmetrics.registerFont(UnicodeCIDFont(cid_name))
            return cid_name
        except Exception:
            continue
    return "Helvetica"


def _p(text: str | None) -> str:
    # Paragraph는 내부적으로 XML 파서처럼 동작하므로, 특수문자를 이스케이프합니다.
    from xml.sax.saxutils import escape

    t = (text or "").strip()
    return escape(t).replace("\n", "<br/>")


def generate_research_pdf(
    *,
    output_path: str | Path,
    run_date: _date,
    question_title: str | None,
    question_query: str,
    sections: dict[str, Any],
) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    font_name = _try_register_korean_font()
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleKR",
        parent=styles["Title"],
        fontName=font_name,
        fontSize=18,
        leading=22,
        spaceAfter=10,
    )
    h_style = ParagraphStyle(
        "H2KR",
        parent=styles["Heading2"],
        fontName=font_name,
        fontSize=14,
        leading=18,
        spaceBefore=6,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyKR",
        parent=styles["BodyText"],
        fontName=font_name,
        fontSize=10.5,
        leading=14,
    )

    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="SmartResearch Report",
        author="SmartResearch",
    )

    title = question_title.strip() if (question_title or "").strip() else "Daily Research Report"
    story = [
        Paragraph(title, title_style),
        Paragraph(f"Date: {run_date.isoformat()}", body_style),
        Spacer(1, 6),
        Paragraph("Question", h_style),
        Paragraph(_p(question_query), body_style),
        Spacer(1, 8),
    ]

    # 키 정규화(구버전 호환)
    if ("insight" not in sections) and ("smartgauge_insight" in sections):
        sections = dict(sections)
        sections["insight"] = sections.get("smartgauge_insight")

    # sources는 list 형태로 들어오므로, PDF 표기용 문자열을 만들어 둡니다.
    sources = sections.get("sources")
    if isinstance(sources, list):
        lines: list[str] = []
        for i, s in enumerate(sources, start=1):
            if isinstance(s, dict):
                t = (s.get("title") or "").strip()
                u = (s.get("url") or "").strip()
                if t and u:
                    lines.append(f"[{i}] {t} - {u}")
                elif u:
                    lines.append(f"[{i}] {u}")
                elif t:
                    lines.append(f"[{i}] {t}")
            elif isinstance(s, str) and s.strip():
                lines.append(f"[{i}] {s.strip()}")
        sections = dict(sections)
        sections["sources_text"] = "\n".join(lines) if lines else ""
    else:
        sections = dict(sections)
        sections["sources_text"] = ""

    order_keys = _pick_order_keys(sections)
    rendered_keys: set[str] = set()

    def _add_page(title: str, body: str):
        if rendered_keys:
            story.append(PageBreak())
        story.append(Paragraph(title, h_style))
        story.append(Paragraph(_p(body), body_style))

    # Layer1: 카테고리별 권장 순서대로 출력
    for k in order_keys:
        v = sections.get(k)
        if isinstance(v, str) and v.strip():
            _add_page(_SECTION_TITLES_KO.get(k, k), v)
            rendered_keys.add(k)

    # Layer2: 있으면 출력
    l2_text = _layer2_to_text(sections.get("layer2_action"))
    if l2_text:
        _add_page(_SECTION_TITLES_KO.get("layer2_action", "layer2_action"), l2_text)
        rendered_keys.add("layer2_action")

    # 출처
    sources_text = str(sections.get("sources_text") or "")
    if sources_text.strip():
        _add_page(_SECTION_TITLES_KO.get("sources", "출처"), sources_text)
        rendered_keys.add("sources")

    # 남은 문자열 키(모델이 추가로 준 값이 있어도 최대한 살려서 PDF에 싣습니다)
    extras: list[tuple[str, str]] = []
    for k, v in (sections or {}).items():
        if k in rendered_keys:
            continue
        if k in ("sources_text", "smartgauge_insight", "sources"):
            continue
        if isinstance(v, str) and v.strip():
            extras.append((k, v))
    for k, v in extras:
        _add_page(_SECTION_TITLES_KO.get(k, k), v)

    doc.build(story)
    return out

