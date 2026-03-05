from __future__ import annotations

import os
from datetime import date as _date
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer


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

    ordered = [
        ("Executive Summary", "executive_summary"),
        ("시장 상황", "market_situation"),
        ("문제점", "problems"),
        ("기회 요인", "opportunities"),
        ("경쟁 분석", "competitive_analysis"),
        ("전략 제안", "strategy_proposals"),
        ("리스크 평가", "risk_assessment"),
        ("인사이트", "insight"),
        ("최적 실행안", "optimal_actions"),
        ("핵심 지표", "metrics"),
        ("로드맵", "roadmap"),
        ("결론", "conclusion"),
        ("출처", "sources_text"),
    ]

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

    for i, (heading, key) in enumerate(ordered):
        if i > 0:
            story.append(PageBreak())
        story.append(Paragraph(heading, h_style))
        story.append(Paragraph(_p(str(sections.get(key, "") or "")), body_style))

    doc.build(story)
    return out

