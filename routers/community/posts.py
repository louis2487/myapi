from __future__ import annotations

# NOTE:
# 이 파일은 기존 `main.py`에 있던 커뮤니티 게시글/댓글/좋아요 API를
# 유지보수 용이성을 위해 `routers/community/`로 이동한 모듈입니다.

import base64
import calendar
import json
import os
import re
import tempfile
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import List, Literal, Optional

import hashlib
import jwt
import openpyxl
import requests
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Header, status
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

from deps import get_db
from models import (
    Cash,
    Community_Comment,
    Community_Post,
    Community_User,
    Community_User_Restriction,
    Notification,
    Point,
    Post_Like,
    Referral,
)
from routers.community.logic import (
    AD_CATEGORIES,
    AD_PRIMARY_CATEGORY,
    _apply_user_grade_upgrade,
    _normalize_ad_job_industry,
    _rollover_ad_card_types,
    _rollover_recruit_card_types,
)
from routers.community.notifications import notify_admin_acknowledged_post, notify_all_push_post, notify_owners_post
from routers.notify import create_notification, get_user_id_by_username, send_push


# 기존 코드에서 사용하던 데코레이터명을 유지하기 위해,
# 여기서는 APIRouter를 `app` 이름으로 둡니다.
app = APIRouter()
router = app


def split_address(addr: str):
    parts = addr.split()
    province = parts[0] if len(parts) > 0 else None
    city = parts[1] if len(parts) > 1 else None
    return province, city


# ---- 지역(시/도) 표기 정규화 ----
# 앱/유저 설정(맞춤현장)에서 축약형("서울")과 정식명("서울특별시")이 혼재할 수 있어
# 서버 필터는 둘 다 매칭되도록 후보군을 만들어 사용합니다.
PROVINCE_SHORT_TO_FULL = {
    "전체": "전체",
    "서울": "서울특별시",
    "경기": "경기도",
    "인천": "인천광역시",
    "강원": "강원특별자치도",
    "충북": "충청북도",
    "충남": "충청남도",
    "대전": "대전광역시",
    "세종": "세종특별자치시",
    "경북": "경상북도",
    "경남": "경상남도",
    "부산": "부산광역시",
    "대구": "대구광역시",
    "전북": "전북특별자치도",
    "전남": "전라남도",
    "광주": "광주광역시",
    "울산": "울산광역시",
    "제주": "제주특별자치도",
}


def normalize_province_name(prov: str) -> str:
    p = (prov or "").strip()
    if not p:
        return ""
    return PROVINCE_SHORT_TO_FULL.get(p, p)


def province_candidates(prov: str) -> list[str]:
    p = (prov or "").strip()
    if not p:
        return []
    full = normalize_province_name(p)
    return [p, full] if full and full != p else [p]


StatusLiteral = Literal["published", "closed"]


class PostCreate(BaseModel):
    title: str
    content: str
    image_url: Optional[str] = None
    contract_fee: Optional[str] = None
    workplace_address: Optional[str] = None
    workplace_map_url: Optional[str] = None
    business_address: Optional[str] = None
    business_map_url: Optional[str] = None
    workplace_lat: Optional[float] = None
    workplace_lng: Optional[float] = None
    business_lat: Optional[float] = None
    business_lng: Optional[float] = None
    job_industry: Optional[str] = None
    job_category: Optional[str] = None
    pay_support: Optional[bool] = None
    meal_support: Optional[bool] = None
    house_support: Optional[bool] = None
    company_developer: Optional[str] = None
    company_constructor: Optional[str] = None
    company_trustee: Optional[str] = None
    company_agency: Optional[str] = None
    agency_call: Optional[str] = None
    province: Optional[str] = None
    city: Optional[str] = None
    status: Optional[StatusLiteral] = "published"
    highlight_color: Optional[str] = None
    highlight_content: Optional[str] = None
    total_use: Optional[bool] = None
    branch_use: Optional[bool] = None
    hq_use: Optional[bool] = None
    leader_use: Optional[bool] = None
    member_use: Optional[bool] = None
    team_use: Optional[bool] = None
    each_use: Optional[bool] = None
    total_fee: Optional[str] = None
    branch_fee: Optional[str] = None
    hq_fee: Optional[str] = None
    leader_fee: Optional[str] = None
    member_fee: Optional[str] = None
    team_fee: Optional[str] = None
    each_fee: Optional[str] = None
    pay_use: Optional[bool] = None
    meal_use: Optional[bool] = None
    house_use: Optional[bool] = None
    pay_sup: Optional[str] = None
    meal_sup: Optional[bool] = None
    house_sup: Optional[str] = None
    item1_use: Optional[bool] = None
    item1_type: Optional[str] = None
    item1_sup: Optional[str] = None
    item2_use: Optional[bool] = None
    item2_type: Optional[str] = None
    item2_sup: Optional[str] = None
    item3_use: Optional[bool] = None
    item3_type: Optional[str] = None
    item3_sup: Optional[str] = None
    item4_use: Optional[bool] = None
    item4_type: Optional[str] = None
    item4_sup: Optional[str] = None
    agent: Optional[str] = None
    other_role_name: Optional[str] = None
    other_role_fee: Optional[str] = None
    post_type: Optional[float] = None
    card_type: Optional[float] = None


class PostAuthor(BaseModel):
    id: int
    username: str


class PostOut(BaseModel):
    id: int
    author: PostAuthor
    title: str
    content: str
    image_url: Optional[str] = None
    created_at: datetime
    contract_fee: Optional[str] = None
    workplace_address: Optional[str] = None
    workplace_map_url: Optional[str] = None
    business_address: Optional[str] = None
    business_map_url: Optional[str] = None
    workplace_lat: Optional[float] = None
    workplace_lng: Optional[float] = None
    business_lat: Optional[float] = None
    business_lng: Optional[float] = None
    job_industry: Optional[str] = None
    job_category: Optional[str] = None
    pay_support: Optional[bool] = None
    meal_support: Optional[bool] = None
    house_support: Optional[bool] = None
    company_developer: Optional[str] = None
    company_constructor: Optional[str] = None
    company_trustee: Optional[str] = None
    company_agency: Optional[str] = None
    agency_call: Optional[str] = None
    province: Optional[str] = None
    city: Optional[str] = None
    status: StatusLiteral
    highlight_color: Optional[str] = None
    highlight_content: Optional[str] = None
    total_use: Optional[bool] = None
    branch_use: Optional[bool] = None
    hq_use: Optional[bool] = None
    leader_use: Optional[bool] = None
    member_use: Optional[bool] = None
    team_use: Optional[bool] = None
    each_use: Optional[bool] = None
    total_fee: Optional[str] = None
    branch_fee: Optional[str] = None
    hq_fee: Optional[str] = None
    leader_fee: Optional[str] = None
    member_fee: Optional[str] = None
    team_fee: Optional[str] = None
    each_fee: Optional[str] = None
    pay_use: Optional[bool] = None
    meal_use: Optional[bool] = None
    house_use: Optional[bool] = None
    pay_sup: Optional[str] = None
    meal_sup: Optional[bool] = None
    house_sup: Optional[str] = None
    item1_use: Optional[bool] = None
    item1_type: Optional[str] = None
    item1_sup: Optional[str] = None
    item2_use: Optional[bool] = None
    item2_type: Optional[str] = None
    item2_sup: Optional[str] = None
    item3_use: Optional[bool] = None
    item3_type: Optional[str] = None
    item3_sup: Optional[str] = None
    item4_use: Optional[bool] = None
    item4_type: Optional[str] = None
    item4_sup: Optional[str] = None
    agent: Optional[str] = None
    other_role_name: Optional[str] = None
    other_role_fee: Optional[str] = None
    post_type: Optional[float] = None
    card_type: Optional[float] = None


class PostOut2(BaseModel):
    id: int
    author: PostAuthor
    title: str
    content: str
    image_url: Optional[str] = None
    created_at: datetime
    contract_fee: Optional[str] = None
    workplace_address: Optional[str] = None
    workplace_map_url: Optional[str] = None
    business_address: Optional[str] = None
    business_map_url: Optional[str] = None
    workplace_lat: Optional[float] = None
    workplace_lng: Optional[float] = None
    business_lat: Optional[float] = None
    business_lng: Optional[float] = None
    job_industry: Optional[str] = None
    job_category: Optional[str] = None
    pay_support: Optional[bool] = None
    meal_support: Optional[bool] = None
    house_support: Optional[bool] = None
    company_developer: Optional[str] = None
    company_constructor: Optional[str] = None
    company_trustee: Optional[str] = None
    company_agency: Optional[str] = None
    agency_call: Optional[str] = None
    province: Optional[str] = None
    city: Optional[str] = None
    status: StatusLiteral
    liked: Optional[bool] = False
    highlight_color: Optional[str] = None
    highlight_content: Optional[str] = None
    total_use: Optional[bool] = None
    branch_use: Optional[bool] = None
    hq_use: Optional[bool] = None
    leader_use: Optional[bool] = None
    member_use: Optional[bool] = None
    team_use: Optional[bool] = None
    each_use: Optional[bool] = None
    total_fee: Optional[str] = None
    branch_fee: Optional[str] = None
    hq_fee: Optional[str] = None
    leader_fee: Optional[str] = None
    member_fee: Optional[str] = None
    team_fee: Optional[str] = None
    each_fee: Optional[str] = None
    pay_use: Optional[bool] = None
    meal_use: Optional[bool] = None
    house_use: Optional[bool] = None
    pay_sup: Optional[str] = None
    meal_sup: Optional[bool] = None
    house_sup: Optional[str] = None
    item1_use: Optional[bool] = None
    item1_type: Optional[str] = None
    item1_sup: Optional[str] = None
    item2_use: Optional[bool] = None
    item2_type: Optional[str] = None
    item2_sup: Optional[str] = None
    item3_use: Optional[bool] = None
    item3_type: Optional[str] = None
    item3_sup: Optional[str] = None
    item4_use: Optional[bool] = None
    item4_type: Optional[str] = None
    item4_sup: Optional[str] = None
    agent: Optional[str] = None
    other_role_name: Optional[str] = None
    other_role_fee: Optional[str] = None
    post_type: Optional[float] = None
    card_type: Optional[float] = None


class PostsOut(BaseModel):
    items: List[PostOut]
    next_cursor: Optional[str] = None


class PostUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    image_url: Optional[str] = None
    contract_fee: Optional[str] = None
    workplace_address: Optional[str] = None
    workplace_map_url: Optional[str] = None
    business_address: Optional[str] = None
    business_map_url: Optional[str] = None
    workplace_lat: Optional[float] = None
    workplace_lng: Optional[float] = None
    business_lat: Optional[float] = None
    business_lng: Optional[float] = None
    job_industry: Optional[str] = None
    job_category: Optional[str] = None
    pay_support: Optional[bool] = None
    meal_support: Optional[bool] = None
    house_support: Optional[bool] = None
    company_developer: Optional[str] = None
    company_constructor: Optional[str] = None
    company_trustee: Optional[str] = None
    company_agency: Optional[str] = None
    agency_call: Optional[str] = None
    province: Optional[str] = None
    city: Optional[str] = None
    status: Optional[StatusLiteral] = None
    highlight_color: Optional[str] = None
    highlight_content: Optional[str] = None
    total_use: Optional[bool] = None
    branch_use: Optional[bool] = None
    hq_use: Optional[bool] = None
    leader_use: Optional[bool] = None
    member_use: Optional[bool] = None
    team_use: Optional[bool] = None
    each_use: Optional[bool] = None
    total_fee: Optional[str] = None
    branch_fee: Optional[str] = None
    hq_fee: Optional[str] = None
    leader_fee: Optional[str] = None
    member_fee: Optional[str] = None
    team_fee: Optional[str] = None
    each_fee: Optional[str] = None
    pay_use: Optional[bool] = None
    meal_use: Optional[bool] = None
    house_use: Optional[bool] = None
    pay_sup: Optional[str] = None
    meal_sup: Optional[bool] = None
    house_sup: Optional[str] = None
    item1_use: Optional[bool] = None
    item1_type: Optional[str] = None
    item1_sup: Optional[str] = None
    item2_use: Optional[bool] = None
    item2_type: Optional[str] = None
    item2_sup: Optional[str] = None
    item3_use: Optional[bool] = None
    item3_type: Optional[str] = None
    item3_sup: Optional[str] = None
    item4_use: Optional[bool] = None
    item4_type: Optional[str] = None
    item4_sup: Optional[str] = None
    other_role_name: Optional[str] = None
    other_role_fee: Optional[str] = None
    agent: Optional[str] = None
    post_type: Optional[float] = None
    card_type: Optional[float] = None


# -------------------- Comments --------------------
class CommentCreate(BaseModel):
    content: str = Field(min_length=1, max_length=2000)
    parent_id: Optional[int] = None


class CommentOut(BaseModel):
    id: int
    post_id: int
    user_id: int
    username: str
    content: str
    created_at: datetime
    parent_id: Optional[int] = None
    is_deleted: bool

    class Config:
        from_attributes = True


class CommentListOut(BaseModel):
    items: list[CommentOut]
    next_cursor: Optional[str] = None


def _enforce_user_post_restriction(db: Session, user_id: int, post_type: int) -> None:
    """
    글 작성 제재 enforcement(필수).
    - now < restricted_until 이면 작성 거부
    - 에러 메시지에 만료일(ISO)을 포함(프론트 안내용)
    """
    try:
        pt = int(post_type)
    except Exception:
        return
    if pt not in (1, 3, 4):
        return

    r = (
        db.query(Community_User_Restriction)
        .filter(Community_User_Restriction.user_id == int(user_id), Community_User_Restriction.post_type == pt)
        .first()
    )
    if not r or not getattr(r, "restricted_until", None):
        return

    until = r.restricted_until
    if getattr(until, "tzinfo", None) is None:
        until = until.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    if now < until:
        raise HTTPException(status_code=403, detail=f"작성 제한 중입니다. post_type={pt}, 제한 만료: {until.isoformat()}")


@app.post("/community/posts/{username}", response_model=PostOut)
def create_post(username: str, body: PostCreate, db: Session = Depends(get_db)):
    # 유저 row lock으로 캐시 차감/포스트 생성 원자성 보장
    user = db.query(Community_User).filter(Community_User.username == username).with_for_update().first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid username")

    userId = user.id
    is_admin_ack = bool(getattr(user, "admin_acknowledged", False))

    now_utc = datetime.now(timezone.utc)
    # admin_acknowledged=True 이면 구인글 작성 제한(제재/일일작성)을 우회하여 무제한 작성 가능
    if not is_admin_ack:
        # ---- 제재 enforcement: 구인글(post_type=1) 작성 제한/차단 ----
        _enforce_user_post_restriction(db, int(userId), 1)

        # ---- 구인글(=post_type 1) 작성 제한: 하루 1회 (자정 기준, KST) ----
        kst = ZoneInfo("Asia/Seoul") if ZoneInfo else timezone(timedelta(hours=9))
        now_kst = now_utc.astimezone(kst)

        last = user.last_recruit_posted_at
        if last is not None:
            # tzinfo가 없으면 UTC로 간주(레거시/드라이버 이슈 방어)
            if getattr(last, "tzinfo", None) is None:
                last = last.replace(tzinfo=timezone.utc)
            last_kst = last.astimezone(kst)
            if last_kst.date() == now_kst.date():
                raise HTTPException(
                    status_code=400,
                    detail="하루에 한 번만 구인글을 작성할 수 있습니다. 자정 이후 다시 시도해주세요.",
                )

    # ---- 구인글(post_type=1) 등록 정책 ----
    # 요청사항: 캐시 차감 없이, 무조건 1유형(card_type=1)으로 등록
    card_type = 1

    post = Community_Post(
        user_id=userId,
        title=body.title,
        content=body.content,
        image_url=body.image_url,
        contract_fee=body.contract_fee,
        workplace_address=body.workplace_address,
        workplace_map_url=body.workplace_map_url,
        business_address=body.business_address,
        business_map_url=body.business_map_url,
        workplace_lat=body.workplace_lat,
        workplace_lng=body.workplace_lng,
        business_lat=body.business_lat,
        business_lng=body.business_lng,
        job_industry=body.job_industry,
        job_category=body.job_category,
        province=body.province,
        city=body.city,
        pay_support=body.pay_support,
        meal_support=body.meal_support,
        house_support=body.house_support,
        company_developer=body.company_developer,
        company_constructor=body.company_constructor,
        company_trustee=body.company_trustee,
        company_agency=body.company_agency,
        agency_call=body.agency_call,
        status=body.status or "published",
        highlight_color=body.highlight_color,
        highlight_content=body.highlight_content,
        total_use=body.total_use,
        branch_use=body.branch_use,
        hq_use=getattr(body, "hq_use", None),
        leader_use=body.leader_use,
        member_use=body.member_use,
        team_use=getattr(body, "team_use", None),
        each_use=getattr(body, "each_use", None),
        total_fee=body.total_fee,
        branch_fee=body.branch_fee,
        hq_fee=getattr(body, "hq_fee", None),
        leader_fee=body.leader_fee,
        member_fee=body.member_fee,
        team_fee=getattr(body, "team_fee", None),
        each_fee=getattr(body, "each_fee", None),
        pay_use=body.pay_use,
        meal_use=body.meal_use,
        house_use=body.house_use,
        pay_sup=body.pay_sup,
        meal_sup=body.meal_sup,
        house_sup=body.house_sup,
        item1_use=body.item1_use,
        item1_type=body.item1_type,
        item1_sup=body.item1_sup,
        item2_use=body.item2_use,
        item2_type=body.item2_type,
        item2_sup=body.item2_sup,
        item3_use=body.item3_use,
        item3_type=body.item3_type,
        item3_sup=body.item3_sup,
        item4_use=body.item4_use,
        item4_type=body.item4_type,
        item4_sup=body.item4_sup,
        agent=body.agent,
        other_role_name=body.other_role_name,
        other_role_fee=body.other_role_fee,
        post_type=1,
        card_type=card_type,
    )

    # ---- 구인글 작성 시각 갱신(하루 1회 제한/통계용) ----
    user.last_recruit_posted_at = now_utc

    db.add(post)
    db.flush()  # created_at/id 확정 후 롤오버 처리
    _rollover_recruit_card_types(db)
    db.commit()
    db.refresh(post)

    # 글 등록 푸쉬 알림(관리자 대상) - 실패해도 글 등록 성공 처리
    try:
        notify_admin_acknowledged_post(
            db,
            post_id=int(post.id),
            post_type=1,
            author_username=username,
            post_title=post.title,
            exclude_user_id=int(userId),
        )
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        print("[WARN] notify_admin_acknowledged_post failed:", e)

    return PostOut(
        id=post.id,
        author=PostAuthor(id=userId, username=username),
        title=post.title,
        content=post.content,
        image_url=post.image_url,
        created_at=post.created_at,
        contract_fee=post.contract_fee,
        workplace_address=post.workplace_address,
        workplace_map_url=post.workplace_map_url,
        business_address=post.business_address,
        business_map_url=post.business_map_url,
        workplace_lat=post.workplace_lat,
        workplace_lng=post.workplace_lng,
        business_lat=post.business_lat,
        business_lng=post.business_lng,
        job_industry=post.job_industry,
        job_category=post.job_category,
        pay_support=post.pay_support,
        meal_support=post.meal_support,
        house_support=post.house_support,
        company_developer=post.company_developer,
        company_constructor=post.company_constructor,
        company_trustee=post.company_trustee,
        company_agency=post.company_agency,
        agency_call=post.agency_call,
        province=post.province,
        city=post.city,
        status=post.status,
        highlight_color=post.highlight_color,
        highlight_content=post.highlight_content,
        total_use=post.total_use,
        branch_use=post.branch_use,
        hq_use=getattr(post, "hq_use", None),
        leader_use=post.leader_use,
        member_use=post.member_use,
        team_use=getattr(post, "team_use", None),
        each_use=getattr(post, "each_use", None),
        total_fee=post.total_fee,
        branch_fee=post.branch_fee,
        hq_fee=getattr(post, "hq_fee", None),
        leader_fee=post.leader_fee,
        member_fee=post.member_fee,
        team_fee=getattr(post, "team_fee", None),
        each_fee=getattr(post, "each_fee", None),
        pay_use=post.pay_use,
        meal_use=post.meal_use,
        house_use=post.house_use,
        pay_sup=post.pay_sup,
        meal_sup=post.meal_sup,
        house_sup=post.house_sup,
        item1_use=post.item1_use,
        item1_type=post.item1_type,
        item1_sup=post.item1_sup,
        item2_use=post.item2_use,
        item2_type=post.item2_type,
        item2_sup=post.item2_sup,
        item3_use=post.item3_use,
        item3_type=post.item3_type,
        item3_sup=post.item3_sup,
        item4_use=post.item4_use,
        item4_type=post.item4_type,
        item4_sup=post.item4_sup,
        agent=post.agent,
        other_role_name=getattr(post, "other_role_name", None),
        other_role_fee=getattr(post, "other_role_fee", None),
        post_type=post.post_type,
        card_type=post.card_type,
    )


@app.post("/community/posts/{username}/type/{post_type}", response_model=PostOut)
def create_post_plus(post_type: int, username: str, body: PostCreate, db: Session = Depends(get_db)):
    # 유저 row lock (포인트/캐시/작성제한 원자성 보장)
    user = db.query(Community_User).filter(Community_User.username == username).with_for_update().first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid username")

    userId = user.id
    is_admin_ack = bool(getattr(user, "admin_acknowledged", False))

    # ---- 제재 enforcement: post_type(1/3/4) 작성 제한/차단 ----
    # 구인글(post_type=1)은 admin_acknowledged=True 이면 제재 우회(무제한 작성)
    if not (int(post_type) == 1 and is_admin_ack):
        _enforce_user_post_restriction(db, int(userId), int(post_type))

    # post_type == 1 (구인글): 하루 1회 제한
    if int(post_type) == 1:
        now_utc = datetime.now(timezone.utc)
        if not is_admin_ack:
            kst = ZoneInfo("Asia/Seoul") if ZoneInfo else timezone(timedelta(hours=9))
            now_kst = now_utc.astimezone(kst)

            last = user.last_recruit_posted_at
            if last is not None:
                if getattr(last, "tzinfo", None) is None:
                    last = last.replace(tzinfo=timezone.utc)
                last_kst = last.astimezone(kst)
                if last_kst.date() == now_kst.date():
                    raise HTTPException(
                        status_code=400,
                        detail="하루에 한 번만 구인글을 작성할 수 있습니다. 자정 이후 다시 시도해주세요.",
                    )

        # 구인글(post_type=1): 캐시 차감 없이 1유형으로 고정
        card_type = 1

        # 작성시각 갱신
        user.last_recruit_posted_at = now_utc
    else:
        # 광고글(post_type=4): card_type은 항상 1로 고정(프론트 정책과 일치)
        if int(post_type) == 4:
            card_type = 1
        else:
            card_type = body.card_type

    job_industry = body.job_industry
    if int(post_type) == 4:
        job_industry = _normalize_ad_job_industry(body.job_industry)

    post = Community_Post(
        user_id=userId,
        title=body.title,
        content=body.content,
        image_url=body.image_url,
        contract_fee=body.contract_fee,
        workplace_address=body.workplace_address,
        workplace_map_url=body.workplace_map_url,
        business_address=body.business_address,
        business_map_url=body.business_map_url,
        workplace_lat=body.workplace_lat,
        workplace_lng=body.workplace_lng,
        business_lat=body.business_lat,
        business_lng=body.business_lng,
        job_industry=job_industry,
        job_category=body.job_category,
        pay_support=body.pay_support,
        meal_support=body.meal_support,
        house_support=body.house_support,
        company_developer=body.company_developer,
        company_constructor=body.company_constructor,
        company_trustee=body.company_trustee,
        company_agency=body.company_agency,
        agency_call=body.agency_call,
        status=body.status or "published",
        highlight_color=body.highlight_color,
        highlight_content=body.highlight_content,
        total_use=body.total_use,
        branch_use=body.branch_use,
        hq_use=getattr(body, "hq_use", None),
        leader_use=body.leader_use,
        member_use=body.member_use,
        team_use=getattr(body, "team_use", None),
        each_use=getattr(body, "each_use", None),
        total_fee=body.total_fee,
        branch_fee=body.branch_fee,
        hq_fee=getattr(body, "hq_fee", None),
        leader_fee=body.leader_fee,
        member_fee=body.member_fee,
        team_fee=getattr(body, "team_fee", None),
        each_fee=getattr(body, "each_fee", None),
        pay_use=body.pay_use,
        meal_use=body.meal_use,
        house_use=body.house_use,
        pay_sup=body.pay_sup,
        meal_sup=body.meal_sup,
        house_sup=body.house_sup,
        item1_use=body.item1_use,
        item1_type=body.item1_type,
        item1_sup=body.item1_sup,
        item2_use=body.item2_use,
        item2_type=body.item2_type,
        item2_sup=body.item2_sup,
        item3_use=body.item3_use,
        item3_type=body.item3_type,
        item3_sup=body.item3_sup,
        item4_use=body.item4_use,
        item4_type=body.item4_type,
        item4_sup=body.item4_sup,
        agent=body.agent,
        other_role_name=body.other_role_name,
        other_role_fee=body.other_role_fee,
        post_type=post_type,
        card_type=card_type,
    )

    db.add(post)
    db.flush()
    # 카드 타입 롤오버 정책
    if int(post_type) == 1:
        _rollover_recruit_card_types(db)
    elif int(post_type) == 4:
        # 광고글(post_type=4): 카테고리별 최신 5개 published 유지 (초과분은 closed)
        _rollover_ad_card_types(db)
    db.commit()
    db.refresh(post)

    # 글 등록 푸쉬 알림 - 실패해도 글 등록 성공 처리
    try:
        if int(post_type) in (1, 3, 4, 6):
            notify_admin_acknowledged_post(
                db,
                post_id=int(post.id),
                post_type=int(post_type),
                author_username=username,
                post_title=post.title,
                exclude_user_id=int(userId),
                # 문의글(post_type=6)은 owner도 함께 수신하도록 확장(관리자 기준 보완)
                include_owners=(int(post_type) == 6),
            )
        elif int(post_type) == 7:
            # 대행문의(post_type=7): 오너에게만 알림/푸쉬
            notify_owners_post(
                db,
                post_id=int(post.id),
                post_type=int(post_type),
                author_username=username,
                post_title=post.title,
                exclude_user_id=int(userId),
            )
        elif int(post_type) == 5:
            notify_all_push_post(
                db,
                post_id=int(post.id),
                post_type=int(post_type),
                author_username=username,
                post_title=post.title,
            )
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        print("[WARN] post notify(push) failed:", e)

    return PostOut(
        id=post.id,
        author=PostAuthor(id=userId, username=username),
        title=post.title,
        content=post.content,
        image_url=post.image_url,
        created_at=post.created_at,
        contract_fee=post.contract_fee,
        workplace_address=post.workplace_address,
        workplace_map_url=post.workplace_map_url,
        business_address=post.business_address,
        business_map_url=post.business_map_url,
        workplace_lat=post.workplace_lat,
        workplace_lng=post.workplace_lng,
        business_lat=post.business_lat,
        business_lng=post.business_lng,
        job_industry=post.job_industry,
        job_category=post.job_category,
        pay_support=post.pay_support,
        meal_support=post.meal_support,
        house_support=post.house_support,
        company_developer=post.company_developer,
        company_constructor=post.company_constructor,
        company_trustee=post.company_trustee,
        company_agency=post.company_agency,
        agency_call=post.agency_call,
        province=post.province,
        city=post.city,
        status=post.status,
        highlight_color=post.highlight_color,
        highlight_content=post.highlight_content,
        total_use=post.total_use,
        branch_use=post.branch_use,
        hq_use=getattr(post, "hq_use", None),
        leader_use=post.leader_use,
        member_use=post.member_use,
        team_use=getattr(post, "team_use", None),
        each_use=getattr(post, "each_use", None),
        total_fee=post.total_fee,
        branch_fee=post.branch_fee,
        hq_fee=getattr(post, "hq_fee", None),
        leader_fee=post.leader_fee,
        member_fee=post.member_fee,
        team_fee=getattr(post, "team_fee", None),
        each_fee=getattr(post, "each_fee", None),
        pay_use=post.pay_use,
        meal_use=post.meal_use,
        house_use=post.house_use,
        pay_sup=post.pay_sup,
        meal_sup=post.meal_sup,
        house_sup=post.house_sup,
        item1_use=post.item1_use,
        item1_type=post.item1_type,
        item1_sup=post.item1_sup,
        item2_use=post.item2_use,
        item2_type=post.item2_type,
        item2_sup=post.item2_sup,
        item3_use=post.item3_use,
        item3_type=post.item3_type,
        item3_sup=post.item3_sup,
        item4_use=post.item4_use,
        item4_type=post.item4_type,
        item4_sup=post.item4_sup,
        agent=post.agent,
        other_role_name=getattr(post, "other_role_name", None),
        other_role_fee=getattr(post, "other_role_fee", None),
        post_type=post.post_type,
        card_type=post.card_type,
    )


class PostsOut2(BaseModel):
    items: list[PostOut2]
    next_cursor: str | None = None


@app.get("/community/posts/custom", response_model=PostsOut2)
def list_posts_custom_by_user_settings(
    username: Optional[str] = Query(None, description="맞춤조건/좋아요 계산용 유저명"),
    cursor: Optional[str] = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(100, ge=1, le=100),
    status: Optional[str] = Query(None, description="published | closed"),
    db: Session = Depends(get_db),
):
    """
    맞춤현장(유저 설정) 기반 구인글(post_type=1) 목록.

    - (B안) 토큰 인증 제거: username 파라미터로 유저 설정을 조회
    - 필터 기준:
      - community_users.custom_industry_codes: job_industry(문자열/CSV)에 포함되는지 LIKE로 매칭
      - community_users.custom_region_codes:
        - "전체" 포함 시 지역 필터 없음
        - "서울" => province="서울"
        - "서울 강남구" => province="서울" AND city LIKE "%강남구%"
    """
    # 토큰 인증을 제거했으므로, username이 없으면 필터 조건을 알 수 없어 빈 목록 반환
    if not username:
        return PostsOut2(items=[], next_cursor=None)

    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return PostsOut2(items=[], next_cursor=None)

    q = db.query(Community_Post).filter(Community_Post.post_type == 1).order_by(Community_Post.created_at.desc())

    if status in ("published", "closed"):
        q = q.filter(Community_Post.status == status)

    # --- 산업(업종) 필터 ---
    industries = [str(x).strip() for x in (getattr(user, "custom_industry_codes", None) or []) if str(x).strip()]
    if industries and "전체" not in industries:
        q = q.filter(or_(*[Community_Post.job_industry.ilike(f"%{ind}%") for ind in industries]))

    # --- 지역 필터 ---
    regions = [str(x).strip() for x in (getattr(user, "custom_region_codes", None) or []) if str(x).strip()]
    if regions and "전체" not in regions:
        conds = []
        for code in regions:
            parts = code.split()
            if not parts:
                continue
            prov = parts[0]
            city = "전체" if len(parts) == 1 else " ".join(parts[1:]).strip() or "전체"

            if prov == "전체":
                conds = []
                break

            prov_in = Community_Post.province.in_(province_candidates(prov))
            if city == "전체":
                conds.append(prov_in)
            else:
                conds.append(
                    and_(
                        prov_in,
                        or_(
                            Community_Post.city == city,
                            Community_Post.city.like(f"%{city}%"),
                        ),
                    )
                )

        if conds:
            q = q.filter(or_(*conds))

    # --- 모집(역할) 필터 ---
    # 저장 값(대표 5종):
    # - "총괄" => total_use
    # - "본부장" => branch_use(본부장) OR hq_use(본부)
    # - "팀장" => leader_use(팀장) OR team_use(팀)
    # - "팀원" => member_use(팀원) OR each_use(각개)
    # - "기타" => other_role_name 존재
    roles = [str(x).strip() for x in (getattr(user, "custom_role_codes", None) or []) if str(x).strip()]
    if roles:
        role_conds = []
        if "총괄" in roles:
            role_conds.append(Community_Post.total_use.is_(True))
        if "본부장" in roles:
            role_conds.append(or_(Community_Post.branch_use.is_(True), Community_Post.hq_use.is_(True)))
        if "팀장" in roles:
            role_conds.append(or_(Community_Post.leader_use.is_(True), Community_Post.team_use.is_(True)))
        if "팀원" in roles:
            role_conds.append(or_(Community_Post.member_use.is_(True), Community_Post.each_use.is_(True)))
        if "기타" in roles:
            role_conds.append(and_(Community_Post.other_role_name.isnot(None), Community_Post.other_role_name != ""))
        if role_conds:
            q = q.filter(or_(*role_conds))

    if cursor:
        try:
            cur_dt = datetime.fromisoformat(cursor)
            q = q.filter(Community_Post.created_at < cur_dt)
        except Exception:
            pass

    rows = q.limit(limit).all()

    # 좋아요 여부는 username 기준으로 계산
    liked_ids = set()
    if rows and username:
        post_ids = [p.id for p in rows]
        liked_rows = (
            db.query(Post_Like.post_id)
            .filter(Post_Like.username == username, Post_Like.post_id.in_(post_ids))
            .all()
        )
        liked_ids = {pid for (pid,) in liked_rows}

    items = [
        PostOut2.model_validate(p, from_attributes=True).model_copy(update={"liked": (p.id in liked_ids)})
        for p in rows
    ]

    next_cursor = rows[-1].created_at.isoformat() if rows else None
    return PostsOut2(items=items, next_cursor=next_cursor)


@app.get("/community/posts", response_model=PostsOut2)
def list_posts(
    username: Optional[str] = Query(None, description="좋아요 여부 계산용 유저명"),
    cursor: Optional[str] = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(100, ge=1, le=100),
    status: Optional[str] = Query(None, description="published | closed"),
    regions: Optional[str] = Query(None, description="지역 필터(복수): 콤마로 구분. 예) 서울특별시,경기도 수원시"),
    province: Optional[str] = Query(None, description="지역 필터: 시/도"),
    city: Optional[str] = Query(None, description="지역 필터: 시/군/구"),
    db: Session = Depends(get_db),
):
    q = db.query(Community_Post).filter(Community_Post.post_type == 1).order_by(Community_Post.created_at.desc())

    if status in ("published", "closed"):
        q = q.filter(Community_Post.status == status)

    # 지역 필터링 (서버 측)
    # - regions(복수)가 우선
    # - 없으면 기존 province/city 단일 필터 유지
    if regions:
        codes = [x.strip() for x in regions.split(",") if x.strip()]
        if codes and "전체" not in codes:
            conds = []
            for code in codes:
                parts = code.split()
                if not parts:
                    continue
                prov = parts[0]
                c = "전체" if len(parts) == 1 else " ".join(parts[1:]).strip() or "전체"

                if prov == "전체":
                    conds = []
                    break

                prov_in = Community_Post.province.in_(province_candidates(prov))
                if c == "전체":
                    conds.append(prov_in)
                else:
                    conds.append(
                        and_(
                            prov_in,
                            or_(
                                Community_Post.city == c,
                                Community_Post.city.like(f"%{c}%"),
                            ),
                        )
                    )
            if conds:
                q = q.filter(or_(*conds))
    elif province and province != "전체":
        q = q.filter(Community_Post.province.in_(province_candidates(province)))
        if city and city != "전체":
            # city 필터링 (정확히 일치하거나 부분 일치)
            q = q.filter(or_(Community_Post.city == city, Community_Post.city.like(f"%{city}%")))

    if cursor:
        try:
            cur_dt = datetime.fromisoformat(cursor)
            q = q.filter(Community_Post.created_at < cur_dt)
        except Exception:
            pass

    rows = q.limit(limit).all()

    liked_ids = set()
    if username and rows:
        post_ids = [p.id for p in rows]

        liked_rows = (
            db.query(Post_Like.post_id).filter(Post_Like.username == username, Post_Like.post_id.in_(post_ids)).all()
        )
        liked_ids = {pid for (pid,) in liked_rows}

    items = [
        PostOut2(
            id=p.id,
            author=PostAuthor(id=p.author.id, username=p.author.username),
            title=p.title,
            content=p.content,
            image_url=p.image_url,
            created_at=p.created_at,
            contract_fee=p.contract_fee,
            workplace_address=p.workplace_address,
            workplace_map_url=p.workplace_map_url,
            business_address=p.business_address,
            business_map_url=p.business_map_url,
            workplace_lat=p.workplace_lat,
            workplace_lng=p.workplace_lng,
            business_lat=p.business_lat,
            business_lng=p.business_lng,
            job_industry=p.job_industry,
            job_category=p.job_category,
            pay_support=p.pay_support,
            meal_support=p.meal_support,
            house_support=p.house_support,
            company_developer=p.company_developer,
            company_constructor=p.company_constructor,
            company_trustee=p.company_trustee,
            company_agency=p.company_agency,
            agency_call=p.agency_call,
            province=p.province,
            city=p.city,
            status=p.status,
            liked=(p.id in liked_ids),
            highlight_color=p.highlight_color,
            highlight_content=p.highlight_content,
            total_use=p.total_use,
            branch_use=p.branch_use,
            hq_use=getattr(p, "hq_use", None),
            leader_use=p.leader_use,
            member_use=p.member_use,
            team_use=getattr(p, "team_use", None),
            each_use=getattr(p, "each_use", None),
            total_fee=p.total_fee,
            branch_fee=p.branch_fee,
            hq_fee=getattr(p, "hq_fee", None),
            leader_fee=p.leader_fee,
            member_fee=p.member_fee,
            team_fee=getattr(p, "team_fee", None),
            each_fee=getattr(p, "each_fee", None),
            pay_use=p.pay_use,
            meal_use=p.meal_use,
            house_use=p.house_use,
            pay_sup=p.pay_sup,
            meal_sup=p.meal_sup,
            house_sup=p.house_sup,
            item1_use=p.item1_use,
            item1_type=p.item1_type,
            item1_sup=p.item1_sup,
            item2_use=p.item2_use,
            item2_type=p.item2_type,
            item2_sup=p.item2_sup,
            item3_use=p.item3_use,
            item3_type=p.item3_type,
            item3_sup=p.item3_sup,
            item4_use=p.item4_use,
            item4_type=p.item4_type,
            item4_sup=p.item4_sup,
            agent=p.agent,
            other_role_name=getattr(p, "other_role_name", None),
            other_role_fee=getattr(p, "other_role_fee", None),
            post_type=p.post_type,
            card_type=p.card_type,
        )
        for p in rows
    ]

    next_cursor = rows[-1].created_at.isoformat() if rows else None
    return PostsOut2(items=items, next_cursor=next_cursor)


@app.get("/community/posts/search/title", response_model=PostsOut2)
def search_posts_by_title(
    q: str = Query(..., description="검색어(제목 포함)", min_length=1, max_length=80),
    post_type: int = Query(1, description="게시글 타입(기본: 1=현장/구인글)"),
    username: Optional[str] = Query(None, description="좋아요 여부 계산용 유저명(선택)"),
    cursor: Optional[str] = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query("published", description="published | closed (선택)"),
    db: Session = Depends(get_db),
):
    """
    제목 검색(서버 필터).
    - textsearch 화면/관리자 추천현장 검색에서 사용
    - post_type 기본값은 1(현장/구인글)
    """
    keyword = (q or "").strip()
    if not keyword:
        return PostsOut2(items=[], next_cursor=None)

    query = (
        db.query(Community_Post)
        .filter(Community_Post.post_type == int(post_type))
        .order_by(Community_Post.created_at.desc())
    )
    if status in ("published", "closed"):
        query = query.filter(Community_Post.status == status)

    # 제목 부분일치(대소문자 무시)
    query = query.filter(Community_Post.title.ilike(f"%{keyword}%"))

    if cursor:
        try:
            cur_dt = datetime.fromisoformat(cursor)
            query = query.filter(Community_Post.created_at < cur_dt)
        except Exception:
            pass

    rows = query.limit(limit).all()

    liked_ids = set()
    if username and rows:
        post_ids = [p.id for p in rows]
        liked_rows = (
            db.query(Post_Like.post_id)
            .filter(Post_Like.username == username, Post_Like.post_id.in_(post_ids))
            .all()
        )
        liked_ids = {pid for (pid,) in liked_rows}

    items = [
        PostOut2(
            id=p.id,
            author=PostAuthor(id=p.author.id, username=p.author.username),
            title=p.title,
            content=p.content,
            image_url=p.image_url,
            created_at=p.created_at,
            contract_fee=p.contract_fee,
            workplace_address=p.workplace_address,
            workplace_map_url=p.workplace_map_url,
            business_address=p.business_address,
            business_map_url=p.business_map_url,
            workplace_lat=p.workplace_lat,
            workplace_lng=p.workplace_lng,
            business_lat=p.business_lat,
            business_lng=p.business_lng,
            job_industry=p.job_industry,
            job_category=p.job_category,
            pay_support=p.pay_support,
            meal_support=p.meal_support,
            house_support=p.house_support,
            company_developer=p.company_developer,
            company_constructor=p.company_constructor,
            company_trustee=p.company_trustee,
            company_agency=p.company_agency,
            agency_call=p.agency_call,
            province=p.province,
            city=p.city,
            status=p.status,
            liked=(p.id in liked_ids),
            highlight_color=p.highlight_color,
            highlight_content=p.highlight_content,
            total_use=p.total_use,
            branch_use=p.branch_use,
            hq_use=getattr(p, "hq_use", None),
            leader_use=p.leader_use,
            member_use=p.member_use,
            team_use=getattr(p, "team_use", None),
            each_use=getattr(p, "each_use", None),
            total_fee=p.total_fee,
            branch_fee=p.branch_fee,
            hq_fee=getattr(p, "hq_fee", None),
            leader_fee=p.leader_fee,
            member_fee=p.member_fee,
            team_fee=getattr(p, "team_fee", None),
            each_fee=getattr(p, "each_fee", None),
            pay_use=p.pay_use,
            meal_use=p.meal_use,
            house_use=p.house_use,
            pay_sup=p.pay_sup,
            meal_sup=p.meal_sup,
            house_sup=p.house_sup,
            item1_use=p.item1_use,
            item1_type=p.item1_type,
            item1_sup=p.item1_sup,
            item2_use=p.item2_use,
            item2_type=p.item2_type,
            item2_sup=p.item2_sup,
            item3_use=p.item3_use,
            item3_type=p.item3_type,
            item3_sup=p.item3_sup,
            item4_use=p.item4_use,
            item4_type=p.item4_type,
            item4_sup=p.item4_sup,
            agent=p.agent,
            other_role_name=getattr(p, "other_role_name", None),
            other_role_fee=getattr(p, "other_role_fee", None),
            post_type=p.post_type,
            card_type=p.card_type,
        )
        for p in rows
    ]

    next_cursor = rows[-1].created_at.isoformat() if rows else None
    return PostsOut2(items=items, next_cursor=next_cursor)


@app.get("/community/posts/type/{post_type}", response_model=PostsOut2)
def list_posts_plus(
    post_type: int,
    username: Optional[str] = Query(None, description="좋아요 여부 계산용 유저명"),
    cursor: Optional[str] = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(100, ge=1, le=100),
    status: Optional[str] = Query(None, description="published | closed"),
    regions: Optional[str] = Query(None, description="지역 필터(복수): 콤마로 구분. 예) 서울특별시,경기도 수원시"),
    province: Optional[str] = Query(None, description="지역 필터: 시/도"),
    city: Optional[str] = Query(None, description="지역 필터: 시/군/구"),
    db: Session = Depends(get_db),
):
    q = db.query(Community_Post).filter(Community_Post.post_type == post_type).order_by(Community_Post.created_at.desc())

    if status in ("published", "closed"):
        q = q.filter(Community_Post.status == status)

    # 지역 필터링 (서버 측)
    if regions:
        codes = [x.strip() for x in regions.split(",") if x.strip()]
        if codes and "전체" not in codes:
            conds = []
            for code in codes:
                parts = code.split()
                if not parts:
                    continue
                prov = parts[0]
                c = "전체" if len(parts) == 1 else " ".join(parts[1:]).strip() or "전체"

                if prov == "전체":
                    conds = []
                    break

                prov_in = Community_Post.province.in_(province_candidates(prov))
                if c == "전체":
                    conds.append(prov_in)
                else:
                    conds.append(
                        and_(
                            prov_in,
                            or_(
                                Community_Post.city == c,
                                Community_Post.city.like(f"%{c}%"),
                            ),
                        )
                    )
            if conds:
                q = q.filter(or_(*conds))
    elif province and province != "전체":
        q = q.filter(Community_Post.province.in_(province_candidates(province)))
        if city and city != "전체":
            # city 필터링 (정확히 일치하거나 부분 일치)
            q = q.filter(or_(Community_Post.city == city, Community_Post.city.like(f"%{city}%")))

    if cursor:
        try:
            cur_dt = datetime.fromisoformat(cursor)
            q = q.filter(Community_Post.created_at < cur_dt)
        except Exception:
            pass

    rows = q.limit(limit).all()

    liked_ids = set()
    if username and rows:
        post_ids = [p.id for p in rows]

        liked_rows = (
            db.query(Post_Like.post_id).filter(Post_Like.username == username, Post_Like.post_id.in_(post_ids)).all()
        )
        liked_ids = {pid for (pid,) in liked_rows}

    items = [
        PostOut2(
            id=p.id,
            author=PostAuthor(id=p.author.id, username=p.author.username),
            title=p.title,
            content=p.content,
            image_url=p.image_url,
            created_at=p.created_at,
            contract_fee=p.contract_fee,
            workplace_address=p.workplace_address,
            workplace_map_url=p.workplace_map_url,
            business_address=p.business_address,
            business_map_url=p.business_map_url,
            workplace_lat=p.workplace_lat,
            workplace_lng=p.workplace_lng,
            business_lat=p.business_lat,
            business_lng=p.business_lng,
            job_industry=p.job_industry,
            job_category=p.job_category,
            pay_support=p.pay_support,
            meal_support=p.meal_support,
            house_support=p.house_support,
            company_developer=p.company_developer,
            company_constructor=p.company_constructor,
            company_trustee=p.company_trustee,
            company_agency=p.company_agency,
            agency_call=p.agency_call,
            province=p.province,
            city=p.city,
            status=p.status,
            liked=(p.id in liked_ids),
            highlight_color=p.highlight_color,
            highlight_content=p.highlight_content,
            total_use=p.total_use,
            branch_use=p.branch_use,
            hq_use=getattr(p, "hq_use", None),
            leader_use=p.leader_use,
            member_use=p.member_use,
            team_use=getattr(p, "team_use", None),
            each_use=getattr(p, "each_use", None),
            total_fee=p.total_fee,
            branch_fee=p.branch_fee,
            hq_fee=getattr(p, "hq_fee", None),
            leader_fee=p.leader_fee,
            member_fee=p.member_fee,
            team_fee=getattr(p, "team_fee", None),
            each_fee=getattr(p, "each_fee", None),
            pay_use=p.pay_use,
            meal_use=p.meal_use,
            house_use=p.house_use,
            pay_sup=p.pay_sup,
            meal_sup=p.meal_sup,
            house_sup=p.house_sup,
            item1_use=p.item1_use,
            item1_type=p.item1_type,
            item1_sup=p.item1_sup,
            item2_use=p.item2_use,
            item2_type=p.item2_type,
            item2_sup=p.item2_sup,
            item3_use=p.item3_use,
            item3_type=p.item3_type,
            item3_sup=p.item3_sup,
            item4_use=p.item4_use,
            item4_type=p.item4_type,
            item4_sup=p.item4_sup,
            agent=p.agent,
            other_role_name=getattr(p, "other_role_name", None),
            other_role_fee=getattr(p, "other_role_fee", None),
            post_type=p.post_type,
            card_type=p.card_type,
        )
        for p in rows
    ]

    next_cursor = rows[-1].created_at.isoformat() if rows else None
    return PostsOut2(items=items, next_cursor=next_cursor)


@app.get("/community/posts/type/{post_type}/my/{username}", response_model=PostsOut2)
def list_my_posts_by_type(
    post_type: int,
    username: str,
    cursor: Optional[str] = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(1000, ge=1, le=1000),
    status: Optional[str] = Query(None, description="published | closed"),
    db: Session = Depends(get_db),
):
    user_id = get_user_id_by_username(db, username)
    q = db.query(Community_Post).filter(Community_Post.post_type == post_type).order_by(Community_Post.created_at.desc())

    super_users = {1, 10, 13, 20, 21, 22, 23, 24, 25, 26, 27, 28}

    if user_id not in super_users:
        q = q.filter(Community_Post.user_id == user_id)

    if status in ("published", "closed"):
        q = q.filter(Community_Post.status == status)

    if cursor:
        q = q.filter(Community_Post.created_at < cursor)

    rows = q.limit(limit).all()

    liked_ids = set()
    if rows:
        post_ids = [p.id for p in rows]
        liked_rows = (
            db.query(Post_Like.post_id).filter(Post_Like.username == username, Post_Like.post_id.in_(post_ids)).all()
        )
        liked_ids = {pid for (pid,) in liked_rows}

    items = [
        PostOut2(
            id=p.id,
            author=PostAuthor(id=p.author.id, username=p.author.username),
            title=p.title,
            content=p.content,
            image_url=p.image_url,
            created_at=p.created_at,
            contract_fee=p.contract_fee,
            workplace_address=p.workplace_address,
            workplace_map_url=p.workplace_map_url,
            business_address=p.business_address,
            business_map_url=p.business_map_url,
            workplace_lat=p.workplace_lat,
            workplace_lng=p.workplace_lng,
            business_lat=p.business_lat,
            business_lng=p.business_lng,
            job_industry=p.job_industry,
            job_category=p.job_category,
            pay_support=p.pay_support,
            meal_support=p.meal_support,
            house_support=p.house_support,
            company_developer=p.company_developer,
            company_constructor=p.company_constructor,
            company_trustee=p.company_trustee,
            company_agency=p.company_agency,
            agency_call=p.agency_call,
            province=p.province,
            city=p.city,
            status=p.status,
            liked=(p.id in liked_ids),
            highlight_color=p.highlight_color,
            highlight_content=p.highlight_content,
            total_use=p.total_use,
            branch_use=p.branch_use,
            hq_use=getattr(p, "hq_use", None),
            leader_use=p.leader_use,
            member_use=p.member_use,
            team_use=getattr(p, "team_use", None),
            each_use=getattr(p, "each_use", None),
            total_fee=p.total_fee,
            branch_fee=p.branch_fee,
            hq_fee=getattr(p, "hq_fee", None),
            leader_fee=p.leader_fee,
            member_fee=p.member_fee,
            team_fee=getattr(p, "team_fee", None),
            each_fee=getattr(p, "each_fee", None),
            pay_use=p.pay_use,
            meal_use=p.meal_use,
            house_use=p.house_use,
            pay_sup=p.pay_sup,
            meal_sup=p.meal_sup,
            house_sup=p.house_sup,
            item1_use=p.item1_use,
            item1_type=p.item1_type,
            item1_sup=p.item1_sup,
            item2_use=p.item2_use,
            item2_type=p.item2_type,
            item2_sup=p.item2_sup,
            item3_use=p.item3_use,
            item3_type=p.item3_type,
            item3_sup=p.item3_sup,
            item4_use=p.item4_use,
            item4_type=p.item4_type,
            item4_sup=p.item4_sup,
            agent=p.agent,
            other_role_name=getattr(p, "other_role_name", None),
            other_role_fee=getattr(p, "other_role_fee", None),
            post_type=p.post_type,
            card_type=p.card_type,
        )
        for p in rows
    ]

    next_cursor = rows[-1].created_at.isoformat() if rows else None
    return PostsOut2(items=items, next_cursor=next_cursor)


@app.get("/community/posts/{post_id}", response_model=PostOut)
def get_post(post_id: int, db: Session = Depends(get_db)):
    p = db.query(Community_Post).filter(Community_Post.id == post_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Post not found")
    return PostOut(
        id=p.id,
        author=PostAuthor(id=p.author.id, username=p.author.username),
        title=p.title,
        content=p.content,
        image_url=p.image_url,
        created_at=p.created_at,
        contract_fee=p.contract_fee,
        workplace_address=p.workplace_address,
        workplace_map_url=p.workplace_map_url,
        business_address=p.business_address,
        business_map_url=p.business_map_url,
        workplace_lat=p.workplace_lat,
        workplace_lng=p.workplace_lng,
        business_lat=p.business_lat,
        business_lng=p.business_lng,
        job_industry=p.job_industry,
        job_category=p.job_category,
        pay_support=p.pay_support,
        meal_support=p.meal_support,
        house_support=p.house_support,
        company_developer=p.company_developer,
        company_constructor=p.company_constructor,
        company_trustee=p.company_trustee,
        company_agency=p.company_agency,
        agency_call=p.agency_call,
        province=p.province,
        city=p.city,
        status=p.status,
        highlight_color=p.highlight_color,
        highlight_content=p.highlight_content,
        total_use=p.total_use,
        branch_use=p.branch_use,
        hq_use=getattr(p, "hq_use", None),
        leader_use=p.leader_use,
        member_use=p.member_use,
        team_use=getattr(p, "team_use", None),
        each_use=getattr(p, "each_use", None),
        total_fee=p.total_fee,
        branch_fee=p.branch_fee,
        hq_fee=getattr(p, "hq_fee", None),
        leader_fee=p.leader_fee,
        member_fee=p.member_fee,
        team_fee=getattr(p, "team_fee", None),
        each_fee=getattr(p, "each_fee", None),
        pay_use=p.pay_use,
        meal_use=p.meal_use,
        house_use=p.house_use,
        pay_sup=p.pay_sup,
        meal_sup=p.meal_sup,
        house_sup=p.house_sup,
        item1_use=p.item1_use,
        item1_type=p.item1_type,
        item1_sup=p.item1_sup,
        item2_use=p.item2_use,
        item2_type=p.item2_type,
        item2_sup=p.item2_sup,
        item3_use=p.item3_use,
        item3_type=p.item3_type,
        item3_sup=p.item3_sup,
        item4_use=p.item4_use,
        item4_type=p.item4_type,
        item4_sup=p.item4_sup,
        agent=p.agent,
        other_role_name=getattr(p, "other_role_name", None),
        other_role_fee=getattr(p, "other_role_fee", None),
        post_type=p.post_type,
        card_type=p.card_type,
    )


@app.post("/community/posts/{post_id}/recreate/{username}", response_model=PostOut)
def recreate_recruit_post(
    post_id: int,
    username: str,
    db: Session = Depends(get_db),
):
    """
    구인글(post_type=1) 재등록(복제 생성).
    - 본인 글만 가능
    - 구인글 작성 제한(제재/하루1회) 정책은 create_post와 동일 적용
    - 새 글은 status="published", card_type=1 로 생성
    """
    src = db.query(Community_Post).filter(Community_Post.id == post_id).first()
    if not src:
        raise HTTPException(status_code=404, detail="Post not found")

    # 유저 row lock으로 포인트/작성제한/생성 원자성 보장
    user = db.query(Community_User).filter(Community_User.username == username).with_for_update().first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid username")

    userId = int(user.id)
    if int(getattr(src, "user_id", 0) or 0) != userId:
        raise HTTPException(status_code=403, detail="본인 글만 재등록할 수 있습니다.")

    try:
        pt = int(getattr(src, "post_type", 0) or 0)
    except Exception:
        pt = 0
    if pt != 1:
        raise HTTPException(status_code=400, detail="구인글만 재등록할 수 있습니다.")

    is_admin_ack = bool(getattr(user, "admin_acknowledged", False))
    now_utc = datetime.now(timezone.utc)

    # admin_acknowledged=True 이면 구인글 작성 제한(제재/일일작성)을 우회하여 무제한 작성 가능
    if not is_admin_ack:
        _enforce_user_post_restriction(db, userId, 1)

        kst = ZoneInfo("Asia/Seoul") if ZoneInfo else timezone(timedelta(hours=9))
        now_kst = now_utc.astimezone(kst)
        last = getattr(user, "last_recruit_posted_at", None)
        if last is not None:
            if getattr(last, "tzinfo", None) is None:
                last = last.replace(tzinfo=timezone.utc)
            last_kst = last.astimezone(kst)
            if last_kst.date() == now_kst.date():
                raise HTTPException(
                    status_code=400,
                    detail="하루에 한 번만 구인글을 작성할 수 있습니다. 자정 이후 다시 시도해주세요.",
                )

    # ---- 재등록(복제 생성) ----
    post = Community_Post(
        user_id=userId,
        title=getattr(src, "title", None),
        content=getattr(src, "content", None),
        image_url=getattr(src, "image_url", None),
        contract_fee=getattr(src, "contract_fee", None),
        workplace_address=getattr(src, "workplace_address", None),
        workplace_map_url=getattr(src, "workplace_map_url", None),
        business_address=getattr(src, "business_address", None),
        business_map_url=getattr(src, "business_map_url", None),
        workplace_lat=getattr(src, "workplace_lat", None),
        workplace_lng=getattr(src, "workplace_lng", None),
        business_lat=getattr(src, "business_lat", None),
        business_lng=getattr(src, "business_lng", None),
        job_industry=getattr(src, "job_industry", None),
        job_category=getattr(src, "job_category", None),
        province=getattr(src, "province", None),
        city=getattr(src, "city", None),
        pay_support=getattr(src, "pay_support", None),
        meal_support=getattr(src, "meal_support", None),
        house_support=getattr(src, "house_support", None),
        company_developer=getattr(src, "company_developer", None),
        company_constructor=getattr(src, "company_constructor", None),
        company_trustee=getattr(src, "company_trustee", None),
        company_agency=getattr(src, "company_agency", None),
        agency_call=getattr(src, "agency_call", None),
        status="published",
        highlight_color=getattr(src, "highlight_color", None),
        highlight_content=getattr(src, "highlight_content", None),
        total_use=getattr(src, "total_use", None),
        branch_use=getattr(src, "branch_use", None),
        hq_use=getattr(src, "hq_use", None),
        leader_use=getattr(src, "leader_use", None),
        member_use=getattr(src, "member_use", None),
        team_use=getattr(src, "team_use", None),
        each_use=getattr(src, "each_use", None),
        total_fee=getattr(src, "total_fee", None),
        branch_fee=getattr(src, "branch_fee", None),
        hq_fee=getattr(src, "hq_fee", None),
        leader_fee=getattr(src, "leader_fee", None),
        member_fee=getattr(src, "member_fee", None),
        team_fee=getattr(src, "team_fee", None),
        each_fee=getattr(src, "each_fee", None),
        pay_use=getattr(src, "pay_use", None),
        meal_use=getattr(src, "meal_use", None),
        house_use=getattr(src, "house_use", None),
        pay_sup=getattr(src, "pay_sup", None),
        meal_sup=getattr(src, "meal_sup", None),
        house_sup=getattr(src, "house_sup", None),
        item1_use=getattr(src, "item1_use", None),
        item1_type=getattr(src, "item1_type", None),
        item1_sup=getattr(src, "item1_sup", None),
        item2_use=getattr(src, "item2_use", None),
        item2_type=getattr(src, "item2_type", None),
        item2_sup=getattr(src, "item2_sup", None),
        item3_use=getattr(src, "item3_use", None),
        item3_type=getattr(src, "item3_type", None),
        item3_sup=getattr(src, "item3_sup", None),
        item4_use=getattr(src, "item4_use", None),
        item4_type=getattr(src, "item4_type", None),
        item4_sup=getattr(src, "item4_sup", None),
        agent=getattr(src, "agent", None),
        other_role_name=getattr(src, "other_role_name", None),
        other_role_fee=getattr(src, "other_role_fee", None),
        post_type=1,
        card_type=1,
    )

    # ---- 구인글 작성 시각 갱신(하루 1회 제한/통계용) ----
    user.last_recruit_posted_at = now_utc

    db.add(post)
    db.flush()
    _rollover_recruit_card_types(db)
    db.commit()
    db.refresh(post)

    # 푸쉬 알림(관리자 대상) - 실패해도 글 등록 성공 처리
    try:
        notify_admin_acknowledged_post(
            db,
            post_id=int(post.id),
            post_type=1,
            author_username=username,
            post_title=post.title,
            exclude_user_id=userId,
        )
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        print("[WARN] notify_admin_acknowledged_post failed:", e)

    return PostOut(
        id=post.id,
        author=PostAuthor(id=post.author.id, username=post.author.username),
        title=post.title,
        content=post.content,
        image_url=post.image_url,
        created_at=post.created_at,
        contract_fee=post.contract_fee,
        workplace_address=post.workplace_address,
        workplace_map_url=post.workplace_map_url,
        business_address=post.business_address,
        business_map_url=post.business_map_url,
        workplace_lat=post.workplace_lat,
        workplace_lng=post.workplace_lng,
        business_lat=post.business_lat,
        business_lng=post.business_lng,
        job_industry=post.job_industry,
        job_category=post.job_category,
        pay_support=post.pay_support,
        meal_support=post.meal_support,
        house_support=post.house_support,
        company_developer=post.company_developer,
        company_constructor=post.company_constructor,
        company_trustee=post.company_trustee,
        company_agency=post.company_agency,
        agency_call=post.agency_call,
        province=post.province,
        city=post.city,
        status=post.status,
        highlight_color=post.highlight_color,
        highlight_content=post.highlight_content,
        total_use=post.total_use,
        branch_use=post.branch_use,
        hq_use=getattr(post, "hq_use", None),
        leader_use=post.leader_use,
        member_use=post.member_use,
        team_use=getattr(post, "team_use", None),
        each_use=getattr(post, "each_use", None),
        total_fee=post.total_fee,
        branch_fee=post.branch_fee,
        hq_fee=getattr(post, "hq_fee", None),
        leader_fee=post.leader_fee,
        member_fee=post.member_fee,
        team_fee=getattr(post, "team_fee", None),
        each_fee=getattr(post, "each_fee", None),
        pay_use=post.pay_use,
        meal_use=post.meal_use,
        house_use=post.house_use,
        pay_sup=post.pay_sup,
        meal_sup=post.meal_sup,
        house_sup=post.house_sup,
        item1_use=post.item1_use,
        item1_type=post.item1_type,
        item1_sup=post.item1_sup,
        item2_use=post.item2_use,
        item2_type=post.item2_type,
        item2_sup=post.item2_sup,
        item3_use=post.item3_use,
        item3_type=post.item3_type,
        item3_sup=post.item3_sup,
        item4_use=post.item4_use,
        item4_type=post.item4_type,
        item4_sup=post.item4_sup,
        agent=post.agent,
        other_role_name=getattr(post, "other_role_name", None),
        other_role_fee=getattr(post, "other_role_fee", None),
        post_type=post.post_type,
        card_type=post.card_type,
    )


@app.put("/community/posts/{post_id}", response_model=PostOut)
def update_post(
    post_id: int,
    body: PostUpdate,
    db: Session = Depends(get_db),
):
    post = db.query(Community_Post).filter(Community_Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")

    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(post, key, value)

    db.flush()
    # post_type=1(구인글): 마감/개시(status 변경) 포함, 항상 30/40 유지 롤오버 적용
    # post_type=4(광고글): 카테고리(job_industry)별 card_type=1 최대 5개 유지 (초과분은 2로 강등)
    try:
        pt = int(getattr(post, "post_type", 0) or 0)
    except Exception:
        pt = 0
    if pt == 1:
        _rollover_recruit_card_types(db)
    if pt == 4:
        # 광고글 정책: 카테고리 정규화
        post.job_industry = _normalize_ad_job_industry(getattr(post, "job_industry", None))
        db.add(post)
        _rollover_ad_card_types(db)

    db.commit()
    db.refresh(post)

    return PostOut(
        id=post.id,
        author=PostAuthor(id=post.author.id, username=post.author.username),
        title=post.title,
        content=post.content,
        image_url=post.image_url,
        created_at=post.created_at,
        contract_fee=post.contract_fee,
        workplace_address=post.workplace_address,
        workplace_map_url=post.workplace_map_url,
        business_address=post.business_address,
        business_map_url=post.business_map_url,
        workplace_lat=post.workplace_lat,
        workplace_lng=post.workplace_lng,
        business_lat=post.business_lat,
        business_lng=post.business_lng,
        job_industry=post.job_industry,
        job_category=post.job_category,
        pay_support=post.pay_support,
        meal_support=post.meal_support,
        house_support=post.house_support,
        company_developer=post.company_developer,
        company_constructor=post.company_constructor,
        company_trustee=post.company_trustee,
        company_agency=post.company_agency,
        agency_call=post.agency_call,
        province=post.province,
        city=post.city,
        status=post.status,
        highlight_color=post.highlight_color,
        highlight_content=post.highlight_content,
        total_use=post.total_use,
        branch_use=post.branch_use,
        hq_use=getattr(post, "hq_use", None),
        leader_use=post.leader_use,
        member_use=post.member_use,
        team_use=getattr(post, "team_use", None),
        each_use=getattr(post, "each_use", None),
        total_fee=post.total_fee,
        branch_fee=post.branch_fee,
        hq_fee=getattr(post, "hq_fee", None),
        leader_fee=post.leader_fee,
        member_fee=post.member_fee,
        team_fee=getattr(post, "team_fee", None),
        each_fee=getattr(post, "each_fee", None),
        pay_use=post.pay_use,
        meal_use=post.meal_use,
        house_use=post.house_use,
        pay_sup=post.pay_sup,
        meal_sup=post.meal_sup,
        house_sup=post.house_sup,
        item1_use=post.item1_use,
        item1_type=post.item1_type,
        item1_sup=post.item1_sup,
        item2_use=post.item2_use,
        item2_type=post.item2_type,
        item2_sup=post.item2_sup,
        item3_use=post.item3_use,
        item3_type=post.item3_type,
        item3_sup=post.item3_sup,
        item4_use=post.item4_use,
        item4_type=post.item4_type,
        item4_sup=post.item4_sup,
        agent=post.agent,
        other_role_name=getattr(post, "other_role_name", None),
        other_role_fee=getattr(post, "other_role_fee", None),
        post_type=post.post_type,
        card_type=post.card_type,
    )


@app.delete("/community/posts/{post_id}")
def delete_post(
    post_id: int,
    db: Session = Depends(get_db),
):
    post = db.query(Community_Post).filter(Community_Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="게시글을 찾을 수 없습니다.")

    # 삭제 후 post_type=1 카드 정책(30/40 유지)을 다시 맞추기 위해 값 보관
    try:
        pt = int(getattr(post, "post_type", 0) or 0)
    except Exception:
        pt = 0

    db.delete(post)
    db.flush()
    if pt == 1:
        _rollover_recruit_card_types(db)
    db.commit()
    return {"ok": True, "message": "삭제되었습니다."}


@app.post(
    "/community/posts/{post_id}/comments/{username}",
    response_model=CommentOut,
    status_code=status.HTTP_201_CREATED,
)
def create_comment(
    username: str,
    post_id: int,
    payload: CommentCreate,
    db: Session = Depends(get_db),
):
    user_id = db.query(Community_User.id).filter(Community_User.username == username).scalar()
    if user_id is None:
        raise HTTPException(status_code=404, detail="User not found")

    parent_id = payload.parent_id
    if parent_id is not None:
        parent = (
            db.query(Community_Comment)
            .filter(Community_Comment.id == parent_id, Community_Comment.post_id == post_id)
            .first()
        )
        if parent is None:
            raise HTTPException(status_code=400, detail="Invalid parent comment")

    comment = Community_Comment(
        post_id=post_id,
        user_id=user_id,
        username=username,
        content=payload.content,
        parent_id=parent_id,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


@app.get("/community/posts/{post_id}/comments", response_model=CommentListOut)
def list_comments(
    post_id: int,
    cursor: Optional[str] = Query(None, description="ISO8601 created_at 커서"),
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
):
    q = db.query(Community_Comment).filter(Community_Comment.post_id == post_id)

    if cursor:
        try:
            dt = datetime.fromisoformat(cursor)
            q = q.filter(Community_Comment.created_at < dt)
        except Exception:
            pass

    rows = q.order_by(Community_Comment.created_at.desc(), Community_Comment.id.desc()).limit(limit + 1).all()

    items = rows[:limit]
    next_cur = items[-1].created_at.isoformat() if len(rows) > limit else None

    return CommentListOut(items=items, next_cursor=next_cur)


class CommentUpdate(BaseModel):
    content: str = Field(min_length=1, max_length=2000)


@app.put("/community/comments/{comment_id}/{username}", response_model=CommentOut)
def update_comment(
    comment_id: int,
    username: str,
    payload: CommentUpdate,
    db: Session = Depends(get_db),
):
    comment = db.query(Community_Comment).filter(Community_Comment.id == comment_id).first()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    if comment.username != username:
        raise HTTPException(status_code=403, detail="No permission to edit this comment")

    if comment.is_deleted:
        raise HTTPException(status_code=400, detail="Already deleted comment")

    comment.content = payload.content
    db.commit()
    db.refresh(comment)
    return comment


@app.delete("/community/comments/{comment_id}/{username}", status_code=status.HTTP_204_NO_CONTENT)
def delete_comment(
    comment_id: int,
    username: str,
    db: Session = Depends(get_db),
):
    comment = db.query(Community_Comment).filter(Community_Comment.id == comment_id).first()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    if comment.username != username:
        raise HTTPException(status_code=403, detail="No permission to delete this comment")

    if comment.is_deleted:
        return

    comment.is_deleted = True
    comment.deleted_at = datetime.now(timezone.utc)
    comment.content = "[삭제된 댓글입니다.]"
    db.commit()


@app.post("/community/posts/{post_id}/like/{username}")
async def like_post(
    post_id: int,
    username: str,
    db: Session = Depends(get_db),
):
    isUsername = db.execute(select(Community_User).where(Community_User.username == username)).scalar()
    if not isUsername:
        raise HTTPException(status_code=400, detail="none username")

    exists = db.execute(
        select(Post_Like).where(Post_Like.username == username, Post_Like.post_id == post_id)
    ).scalar()
    if exists:
        raise HTTPException(status_code=400, detail="already row")

    db.add(Post_Like(username=username, post_id=post_id))
    db.commit()
    return {"ok": True}


@app.delete("/community/posts/{post_id}/like/{username}")
async def unlike_post(
    post_id: int,
    username: str,
    db: Session = Depends(get_db),
):
    isUsername = db.execute(select(Community_User).where(Community_User.username == username)).scalar()
    if not isUsername:
        raise HTTPException(status_code=400, detail="none username")

    isRow = db.execute(
        select(Post_Like).where(Post_Like.username == username, Post_Like.post_id == post_id)
    ).scalars().first()
    if not isRow:
        raise HTTPException(status_code=400, detail="not row")

    db.delete(isRow)
    db.commit()
    return {"ok": True}


@app.get("/community/posts/liked/{username}")
async def get_liked_posts(
    username: str,
    cursor: Optional[str] = None,
    limit: int = 20,
    db: Session = Depends(get_db),
):
    isUsername = db.execute(select(Community_User).where(Community_User.username == username)).scalar()
    if not isUsername:
        raise HTTPException(status_code=404, detail="username not found")

    stmt = (
        select(Community_Post, Post_Like.created_at, Post_Like.post_id)
        .join(Post_Like, Post_Like.post_id == Community_Post.id)
        .where(Post_Like.username == username)
        .order_by(Post_Like.created_at.desc(), Post_Like.post_id.desc())
        .limit(limit)
    )

    if cursor:
        try:
            dt_str, pid_str = cursor.split("__", 1)
            cur_dt = datetime.fromisoformat(dt_str)
            cur_id = int(pid_str)
            if cur_dt.tzinfo is None:
                cur_dt = cur_dt.replace(tzinfo=timezone.utc)
            stmt = stmt.where(
                or_(
                    Post_Like.created_at < cur_dt,
                    and_(
                        Post_Like.created_at == cur_dt,
                        Post_Like.post_id < cur_id,
                    ),
                )
            )
        except Exception:
            raise HTTPException(status_code=400, detail="invalid cursor format")

    result = db.execute(stmt).all()
    rows = [r[0] for r in result]

    next_cursor = None
    if result:
        last_dt, last_pid = result[-1][1], result[-1][2]
        next_cursor = f"{last_dt.isoformat()}__{last_pid}"

    posts: List[PostOut] = [
        PostOut2.model_validate(p, from_attributes=True).model_copy(update={"liked": True}) for p in rows
    ]

    return {"items": posts, "next_cursor": next_cursor}

