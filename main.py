import os
import calendar
from datetime import datetime, timedelta, timezone, date
try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore
from fastapi import FastAPI, Depends, HTTPException, status, Request, Header, Query, Body
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from database import SessionLocal, engine
import models
from models import Base, RuntimeRecord, User, Recode, RangeSummaryOut, PurchaseVerifyIn, SubscriptionStatusOut, Community_User, Community_User_Restriction, Community_Phone_Verification, Phone, Community_Post, Community_Comment, Post_Like, Notification, Referral, Point, Cash, Payment
import hashlib
import jwt 
from sqlalchemy import func ,select, or_, and_, text
from google_play import get_service, PACKAGE_NAME
import crud
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import base64, json
from googleapiclient.errors import HttpError
from typing import Optional, List, Literal
import uuid
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import re
import requests
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None
import secrets
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
import openpyxl, tempfile
from starlette.background import BackgroundTask
from rss_service import fetch_rss_and_save, parse_pubdate
Base.metadata.create_all(bind=engine)
app = FastAPI()
bearer = HTTPBearer(auto_error=True)

# .env 로드(로컬/개발 편의). 운영 환경에서는 플랫폼의 환경변수 주입을 권장.
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
SECRET_RSS_TOKEN = "rss-secret-token"

# -------------------- Kakao (recode: geocode + route distance) --------------------
# 역지오코딩: Kakao Local REST API Key
KAKAO_REST_API_KEY = os.getenv("KAKAO_REST_API_KEY", "").strip()
# 도로거리: Kakao Mobility(Navi) API Key (프로젝트에 따라 REST 키와 동일할 수 있음)
KAKAO_MOBILITY_API_KEY = os.getenv("KAKAO_MOBILITY_API_KEY", "").strip() or KAKAO_REST_API_KEY

# -------------------- Community Post card_type rollover --------------------
# 요구사항:
# - 구인글(post_type=1)은 write.tsx에서 항상 card_type=1로 등록됨
# - 서버에서 card_type=1 글이 30개 초과 시: 가장 오래된 1유형을 2유형으로 변경
# - 서버에서 card_type=2 글이 70개 초과 시: 가장 오래된 2유형을 3유형으로 변경
CARD1_MAX = 30
CARD2_MAX = 70
AD_CARD1_MAX = 5

GRADE_REWARD_BY_GRADE: dict[int, int] = {
    # 등급 달성 보상 포인트(1회성)
    # -1: 일반회원(보상 없음)
    0: 50_000,      # 아마추어
    1: 100_000,     # 세미프로
    2: 200_000,     # 프로
    3: 500_000,     # 마스터
    4: 1_000_000,   # 레전드
}

def _grade_from_referral_count(referral_count: int) -> int:
    """
    추천인 수 기준 user_grade 자동 등업.
    user_grade:
      -1: 일반회원(기본)
       0: 아마추어(5명 이상)
       1: 세미프로(10명 이상)
       2: 프로(20명 이상)
       3: 마스터(50명 이상)
       4: 레전드(100명 이상)
    """
    c = int(referral_count or 0)
    if c >= 100:
        return 4
    if c >= 50:
        return 3
    if c >= 20:
        return 2
    if c >= 10:
        return 1
    if c >= 5:
        return 0
    return -1

def _grant_user_grade_reward_if_needed(db: Session, user: Community_User, grade: int) -> int:
    """
    등급 달성 보상 포인트를 1회만 지급.
    - 이미 지급된 경우: 0 반환
    - 지급 시: 지급 금액 반환 + point_balance/원장(Point) 반영
    """
    g = int(grade or 0)
    amount = int(GRADE_REWARD_BY_GRADE.get(g, 0) or 0)
    # 0(아마추어)부터 보상 지급 대상. 음수 등급은 보상 없음.
    if g < 0 or amount <= 0:
        return 0

    reason = f"user_grade_reward_{g}"
    already = (
        db.query(Point.id)
        .filter(Point.user_id == user.id, Point.reason == reason)
        .first()
        is not None
    )
    if already:
        return 0

    user.point_balance = int(getattr(user, "point_balance", 0) or 0) + amount
    db.add(Point(user_id=user.id, reason=reason, amount=amount))
    return amount

def _apply_user_grade_upgrade(db: Session, user: Community_User, referral_count: int) -> bool:
    """
    추천인 수 기반 user_grade 동기화 + 달성 보너스 지급(원장/잔액 반영).
    - 등급은 referral_count 기준으로 항상 동기화(다운그레이드 포함)
    - 보상은 등급이 올라갈 때만(중간 등급 포함) 1회성으로 지급
    Returns: 변경 여부(등급이 실제로 변경됐는지)
    """
    target = _grade_from_referral_count(referral_count)
    current = int(getattr(user, "user_grade", -1) or -1)
    if target == current:
        return False

    # 등급이 올라가는 경우에만(예: -1 -> 0, 1 -> 3) 중간 등급 보너스도 누락 없이 지급
    if target > current:
        for g in range(current + 1, target + 1):
            _grant_user_grade_reward_if_needed(db, user, g)

    user.user_grade = target
    db.add(user)
    return True

def _rollover_recruit_card_types(db: Session) -> None:
    """
    구인글(post_type=1) 카드 타입을 개수 제한에 맞춰 롤오버합니다.
    - card_type=1 -> 2 (30개 초과분을 오래된 순으로)
    - card_type=2 -> 3 (70개 초과분을 오래된 순으로)
    - card_type=2 -> 1 (card_type=1이 30개 미만이면, 가장 최신 2유형을 1유형으로 승격)
    - card_type=3 -> 2 (card_type=2가 70개 미만이면, 가장 최신 3유형을 2유형으로 승격)
    같은 트랜잭션 안에서 호출되어야 합니다.
    """
    # 1유형: 30개 유지
    while True:
        c1 = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 1,
            )
            .scalar()
            or 0
        )
        if c1 <= CARD1_MAX:
            break

        oldest1 = (
            db.query(Community_Post)
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 1,
            )
            .order_by(Community_Post.created_at.asc(), Community_Post.id.asc())
            # Community_Post.author 가 lazy="joined"라 LEFT OUTER JOIN이 붙음.
            # PostgreSQL은 OUTER JOIN의 nullable side에 FOR UPDATE를 적용할 수 없어 500이 남.
            # 롤오버는 Post row만 잠그면 되므로 eager load를 끄고 row lock만 수행.
            .enable_eagerloads(False)
            .with_for_update()
            .first()
        )
        if not oldest1:
            break
        oldest1.card_type = 2
        db.add(oldest1)

    # 1유형: 30개 미만이면 2유형에서 승격하여 채움
    # - 삭제/수정 등으로 1유형이 줄어든 경우에도 30개를 유지하기 위함
    while True:
        c1 = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 1,
            )
            .scalar()
            or 0
        )
        if c1 >= CARD1_MAX:
            break

        newest2 = (
            db.query(Community_Post)
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 2,
            )
            .order_by(Community_Post.created_at.desc(), Community_Post.id.desc())
            .enable_eagerloads(False)
            .with_for_update()
            .first()
        )
        if not newest2:
            break
        newest2.card_type = 1
        db.add(newest2)

    # 2유형: 70개 유지 (초과분을 3유형으로)
    while True:
        c2 = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 2,
            )
            .scalar()
            or 0
        )
        if c2 <= CARD2_MAX:
            break

        oldest2 = (
            db.query(Community_Post)
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 2,
            )
            .order_by(Community_Post.created_at.asc(), Community_Post.id.asc())
            .enable_eagerloads(False)
            .with_for_update()
            .first()
        )
        if not oldest2:
            break
        oldest2.card_type = 3
        db.add(oldest2)

    # 2유형: 70개 미만이면 3유형에서 승격하여 채움
    # - 삭제/수정/승격(card_type=2 -> 1) 등으로 2유형이 줄어든 경우에도 70개를 유지하기 위함
    while True:
        c2 = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 2,
            )
            .scalar()
            or 0
        )
        if c2 >= CARD2_MAX:
            break

        newest3 = (
            db.query(Community_Post)
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 3,
            )
            .order_by(Community_Post.created_at.desc(), Community_Post.id.desc())
            .enable_eagerloads(False)
            .with_for_update()
            .first()
        )
        if not newest3:
            break
        newest3.card_type = 2
        db.add(newest3)

def _rollover_ad_card_types(db: Session) -> None:
    """
    광고글(post_type=4) 카드 1유형(card_type=1)을 최대 개수로 제한합니다.
    - card_type=1 -> 2 (5개 초과분을 오래된 순으로)
    같은 트랜잭션 안에서 호출되어야 합니다.
    """
    while True:
        c1 = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 4,
                Community_Post.card_type == 1,
            )
            .scalar()
            or 0
        )
        if c1 <= AD_CARD1_MAX:
            break

        oldest1 = (
            db.query(Community_Post)
            .filter(
                Community_Post.post_type == 4,
                Community_Post.card_type == 1,
            )
            .order_by(Community_Post.created_at.asc(), Community_Post.id.asc())
            .enable_eagerloads(False)
            .with_for_update()
            .first()
        )
        if not oldest1:
            break
        oldest1.card_type = 2
        db.add(oldest1)


@app.on_event("startup")
def _startup_enforce_recruit_card_limits() -> None:
    """
    서버 기동 시 구인글(post_type=1)의 card_type 개수 제한을 1회 적용.
    - 기존 데이터에 card_type=2가 40개를 초과해서 쌓여있는 경우(예: 70개)도 즉시 정리됩니다.
    """
    db = SessionLocal()
    try:
        _rollover_recruit_card_types(db)
        db.commit()
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        print("[WARN] startup recruit card rollover failed:", e)
    finally:
        db.close()

# -------------------- TossPayments (SSOT) --------------------
# clientKey: 결제 페이지(HTML)에서만 사용
# secretKey: 서버에서 confirm 호출에만 사용 (절대 앱/웹에 노출 금지)
TOSS_CLIENT_KEY = os.getenv("TOSS_CLIENT_KEY", "").strip()
TOSS_SECRET_KEY = os.getenv("TOSS_SECRET_KEY", "").strip()

# 결제 성공/실패 시 앱으로 돌아오는 딥링크 스킴
TOSS_APP_SCHEME = os.getenv("TOSS_APP_SCHEME", "smartgauge").strip() or "smartgauge"

# 캐시 충전 허용 금액(서버가 최종 결정)
ALLOWED_CASH_AMOUNTS = {10000, 30000, 50000, 80000, 100000}

# -------------------- Aligo SMS (community phone verification) --------------------
ALIGO_API_KEY = os.getenv("ALIGO_API_KEY", "").strip()
ALIGO_USER_ID = os.getenv("ALIGO_USER_ID", "").strip()
ALIGO_SENDER = os.getenv("ALIGO_SENDER", "").strip()
# 기본값 N(실발송). 필요 시 Y로 설정
ALIGO_TESTMODE_YN = os.getenv("ALIGO_TESTMODE_YN", "N").strip().upper()  # 'Y' / 'N'

PHONE_VERIFICATION_TTL_SECONDS = int(os.getenv("PHONE_VERIFICATION_TTL_SECONDS", "300"))  # default 5m
PHONE_VERIFICATION_MAX_ATTEMPTS = int(os.getenv("PHONE_VERIFICATION_MAX_ATTEMPTS", "5"))

def _normalize_phone(value: str) -> str:
    return re.sub(r"[^0-9]", "", (value or "").strip())

def _is_valid_korean_phone(digits: str) -> bool:
    # 최소한의 검증: 10~11자리 숫자
    return digits.isdigit() and (10 <= len(digits) <= 11)

def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def _generate_6digit_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

def _send_aligo_sms(receiver_digits: str, message: str) -> dict:
    """
    알리고 SMS 발송. 실패 시 HTTPException 발생.
    """
    if not (ALIGO_API_KEY and ALIGO_USER_ID and ALIGO_SENDER):
        raise HTTPException(status_code=500, detail="ALIGO not configured (ALIGO_API_KEY/ALIGO_USER_ID/ALIGO_SENDER)")

    payload = {
        "key": ALIGO_API_KEY,
        "user_id": ALIGO_USER_ID,
        "sender": ALIGO_SENDER,
        "receiver": receiver_digits,
        "msg": message,
        "msg_type": "SMS",
    }
    if ALIGO_TESTMODE_YN in {"Y", "N"}:
        payload["testmode_yn"] = ALIGO_TESTMODE_YN

    try:
        r = requests.post("https://apis.aligo.in/send/", data=payload, timeout=10)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"SMS provider error: {e}")

    try:
        data = r.json()
    except Exception:
        data = {"raw": r.text}

    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"SMS provider http error: {r.status_code}")

    result_code = str(data.get("result_code", ""))
    if result_code and result_code != "1":
        detail = data.get("message") or data.get("msg") or data.get("error") or data
        raise HTTPException(status_code=400, detail=f"SMS send failed: {detail}")

    return data

def _drop_all_constraints_on_table(table_name: str) -> None:
    """
    PostgreSQL에서 특정 테이블에 걸린 모든 제약조건(FK/UNIQUE/CHECK 등)을 제거합니다.
    - 사용자 요청: 제약조건 모두 없애기
    - 주의: 데이터 무결성은 애플리케이션 로직으로만 보장됩니다.
    """
    try:
        with engine.begin() as conn:
            # 테이블이 없으면 skip
            exists = conn.execute(
                text("SELECT to_regclass(:tname) IS NOT NULL"),
                {"tname": table_name},
            ).scalar()
            if not exists:
                return

            rows = conn.execute(
                text(
                    """
                    SELECT conname
                    FROM pg_constraint
                    WHERE conrelid = to_regclass(:tname)
                    """
                ),
                {"tname": table_name},
            ).fetchall()

            for (conname,) in rows:
                conn.execute(
                    text(f'ALTER TABLE "{table_name}" DROP CONSTRAINT IF EXISTS "{conname}" CASCADE')
                )
    except Exception as e:
        # 제약조건 제거 실패해도 서버는 뜨게 하되, 로그는 남김
        print(f"[WARN] drop constraints failed for {table_name}: {e}")

# --- schema sync helpers (no alembic) ---
def _ensure_community_users_columns_and_indexes() -> None:
    """
    Alembic 없이 운영 중인 DB 스키마를 최소한으로 동기화합니다.
    - community_users 신규 컬럼/인덱스가 없으면 생성
    - 이미 존재하면 스킵(에러 없이 idempotent)
    """
    try:
        with engine.begin() as conn:
            # 테이블이 없으면 skip (create_all에서 생성될 수 있음)
            exists = conn.execute(
                text("SELECT to_regclass('public.community_users') IS NOT NULL")
            ).scalar()
            if not exists:
                return

            # 컬럼 추가 (PostgreSQL: ADD COLUMN IF NOT EXISTS 지원)
            conn.execute(
                text(
                    """
                    ALTER TABLE public.community_users
                      ADD COLUMN IF NOT EXISTS last_recruit_posted_at timestamp with time zone NULL,
                      ADD COLUMN IF NOT EXISTS user_grade smallint NOT NULL DEFAULT 0,
                      ADD COLUMN IF NOT EXISTS is_owner boolean NOT NULL DEFAULT false;
                    """
                )
            )

            # 인덱스 추가
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_community_users_is_owner ON public.community_users (is_owner);"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_community_users_user_grade ON public.community_users (user_grade);"
                )
            )
    except Exception as e:
        # 스키마 동기화 실패해도 서버는 뜨게 하되, 로그는 남김
        print(f"[WARN] ensure community_users columns/indexes failed: {e}")

def _ensure_community_posts_columns() -> None:
    """
    Alembic 없이 운영 중인 DB 스키마를 최소한으로 동기화합니다.
    - community_posts에 필요한 컬럼이 없으면 생성(구인글 등록/수정 시 500 방지)
    - 이미 존재하면 스킵(에러 없이 idempotent)

    주의: PostgreSQL 전용 구문(to_regclass / ADD COLUMN IF NOT EXISTS)을 사용합니다.
    """
    try:
        with engine.begin() as conn:
            exists = conn.execute(
                text("SELECT to_regclass('public.community_posts') IS NOT NULL")
            ).scalar()
            if not exists:
                return

            conn.execute(
                text(
                    """
                    ALTER TABLE public.community_posts
                      ADD COLUMN IF NOT EXISTS workplace_lat double precision NULL,
                      ADD COLUMN IF NOT EXISTS workplace_lng double precision NULL,
                      ADD COLUMN IF NOT EXISTS business_lat double precision NULL,
                      ADD COLUMN IF NOT EXISTS business_lng double precision NULL,

                      ADD COLUMN IF NOT EXISTS highlight_color varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS highlight_content varchar(255) NULL,

                      ADD COLUMN IF NOT EXISTS total_use boolean NULL,
                      ADD COLUMN IF NOT EXISTS branch_use boolean NULL,
                      ADD COLUMN IF NOT EXISTS leader_use boolean NULL,
                      ADD COLUMN IF NOT EXISTS member_use boolean NULL,

                      ADD COLUMN IF NOT EXISTS total_fee varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS branch_fee varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS leader_fee varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS member_fee varchar(255) NULL,

                      ADD COLUMN IF NOT EXISTS pay_use boolean NULL,
                      ADD COLUMN IF NOT EXISTS meal_use boolean NULL,
                      ADD COLUMN IF NOT EXISTS house_use boolean NULL,

                      ADD COLUMN IF NOT EXISTS pay_sup varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS meal_sup boolean NULL,
                      ADD COLUMN IF NOT EXISTS house_sup varchar(255) NULL,

                      ADD COLUMN IF NOT EXISTS item1_use boolean NULL,
                      ADD COLUMN IF NOT EXISTS item1_type varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS item1_sup varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS item2_use boolean NULL,
                      ADD COLUMN IF NOT EXISTS item2_type varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS item2_sup varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS item3_use boolean NULL,
                      ADD COLUMN IF NOT EXISTS item3_type varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS item3_sup varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS item4_use boolean NULL,
                      ADD COLUMN IF NOT EXISTS item4_type varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS item4_sup varchar(255) NULL,

                      ADD COLUMN IF NOT EXISTS agent varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS other_role_name varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS other_role_fee varchar(255) NULL,
                      ADD COLUMN IF NOT EXISTS post_type double precision NULL,
                      ADD COLUMN IF NOT EXISTS card_type double precision NULL,

                      ADD COLUMN IF NOT EXISTS status varchar(20) NOT NULL DEFAULT 'published';
                    """
                )
            )
    except Exception as e:
        print(f"[WARN] ensure community_posts columns failed: {e}")

def _ensure_phone_table() -> None:
    """
    Alembic 없이 phone 테이블을 생성/동기화합니다.
    요구 스키마:
      create table if not exists phone (
        id         bigserial primary key,
        phone      text not null,
        created_at timestamptz not null default now()
      );
    """
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS public.phone (
                      id bigserial PRIMARY KEY,
                      phone text NOT NULL,
                      created_at timestamptz NOT NULL DEFAULT now()
                    );
                    """
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_phone_phone ON public.phone (phone);"))
    except Exception as e:
        print(f"[WARN] ensure phone table failed: {e}")

def _ensure_community_user_restrictions_table() -> None:
    """
    Alembic 없이 community_user_restrictions 테이블을 생성/동기화합니다.
    요구 스키마(Contract/지시서):
      - user_id, post_type(1|3|4), restricted_until(timestamptz|null), reason, created_at, created_by_user_id
      - UNIQUE (user_id, post_type) (업서트 갱신/해제용)
    """
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS public.community_user_restrictions (
                      id bigserial PRIMARY KEY,
                      user_id integer NOT NULL,
                      post_type smallint NOT NULL,
                      restricted_until timestamptz NULL,
                      reason text NULL,
                      created_at timestamptz NOT NULL DEFAULT now(),
                      created_by_user_id integer NULL,
                      CONSTRAINT uq_community_user_restrictions_user_post_type UNIQUE (user_id, post_type)
                    );
                    """
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_community_user_restrictions_user_id ON public.community_user_restrictions (user_id);"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_community_user_restrictions_post_type ON public.community_user_restrictions (post_type);"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_community_user_restrictions_user_post_type ON public.community_user_restrictions (user_id, post_type);"
                )
            )
    except Exception as e:
        print(f"[WARN] ensure community_user_restrictions table failed: {e}")

def _ensure_recode_columns() -> None:
    """
    recode 테이블을 운행일지 스펙(smartgauge.md)에 맞춰 확장합니다.
    - 기존 테이블이 있어도 컬럼이 없으면 ADD COLUMN IF NOT EXISTS로 보강
    - 기존 앱 하위호환을 위해 username/duration(초) 컬럼은 유지
    """
    try:
        with engine.begin() as conn:
            exists = conn.execute(
                text("SELECT to_regclass('public.recode') IS NOT NULL")
            ).scalar()
            if not exists:
                return

            conn.execute(
                text(
                    """
                    ALTER TABLE public.recode
                      ADD COLUMN IF NOT EXISTS user_id integer NULL,
                      ADD COLUMN IF NOT EXISTS duration_minutes integer NULL,
                      ADD COLUMN IF NOT EXISTS start_location text NULL,
                      ADD COLUMN IF NOT EXISTS end_location text NULL,
                      ADD COLUMN IF NOT EXISTS trip_km numeric(10,2) NULL,
                      ADD COLUMN IF NOT EXISTS trip_purpose text NULL,
                      ADD COLUMN IF NOT EXISTS business_use boolean NOT NULL DEFAULT false;
                    """
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_recode_user_id ON public.recode (user_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_recode_date ON public.recode (date);"))
    except Exception as e:
        print(f"[WARN] ensure recode columns failed: {e}")

def _kakao_auth_header(api_key: str) -> dict:
    """
    Kakao REST/Mobility API 공통 인증 헤더.
    """
    k = (api_key or "").strip()
    if not k:
        return {}
    return {"Authorization": f"KakaoAK {k}"}

def _kakao_coord2_sigungu(lat: float, lng: float) -> str | None:
    """
    좌표(위도/경도)를 시/군/구 문자열로 변환합니다.
    - 요구사항: 도/시군구 단위만 기록
    - 저장 형태: \"{region_1depth_name} {region_2depth_name}\" (예: \"경기도 평택시\")
    """
    if not KAKAO_REST_API_KEY:
        return None
    try:
        r = requests.get(
            "https://dapi.kakao.com/v2/local/geo/coord2regioncode.json",
            params={"x": lng, "y": lat},
            headers=_kakao_auth_header(KAKAO_REST_API_KEY),
            timeout=8,
        )
        r.raise_for_status()
        data = r.json() or {}
        docs = data.get("documents") or []
        if not docs:
            return None
        # 우선순위: 행정동(H) -> 법정동(B) -> 첫번째
        pick = None
        for d in docs:
            if d.get("region_type") == "H":
                pick = d
                break
        if pick is None:
            for d in docs:
                if d.get("region_type") == "B":
                    pick = d
                    break
        if pick is None:
            pick = docs[0]
        r1 = (pick.get("region_1depth_name") or "").strip()
        r2 = (pick.get("region_2depth_name") or "").strip()
        sigungu = " ".join([x for x in [r1, r2] if x])
        return sigungu or None
    except Exception as e:
        print(f"[WARN] kakao coord2regioncode failed: {e}")
        return None

def _kakao_route_distance_km(start_lat: float, start_lng: float, end_lat: float, end_lng: float) -> float | None:
    """
    출발/도착 좌표 사이 도로거리(km)를 카카오 모빌리티 길찾기 API로 계산합니다.
    - 성공 시 km(float) 반환 (소수 2자리 반올림)
    """
    if not KAKAO_MOBILITY_API_KEY:
        return None
    try:
        # Kakao Mobility(Navi) directions
        r = requests.get(
            "https://apis-navi.kakaomobility.com/v1/directions",
            params={
                "origin": f"{start_lng},{start_lat}",
                "destination": f"{end_lng},{end_lat}",
                "priority": "RECOMMEND",
            },
            headers=_kakao_auth_header(KAKAO_MOBILITY_API_KEY),
            timeout=10,
        )
        r.raise_for_status()
        data = r.json() or {}
        # routes[0].summary.distance (meters)
        routes = data.get("routes") or []
        if not routes:
            return None
        summary = (routes[0] or {}).get("summary") or {}
        dist_m = summary.get("distance")
        if dist_m is None:
            return None
        km = float(dist_m) / 1000.0
        return round(km, 2)
    except Exception as e:
        print(f"[WARN] kakao directions distance failed: {e}")
        return None

# 앱 시작 시 referral/point 테이블의 제약조건을 모두 제거
_drop_all_constraints_on_table("referral")
_drop_all_constraints_on_table("point")
_drop_all_constraints_on_table("cash")
_ensure_community_users_columns_and_indexes()
_ensure_community_posts_columns()
_ensure_phone_table()
_ensure_community_user_restrictions_table()
_ensure_recode_columns()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RuntimePayload(BaseModel):
    user_id: str
    runtime_seconds: int

class SignupRequest(BaseModel):
    username: str
    email:    EmailStr
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginRequest2(BaseModel):
    username: str
    password: str
    push_token: str | None = None

class LoginResponse(BaseModel):
    user_id: int
    token: str

class RecodeCreate(BaseModel):
    username: str
    date: str
    ontime: str
    offtime: str
    duration: int
    # 스펙 확장(선택): GPS/사용자 입력
    start_location: str | None = None
    end_location: str | None = None
    trip_km: float | None = None
    trip_purpose: str | None = None
    business_use: bool = False
    # 선택: 서버에서 username -> user_id 매핑용 (신규 클라이언트)
    user_id: int | None = None

class RecodeOut(BaseModel):
    id: int | None = None
    username: str | None = None
    user_id: int | None = None
    date: str
    ontime: str
    offtime: str
    duration: int
    duration_minutes: int | None = None
    start_location: str | None = None
    end_location: str | None = None
    trip_km: float | None = None
    trip_purpose: str | None = None
    business_use: bool = False
    class Config:
        orm_mode = True

class RecodeListOut(BaseModel):
    recodes: list[RecodeOut]

@app.post("/runtime/update")
def update_runtime(payload: RuntimePayload, db: Session = Depends(get_db)):
    stmt = insert(RuntimeRecord).values(
        user_id=payload.user_id,
        runtime_seconds=payload.runtime_seconds
    ).on_conflict_do_update(
        index_elements=["user_id"],  
        set_={
            "runtime_seconds": RuntimeRecord.runtime_seconds + payload.runtime_seconds,
        }
    )
    try:
        db.execute(stmt)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="데이터베이스 업데이트 실패") from e

    total = db.query(RuntimeRecord.runtime_seconds)\
              .filter(RuntimeRecord.user_id == payload.user_id)\
              .scalar()

    return {
        "status": "ok",
        "user_id": payload.user_id,
        "total_runtime": total
    }



@app.get("/runtime/{user_id}", response_model=RuntimePayload)
def read_runtime(user_id: str, db: Session = Depends(get_db)):
    record = (
        db.query(RuntimeRecord)
        .filter(RuntimeRecord.user_id == user_id)
        .first()
    )


    if not record:
        raise HTTPException(status_code=404, detail="런타임 기록을 찾을 수 없습니다.")

    return record



@app.post("/auth/signup")
def signup(req: SignupRequest, db: Session = Depends(get_db)):

    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400,  "Username already taken")

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()

    user = User(
        username      = req.username,
        email         = req.email,
        password_hash = pw_hash
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"status":"ok", "user_id": user.id}



@app.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.username == req.username).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()
    if user.password_hash != pw_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": str(user.id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

    return LoginResponse(user_id=user.id, token=token)




@app.get("/recode/{username}/{date}", response_model=RecodeListOut)
def get_recode(username: str, date: str, db: Session = Depends(get_db)):
    # 하위호환: 기존 데이터(username 기반) + 신규 데이터(user_id 기반) 모두 조회
    user = db.query(User).filter(User.username == username).first()
    conds = [Recode.username == username]
    if user:
        conds.append(Recode.user_id == user.id)
    q = db.query(Recode).filter(or_(*conds))

    # date 파라미터 지원:
    # - YYYY-MM-DD: 해당 날짜(일간)
    # - YYYY-MM: 해당 월 전체(월간)
    if len(date) == 10 and date[4] == "-" and date[7] == "-":
        q = q.filter(Recode.date == date)
    elif len(date) == 7 and date[4] == "-":
        try:
            y = int(date[0:4])
            m = int(date[5:7])
            last_day = calendar.monthrange(y, m)[1]
            start = f"{y:04d}-{m:02d}-01"
            end = f"{y:04d}-{m:02d}-{last_day:02d}"
            q = q.filter(Recode.date >= start, Recode.date <= end)
        except Exception:
            # 파싱 실패 시 하위호환(정확 일치)
            q = q.filter(Recode.date == date)
    else:
        # 예상 외 포맷은 하위호환(정확 일치)
        q = q.filter(Recode.date == date)

    recodes = q.all()
    return {"recodes": recodes}


@app.post("/recode/add")
def add_recode(recode: RecodeCreate, db: Session = Depends(get_db)):
    # 신규 스펙: 가능하면 user_id를 채워서 저장(기존 클라이언트는 username만 보냄)
    uid = recode.user_id
    if uid is None and recode.username:
        u = db.query(User).filter(User.username == recode.username).first()
        uid = u.id if u else None

    duration_minutes = None
    try:
        # 기존 클라이언트 duration은 초 단위로 들어오므로 분 컬럼도 함께 채움(바닥 나눗셈)
        duration_minutes = int(recode.duration) // 60 if recode.duration is not None else None
    except Exception:
        duration_minutes = None

    new_r = Recode(  
        username=recode.username,
        user_id=uid,
        date=recode.date,
        ontime=recode.ontime,
        offtime=recode.offtime,
        duration=recode.duration,
        duration_minutes=duration_minutes,
        start_location=recode.start_location,
        end_location=recode.end_location,
        trip_km=recode.trip_km,
        trip_purpose=recode.trip_purpose,
        business_use=bool(recode.business_use),
    )
    db.add(new_r)
    db.commit()
    return {"status":"success"}



@app.get("/recode/summary/{username}/{start}/{end}", response_model=RangeSummaryOut)
def recode_summary(username: str, start: str, end: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    conds = [Recode.username == username]
    if user:
        conds.append(Recode.user_id == user.id)
    cnt, total = db.query(
        func.count(Recode.id),
        func.coalesce(func.sum(Recode.duration), 0)
    ).filter(
        or_(*conds),
        Recode.date >= start,
        Recode.date <= end
    ).one()
    return RangeSummaryOut(
        username=username, start=start, end=end,
        on_count=int(cnt), runtime_seconds=int(total or 0)
    )

# -------------------- 운행일지(신규 스펙) API --------------------
def _try_get_current_user(db: Session, authorization: str | None) -> User | None:
    """
    Authorization 헤더가 있을 때만 JWT를 시도하고, 실패 시 None을 반환합니다.
    - /auth/login 토큰(sub=users.id) 전용
    """
    try:
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        token = authorization.split(" ", 1)[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload.get("sub"))
        return db.query(User).filter(User.id == uid).first()
    except Exception:
        return None

def get_current_user(
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> User:
    """
    /auth/login 으로 발급된 JWT(sub=users.id) 기반 인증.
    - 기존 코드(Depends(get_current_user)) 하위호환용으로 유지
    """
    u = _try_get_current_user(db, authorization)
    if not u:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return u

class RecodeStartIn(BaseModel):
    """
    시동 ON 시작 기록 생성.

    인증/식별:
    - (권장) Authorization: Bearer <JWT(sub=users.id)>
    - (하위호환) username 필드

    위치/거리:
    - 서버는 좌표를 저장하지 않고, 시/군/구만 `start_location`에 저장합니다.
    """
    username: str | None = None
    date: str | None = None  # YYYY-MM-DD (없으면 오늘)
    ontime: str | None = None  # HH:MM[:SS] (없으면 현재)
    start_lat: float
    start_lng: float

class RecodeStartOut(BaseModel):
    id: int
    date: str
    ontime: str
    start_location: str | None = None

class RecodeEndIn(BaseModel):
    """
    시동 OFF 종료 기록 확정.
    - 도착 시점 좌표로 `end_location`(시/군/구) 저장
    - 출발/도착 좌표로 카카오 길찾기 기반 `trip_km`(도로거리) 계산
    """
    username: str | None = None
    recode_id: int
    offtime: str | None = None  # HH:MM[:SS]
    duration_seconds: int | None = None
    start_lat: float | None = None
    start_lng: float | None = None
    end_lat: float
    end_lng: float

class RecodePatchIn(BaseModel):
    trip_purpose: str | None = None
    business_use: bool | None = None

@app.post("/recode/start", response_model=RecodeStartOut)
def recode_start(
    payload: RecodeStartIn,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    now = datetime.now()
    date_str = payload.date or now.strftime("%Y-%m-%d")
    on_str = payload.ontime or now.strftime("%H:%M:%S")

    user = _try_get_current_user(db, authorization)
    username = user.username if user else (payload.username or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="username or Authorization required")

    uid = user.id if user else None
    if uid is None:
        u = db.query(User).filter(User.username == username).first()
        uid = u.id if u else None

    start_loc = _kakao_coord2_sigungu(payload.start_lat, payload.start_lng)
    r = Recode(
        user_id=uid,
        username=username,  # legacy 병행
        date=date_str,
        ontime=on_str,
        offtime="",
        duration=0,
        duration_minutes=0,
        start_location=start_loc,
        end_location=None,
        trip_km=None,
        trip_purpose=None,
        business_use=False,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return RecodeStartOut(id=r.id, date=r.date, ontime=r.ontime, start_location=r.start_location)

@app.post("/recode/end", response_model=RecodeOut)
def recode_end(
    payload: RecodeEndIn,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    user = _try_get_current_user(db, authorization)
    username = user.username if user else (payload.username or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="username or Authorization required")

    q = db.query(Recode).filter(Recode.id == payload.recode_id)
    if user:
        q = q.filter(or_(Recode.user_id == user.id, Recode.username == user.username))
    else:
        q = q.filter(Recode.username == username)
    r = q.first()
    if not r:
        raise HTTPException(status_code=404, detail="recode not found")

    now = datetime.now()
    off_str = payload.offtime or now.strftime("%H:%M:%S")
    r.offtime = off_str
    r.end_location = _kakao_coord2_sigungu(payload.end_lat, payload.end_lng)

    # 도로거리 계산: 출발/도착 좌표가 모두 있는 경우에만 수행
    if payload.start_lat is not None and payload.start_lng is not None:
        r.trip_km = _kakao_route_distance_km(payload.start_lat, payload.start_lng, payload.end_lat, payload.end_lng)

    # duration: 클라이언트가 주면 그대로 사용, 아니면 문자열로 계산(가능할 때만)
    if payload.duration_seconds is not None:
        try:
            r.duration = max(int(payload.duration_seconds), 0)
            r.duration_minutes = int(r.duration) // 60
        except Exception:
            pass
    else:
        # HH:MM[:SS] 파싱 지원
        try:
            def _parse_hms(s: str) -> int:
                parts = (s or "").split(":")
                if len(parts) == 2:
                    h, m = int(parts[0]), int(parts[1])
                    return h * 3600 + m * 60
                if len(parts) == 3:
                    h, m, sec = int(parts[0]), int(parts[1]), int(parts[2])
                    return h * 3600 + m * 60 + sec
                return 0

            start_sec = _parse_hms(r.ontime)
            end_sec = _parse_hms(off_str)
            dur_sec = end_sec - start_sec
            if dur_sec < 0:
                dur_sec = 0
            r.duration = int(dur_sec)
            r.duration_minutes = int(dur_sec) // 60
        except Exception:
            pass

    db.add(r)
    db.commit()
    db.refresh(r)
    return r

@app.patch("/recode/{recode_id}", response_model=RecodeOut)
def recode_patch(recode_id: int, payload: RecodePatchIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    r = db.query(Recode).filter(Recode.id == recode_id, Recode.user_id == user.id).first()
    if not r:
        raise HTTPException(status_code=404, detail="recode not found")
    if payload.trip_purpose is not None:
        r.trip_purpose = payload.trip_purpose
    if payload.business_use is not None:
        r.business_use = bool(payload.business_use)
    db.add(r)
    db.commit()
    db.refresh(r)
    return r

@app.get("/recode", response_model=RecodeListOut)
def recode_list(date: str = Query(..., description="YYYY-MM-DD"), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    recodes = db.query(Recode).filter(Recode.user_id == user.id, Recode.date == date).all()
    return {"recodes": recodes}

@app.post("/play/rtdn")
async def play_rtdn(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    try:
        msg = body["message"]
        data_b64 = msg["data"]
        payload = json.loads(base64.b64decode(data_b64).decode("utf-8"))

        sub = payload.get("subscriptionNotification") or {}
        purchase_token = sub.get("purchaseToken")
        product_id = sub.get("subscriptionId")

        if not purchase_token or not product_id:
            return {"ok": True, "skip": True}

        service = get_service()
        res = service.purchases().subscriptions().get(
            packageName="kr.co.smartgauge",
            subscriptionId=product_id,
            token=purchase_token,
        ).execute()

        _ack_if_needed(service, product_id, purchase_token, developer_payload="rtdn")

        expiry_ms = int(res.get("expiryTimeMillis", "0"))
        if not expiry_ms:
            return {"ok": True, "invalid_expiry": True}

        expires_at = _to_dt_utc(expiry_ms)
        auto_renewing = bool(res.get("autoRenewing", True))
        order_id = res.get("orderId")
        status = _derive_status(res)
        active = (status in ["ACTIVE", "CANCELED"])

        row = crud.get_subscription_by_token(db, purchase_token)
        if row:
            crud.update_subscription_fields(
                db,
                row,
                product_id=product_id,
                order_id=order_id,
                expires_at=expires_at,
                auto_renewing=auto_renewing,
                status=status,
                active=active,
            )
            db.commit()
            return {"ok": True, "updated": True}

        linked = res.get("linkedPurchaseToken")
        if linked:
            prev = crud.get_subscription_by_token(db, linked)
            if prev:
                prev.active = False
                crud.insert_active_subscription(
                    db=db,
                    user_id=prev.user_id,
                    product_id=product_id,
                    purchase_token=purchase_token,
                    order_id=order_id,
                    expires_at=expires_at,
                    auto_renewing=auto_renewing,
                    status=status,
                    active=active,
                )
                db.commit()
                return {"ok": True, "migrated_from_linked": True}

        return {"ok": True, "unknown_token": True}

    except Exception as e:
        return {"ok": False, "error": str(e)}


        
def _ack_if_needed(service, product_id: str, purchase_token: str, developer_payload: str = "") -> None:
    try:
        service.purchases().subscriptions().acknowledge(
            packageName="kr.co.smartgauge",
            subscriptionId=product_id,
            token=purchase_token,
            body={"developerPayload": developer_payload or ""}
        ).execute()
    except HttpError as e:
        code = getattr(e, "status_code", None) or (e.resp.status if hasattr(e, "resp") else None)
        if code in (400, 409):
            return
        raise


def _to_dt_utc(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)

def _derive_status(res: dict) -> str:
    now_ms = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
    expiry_ms = int(res.get("expiryTimeMillis", "0"))
    if not expiry_ms:
        return "INVALID"
        
    cancel_reason = res.get("cancelReason")     
    account_hold = res.get("accountHold", False)  
    payment_state = res.get("paymentState")       
    price_change = res.get("priceChange", {}).get("state")

    if account_hold:
        return "ON_HOLD"
    if cancel_reason is not None and expiry_ms > now_ms:
        return "CANCELED"
    if expiry_ms <= now_ms:
        return "EXPIRED"
    if payment_state == 0:
        return "PENDING"   
    if payment_state == 2:
        return "TRIAL"    
    if price_change == 1:
        return "PRICE_CHANGE_PENDING"
    return "ACTIVE"


@app.post("/billing/verify", response_model=SubscriptionStatusOut)
def verify_subscription_endpoint(
    payload: PurchaseVerifyIn,  
    db: Session = Depends(get_db),
):

    user = db.query(User).filter(User.username == payload.username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username")
    user_id = user.id

    try:
        service = get_service()
        res = service.purchases().subscriptions().get(
            packageName="kr.co.smartgauge",
            subscriptionId=payload.product_id,
            token=payload.purchase_token,
        ).execute()

      
        _ack_if_needed(
            service=service,
            product_id=payload.product_id,
            purchase_token=payload.purchase_token,
            developer_payload=f"user:{user.username}"  
        )

    except HttpError as e:
        code = getattr(e, "status_code", None) or (e.resp.status if hasattr(e, "resp") else None)
        msg = e.reason if hasattr(e, "reason") else str(e)
        print(f"[Google API Error] code={code}, msg={msg}") 
        if code in (400, 404, 410):
            raise HTTPException(status_code=400, detail=f"Invalid purchase token/product ({code}): {msg}")
        raise HTTPException(status_code=502, detail=f"Google API error ({code}): {msg}")

    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Google API error: {e}")

    expiry_ms = int(res.get("expiryTimeMillis", "0"))
    if not expiry_ms:
        raise HTTPException(status_code=400, detail="Invalid expiryTimeMillis from Google API")

    expires_at = _to_dt_utc(expiry_ms)
    auto_renewing = bool(res.get("autoRenewing", True))
    order_id = res.get("orderId")
    status = _derive_status(res)
    active = (status in ["ACTIVE", "CANCELED"])

    existing = crud.get_subscription_by_token(db, payload.purchase_token)
    if existing:
        crud.update_subscription_fields(
            db,
            existing,
            product_id=payload.product_id,
            order_id=order_id,
            expires_at=expires_at,
            auto_renewing=auto_renewing,
            status=status,
            active=active,
        )
    else:
        crud.insert_active_subscription(
            db=db,
            user_id=user_id,
            product_id="smartgauge_yearly",
            purchase_token=payload.purchase_token,
            order_id=order_id,
            expires_at=expires_at,
            auto_renewing=auto_renewing,
            status=status,
            active=active
        )
    db.commit()

    return SubscriptionStatusOut(
        active=active,
        product_id=payload.product_id,
        expires_at=expires_at,
        status=status,
        auto_renewing=auto_renewing,
    )



@app.get("/billing/status", response_model=SubscriptionStatusOut)
def get_subscription_status(
    username: str,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username")
    user_id = user.id
     
    sub = crud.get_active_subscription(db, user_id)
    if not sub:
        return SubscriptionStatusOut(active=False)

    db.refresh(sub)
    
    return SubscriptionStatusOut(
        active=sub.active,
        product_id=sub.product_id,
        expires_at=sub.expires_at,
        status=sub.status,
        auto_renewing=sub.auto_renewing,
    )

#--------community-app-mvp-------------------------------------------------------------------------------
def get_current_community_user(
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(Community_User).filter(Community_User.id == uid).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

def _try_get_current_community_user(db: Session, authorization: str | None) -> Community_User | None:
    """
    Authorization 헤더가 있을 때만 JWT를 시도하고, 실패 시 None을 반환합니다.
    - Admin/Owner API에서 Contract(status=3)로 처리하기 위한 헬퍼
    """
    try:
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        token = authorization.split(" ", 1)[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = int(payload.get("sub"))
        return db.query(Community_User).filter(Community_User.id == uid).first()
    except Exception:
        return None

def _is_admin_or_owner(u: Community_User | None) -> bool:
    if not u:
        return False
    return bool(getattr(u, "admin_acknowledged", False) or getattr(u, "is_owner", False))

def _is_owner(u: Community_User | None) -> bool:
    return bool(u and getattr(u, "is_owner", False))

class SignupRequest_C(BaseModel):
    username: str = Field(min_length=2, max_length=50)
    password: str = Field(min_length=2, max_length=255)
    password_confirm: str = Field(min_length=2, max_length=255)
    name: str | None = Field(default=None, max_length=50)
    phone_number: str | None = Field(default=None, max_length=20)
    phone_verification_id: str | None = Field(default=None, max_length=80)
    region: str | None = Field(default=None, max_length=100)
    referral_code: str | None = Field(default=None, max_length=20)
    # community_users 신규 필드(2026-01)
    marketing_consent: bool = False
    custom_industry_codes: list[str] = Field(default_factory=list)
    custom_region_codes: list[str] = Field(default_factory=list)

class PhoneSendRequest(BaseModel):
    phone_number: str = Field(min_length=8, max_length=30)

class PhoneSendResponse(BaseModel):
    status: int
    verification_id: str | None = None
    expires_in_sec: int | None = None

class PhoneVerifyRequest(BaseModel):
    verification_id: str = Field(min_length=10, max_length=80)
    code: str = Field(min_length=4, max_length=10)

class PhoneVerifyResponse(BaseModel):
    status: int
    verified: bool = False

class FindUsernameRequest(BaseModel):
    phone_number: str = Field(min_length=8, max_length=30)
    phone_verification_id: str = Field(min_length=10, max_length=80)

class FindUsernameResponse(BaseModel):
    status: int
    items: list[str] = Field(default_factory=list)

class ResetPasswordRequest(BaseModel):
    username: str = Field(min_length=2, max_length=50)
    phone_number: str = Field(min_length=8, max_length=30)
    phone_verification_id: str = Field(min_length=10, max_length=80)
    new_password: str = Field(min_length=2, max_length=255)
    new_password_confirm: str = Field(min_length=2, max_length=255)

class ResetPasswordResponse(BaseModel):
    status: int
    detail: str | None = None

def _require_verified_phone(db: Session, phone_number: str, phone_verification_id: str) -> str:
    """
    인증 완료된 휴대폰(verification_id + phone 매칭, 만료/검증 체크)을 강제하고
    정규화된 phone digits를 반환합니다.
    """
    digits = _normalize_phone(phone_number)
    if not _is_valid_korean_phone(digits):
        raise HTTPException(status_code=400, detail="invalid phone_number")

    try:
        vid = uuid.UUID(phone_verification_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid phone_verification_id")

    vrow = db.query(Community_Phone_Verification).filter(Community_Phone_Verification.id == vid).first()
    now = datetime.now(tz=timezone.utc)
    if (
        (not vrow)
        or (vrow.phone_number != digits)
        or (vrow.verified_at is None)
        or (vrow.expires_at is not None and vrow.expires_at <= now)
    ):
        raise HTTPException(status_code=400, detail="phone verification required")
    return digits

@app.post("/community/phone/send", response_model=PhoneSendResponse)
def community_phone_send(req: PhoneSendRequest, db: Session = Depends(get_db)):
    digits = _normalize_phone(req.phone_number)
    if not _is_valid_korean_phone(digits):
        raise HTTPException(status_code=400, detail="invalid phone_number")

    code = _generate_6digit_code()
    now = datetime.now(tz=timezone.utc)
    expires_at = now + timedelta(seconds=PHONE_VERIFICATION_TTL_SECONDS)

    row = Community_Phone_Verification(
        phone_number=digits,
        code_hash=_hash_code(code),
        expires_at=expires_at,
    )
    db.add(row)
    db.flush()  # id 생성

    msg = f"[분양프로] 인증번호는 {code} 입니다."
    try:
        _send_aligo_sms(digits, msg)
    except Exception:
        db.rollback()
        raise

    db.commit()
    db.refresh(row)

    return {
        "status": 0,
        "verification_id": str(row.id),
        "expires_in_sec": PHONE_VERIFICATION_TTL_SECONDS,
    }

@app.post("/community/phone/verify", response_model=PhoneVerifyResponse)
def community_phone_verify(req: PhoneVerifyRequest, db: Session = Depends(get_db)):
    try:
        vid = uuid.UUID(req.verification_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid verification_id")

    row = db.query(Community_Phone_Verification).filter(Community_Phone_Verification.id == vid).first()
    if not row:
        return {"status": 1, "verified": False}

    now = datetime.now(tz=timezone.utc)
    if row.verified_at is not None:
        return {"status": 0, "verified": True}
    if row.expires_at is not None and row.expires_at <= now:
        return {"status": 2, "verified": False}

    attempts = int(getattr(row, "attempts", 0) or 0)
    if attempts >= PHONE_VERIFICATION_MAX_ATTEMPTS:
        return {"status": 3, "verified": False}

    if _hash_code(req.code.strip()) != row.code_hash:
        row.attempts = attempts + 1
        db.add(row)
        db.commit()
        return {"status": 4, "verified": False}

    row.verified_at = now
    db.add(row)
    db.commit()
    return {"status": 0, "verified": True}

@app.post("/community/account/find-username", response_model=FindUsernameResponse)
def community_find_username(req: FindUsernameRequest, db: Session = Depends(get_db)):
    digits = _require_verified_phone(db, req.phone_number, req.phone_verification_id)

    # 기존 데이터가 하이픈 포함으로 저장되어 있을 수 있어, DB/파이썬에서 숫자만 비교
    try:
        dialect = db.get_bind().dialect.name
    except Exception:
        dialect = ""

    if dialect == "postgresql":
        users = (
            db.query(Community_User)
            .filter(
                func.regexp_replace(Community_User.phone_number, r"[^0-9]", "", "g") == digits
            )
            .all()
        )
    else:
        rows = (
            db.query(Community_User)
            .filter(Community_User.phone_number.isnot(None))
            .all()
        )
        users = [u for u in rows if _normalize_phone(u.phone_number or "") == digits]

    if not users:
        return {"status": 1, "items": []}

    items = [u.username for u in users if u and u.username]
    return {"status": 0, "items": items}

@app.post("/community/account/reset-password", response_model=ResetPasswordResponse)
def community_reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    if req.new_password != req.new_password_confirm:
        return {"status": 2, "detail": "비밀번호와 비밀번호 확인이 일치하지 않습니다."}

    digits = _require_verified_phone(db, req.phone_number, req.phone_verification_id)

    user = db.query(Community_User).filter(Community_User.username == req.username).first()
    if not user:
        return {"status": 1, "detail": "사용자를 찾을 수 없습니다."}

    # 기존 데이터(하이픈 포함) 고려하여 숫자만 비교
    if _normalize_phone(user.phone_number or "") != digits:
        return {"status": 3, "detail": "휴대폰 번호가 일치하지 않습니다."}

    user.password_hash = hashlib.sha256(req.new_password.encode()).hexdigest()
    db.add(user)
    db.commit()
    return {"status": 0}

   
@app.post("/community/signup")
def community_signup(req: SignupRequest_C, db: Session = Depends(get_db)):

    if db.query(Community_User).filter(Community_User.username == req.username).first():
        return {"status": 1} 

    if req.password != req.password_confirm:
        return {"status": 2} 

    if req.name is None:
        return {"status": 3}

    if req.phone_number is None:
        return {"status": 4}

    # 휴대폰 인증 강제
    digits = _normalize_phone(req.phone_number)
    if not _is_valid_korean_phone(digits):
        raise HTTPException(status_code=400, detail="invalid phone_number")

    if not req.phone_verification_id:
        return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}
    try:
        vid = uuid.UUID(req.phone_verification_id)
    except Exception:
        return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}

    vrow = db.query(Community_Phone_Verification).filter(Community_Phone_Verification.id == vid).first()
    now = datetime.now(tz=timezone.utc)
    if (
        (not vrow)
        or (vrow.phone_number != digits)
        or (vrow.verified_at is None)
        or (vrow.expires_at is not None and vrow.expires_at <= now)
    ):
        return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}

    # community_users 테이블 기준 "동일 휴대폰 번호" 중복 가입 차단
    # (과거 데이터에 하이픈이 포함되어 있을 수 있어 숫자만 비교)
    try:
        dialect = db.get_bind().dialect.name
    except Exception:
        dialect = ""

    if dialect == "postgresql":
        phone_already_registered = (
            db.query(Community_User.id)
            .filter(func.regexp_replace(Community_User.phone_number, r"[^0-9]", "", "g") == digits)
            .first()
            is not None
        )
    else:
        rows = (
            db.query(Community_User)
            .filter(Community_User.phone_number.isnot(None))
            .all()
        )
        phone_already_registered = any(_normalize_phone(u.phone_number or "") == digits for u in rows)

    if phone_already_registered:
        return {"status": 10, "detail": "이미 등록된 휴대폰 번호가 있습니다."}

    if req.region is None:
        return {"status": 3}    

    # phone 테이블 기준 "기존에 사용된 번호"인지 확인 (추천인 시스템 차단용)
    phone_already_saved = (
        db.query(Phone.id)
        .filter(Phone.phone == digits)
        .first()
        is not None
    )

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()

    user = Community_User(
        username      = req.username,
        password_hash = pw_hash,
        name          = req.name,
        phone_number  = digits,
        region        = req.region,  
        signup_date   = date.today(), 
        # 정책(2026-01): 일반회원 기본 등급은 -1
        user_grade    = -1,
        marketing_consent=bool(req.marketing_consent),
        custom_industry_codes=list(req.custom_industry_codes or []),
        custom_region_codes=list(req.custom_region_codes or []),
    )
    db.add(user)
    db.flush()
    
    # referral_code 생성 및 할당
    try:
        assign_referral_code(db, user, req.phone_number)
    except HTTPException:
        db.rollback()
        raise  # HTTPException은 그대로 전달
    except Exception as e:
        db.rollback()
        print(f"[ERROR] referral_code 할당 중 예상치 못한 오류: {e}")
        raise HTTPException(
            status_code=500,
            detail="회원가입 처리 중 오류가 발생했습니다"
        )

    # phone 테이블에 번호 영구 저장 (중복이면 삽입 스킵)
    if not phone_already_saved:
        db.add(Phone(phone=digits))

    SIGNUP_BONUS = 500
    signup_bonus_amount = 0
    referral_bonus_referred_amount = 0
    referral_bonus_referrer_amount = 0

    input_code = (req.referral_code or "").strip()

    # 정책:
    # - 추천인코드 미기입 시에만 가입 포인트 500P 지급
    # - 추천인코드 기입 + (phone 테이블에 없는 번호)일 때만 추천인 시스템(각 1000P) 적용
    # - 추천인코드 기입했더라도, phone 테이블에 이미 저장된 번호면 추천인 시스템은 "완전 미적용"(코드 검증/포인트/원장/알림 모두 스킵)
    if not input_code:
        signup_bonus_amount = SIGNUP_BONUS
        user.point_balance = int(user.point_balance or 0) + SIGNUP_BONUS
        db.add(Point(user_id=user.id, reason="signup_bonus", amount=SIGNUP_BONUS))
    
    # 추천인코드가 있을 때: phone 중복이면 "추천인 시스템 완전 미적용"
    if input_code and (not phone_already_saved):
        # 본인 코드로 추천 방지(가입 직후 생성된 코드와 동일할 가능성도 있어 체크)
        if user.referral_code and input_code == user.referral_code:
            db.rollback()
            return {"status": 6, "detail": "본인 추천인코드는 사용할 수 없습니다."}

        referrer = (
            db.query(Community_User)
            .filter(Community_User.referral_code == input_code)
            .first()
        )
        if not referrer:
            db.rollback()
            return {"status": 6, "detail": "추천인코드가 올바르지 않습니다."}

        try:
            db.add(
                Referral(
                    referrer_user_id=referrer.id,
                    referred_user_id=user.id,
                    referrer_code=input_code,
                )
            )
            db.flush()  # 아래 추천인 수 집계에 방금 추가한 Referral이 포함되도록

            bonus = 1000
            referral_bonus_referred_amount = bonus
            referral_bonus_referrer_amount = bonus

            # 추천인 포인트 적립
            referrer.point_balance = int(referrer.point_balance or 0) + bonus
            db.add(Point(user_id=referrer.id, reason="referral_bonus_referrer", amount=bonus))

            # --- 추천인 수 기반 자동 등급 동기화(등급 상승 시 보상 지급) ---
            ref_cnt = (
                db.query(func.count(Referral.id))
                .filter(Referral.referrer_user_id == referrer.id)
                .scalar()
                or 0
            )
            _apply_user_grade_upgrade(db, referrer, int(ref_cnt))

            # 피추천인 포인트 적립
            user.point_balance = int(user.point_balance or 0) + bonus
            db.add(Point(user_id=user.id, reason="referral_bonus_referred", amount=bonus))

            # 추천인에게 "미확인 알림" 누적(앱 실행 시 Alert로 보여주기 위함)
            db.add(
                Notification(
                    user_id=int(referrer.id),
                    type="referral",
                    title="추천인 가입 포인트 지급",
                    body=f"{user.username}님이 추천인코드로 가입하여 {bonus}점이 지급되었습니다.",
                    data={
                        "referred_username": user.username,
                        "amount": bonus,
                        "reason": "referral_bonus_referrer",
                    },
                    is_read=False,
                )
            )

        except IntegrityError as e:
            # 사용자 요청에 따라 referral/point 테이블 제약조건을 제거하므로
            # 여기서는 "1회 제한" 같은 메시지를 내지 않고, DB 오류로만 처리합니다.
            db.rollback()

            pgcode = getattr(getattr(e, "orig", None), "pgcode", None)

            # FK violation (23503): 대부분 referral/point 테이블 FK가 users(id)를 참조하는데
            # 앱은 community_users(id)를 넣는 경우 발생
            if pgcode == "23503":
                return {
                    "status": 8,
                    "detail": "DB 제약조건(FK) 오류로 추천인 포인트 지급에 실패했습니다. referral/point 테이블 FK가 community_users(id)를 참조하는지 확인해주세요.",
                }

            # 그 외
            return {"status": 8, "detail": "추천인 처리 중 DB 오류가 발생했습니다."}

    db.commit()
    db.refresh(user)

    # 회원가입 푸쉬 알림(오너 대상) - 실패해도 회원가입 성공 처리
    try:
        notify_owners_event(
            db,
            title="회원가입 알림",
            body=f"새 회원 가입: {user.username}",
            data={"event": "signup", "username": user.username},
        )
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        print("[WARN] notify_owners_event(signup) failed:", e)

    return {
        "status": 0,
        "signup_bonus_amount": signup_bonus_amount,
        "referral_bonus_referred_amount": referral_bonus_referred_amount,
        "referral_bonus_referrer_amount": referral_bonus_referrer_amount,
    }


class AppVersionOut(BaseModel):
    status: int = 0
    platform: Literal["android", "ios"]
    current_version: Optional[str] = None
    latest_version: str
    min_supported_version: str
    force_update: bool
    store_url: Optional[str] = None
    message: Optional[str] = None


def _version_parts(v: str) -> List[int]:
    """
    "1.2.3" 형태 버전을 비교 가능한 숫자 배열로 변환합니다.
    - 숫자 이외 문자는 무시(예: "1.0.0-beta" -> 1.0.0)
    """
    s = (v or "").strip()
    if not s:
        return [0]
    parts = s.split(".")
    nums: List[int] = []
    for p in parts:
        m = re.match(r"(\d+)", (p or "").strip())
        nums.append(int(m.group(1)) if m else 0)
    # trailing 0 정리(1.0.0 == 1)
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    return nums or [0]


def _is_version_lt(a: str, b: str) -> bool:
    pa = _version_parts(a)
    pb = _version_parts(b)
    n = max(len(pa), len(pb))
    for i in range(n):
        av = pa[i] if i < len(pa) else 0
        bv = pb[i] if i < len(pb) else 0
        if av < bv:
            return True
        if av > bv:
            return False
    return False


@app.get("/community/app/version", response_model=AppVersionOut)
def community_app_version(
    platform: Literal["android", "ios"] = Query(...),
    current_version: Optional[str] = Query(None),
):
    """
    앱 시작 시 버전 체크(강제 업데이트용).
    - 최신 버전이 아니면 force_update=True
    환경변수:
      - APP_ANDROID_LATEST_VERSION / APP_ANDROID_MIN_SUPPORTED_VERSION / APP_ANDROID_STORE_URL / APP_ANDROID_PACKAGE
      - APP_IOS_LATEST_VERSION / APP_IOS_MIN_SUPPORTED_VERSION / APP_IOS_STORE_URL
      - APP_FORCE_UPDATE_MESSAGE
    """
    msg = (os.getenv("APP_FORCE_UPDATE_MESSAGE", "") or "").strip() or "최신 버전으로 업데이트 후 이용해 주세요."

    if platform == "android":
        latest = (os.getenv("APP_ANDROID_LATEST_VERSION", "") or "").strip()
        min_supported = (os.getenv("APP_ANDROID_MIN_SUPPORTED_VERSION", "") or "").strip()
        pkg = (os.getenv("APP_ANDROID_PACKAGE", "") or "").strip() or "com.smartgauge.bunyangpro"
        store_url = (os.getenv("APP_ANDROID_STORE_URL", "") or "").strip() or f"market://details?id={pkg}"
    else:
        latest = (os.getenv("APP_IOS_LATEST_VERSION", "") or "").strip()
        min_supported = (os.getenv("APP_IOS_MIN_SUPPORTED_VERSION", "") or "").strip()
        store_url = (os.getenv("APP_IOS_STORE_URL", "") or "").strip() or None

    # 값이 비어있으면 안전한 기본값으로 보정
    # - 운영에서 환경변수 설정이 누락되면, 의도치 않게 전 사용자 강제업데이트가 걸릴 수 있어
    #   기본값은 "현재 버전 == 최신"으로 간주합니다.
    if not latest and not min_supported:
        latest = current_version or "0.0.0"
        min_supported = latest
    else:
        latest = latest or min_supported
        min_supported = min_supported or latest

    force_update = False
    if current_version:
        # 요구사항: 최신 버전이 아니면 강제 업데이트
        if _is_version_lt(current_version, latest):
            force_update = True

    return {
        "status": 0,
        "platform": platform,
        "current_version": current_version,
        "latest_version": latest,
        "min_supported_version": min_supported,
        "force_update": force_update,
        "store_url": store_url,
        "message": msg,
    }


@app.get("/community/referrals/by-referrer/{username}")
def list_referrals_by_referrer(username: str, db: Session = Depends(get_db)):
    """
    내가 추천한 회원 목록(닉네임 기준).
    """
    referrer = db.query(Community_User).filter(Community_User.username == username).first()
    if not referrer:
        return {"status": 1, "items": []}

    rows = (
        db.query(Referral, Community_User.username.label("referred_username"))
        .join(Community_User, Community_User.id == Referral.referred_user_id)
        .filter(Referral.referrer_user_id == referrer.id)
        .order_by(Referral.created_at.desc(), Referral.id.desc())
        .all()
    )

    items = [
        {
            "id": r.Referral.id,
            "referred_username": r.referred_username,
            "created_at": r.Referral.created_at.isoformat() if r.Referral.created_at else None,
        }
        for r in rows
    ]

    return {"status": 0, "items": items}


def _mask_nickname(value: str) -> str:
    """
    닉네임을 앞 2글자만 보여주고 나머지는 '*'로 마스킹합니다.
    예) '홍길동' -> '홍길*', 'ab' -> 'ab', 'a' -> 'a'
    """
    s = (value or "").strip()
    if len(s) <= 2:
        return s
    return s[:2] + ("*" * (len(s) - 2))


@app.get("/community/referrals/ranking")
def referral_ranking(db: Session = Depends(get_db)):
    """
    추천인 기준 랭킹.
    응답 형식: 순위 / 닉네임(2글자 + 마스킹) / 추천인 수
    - 순위는 제한 없이(서버에서 limit 걸지 않음) 반환합니다.
    """
    rows = (
        db.query(
            Community_User.id.label("user_id"),
            Community_User.username.label("username"),
            func.count(Referral.id).label("referral_count"),
        )
        .join(Referral, Referral.referrer_user_id == Community_User.id)
        .group_by(Community_User.id, Community_User.username)
        .order_by(func.count(Referral.id).desc(), Community_User.id.asc())
        .all()
    )

    items = [
        {
            "rank": idx,
            "nickname": _mask_nickname(r.username or ""),
            "referral_count": int(r.referral_count or 0),
        }
        for idx, r in enumerate(rows, start=1)
    ]

    return {"status": 0, "items": items}


@app.get("/community/referrals/network/{username}")
def referral_network(
    username: str,
    max_depth: int = Query(20),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """
    내 아래로 추천인 인맥(트리/다단계) 조회.
    - nickname은 Community_User.username을 그대로 사용
    - cursor는 offset 문자열("0", "100") 기반
    - total_count는 root 제외, 하위 인맥 distinct 기준
    - 100명 달성 시 1회 보상(100만 포인트) 지급
    """
    try:
        root = db.query(Community_User).filter(Community_User.username == username).first()
        if not root:
            return {
                "status": 1,
                "root_username": username,
                "total_count": 0,
                "items": [],
                "next_cursor": None,
                "reward": {"threshold": 100, "amount": 1_000_000, "granted": False},
            }

        # 방어적 파싱/제한
        try:
            offset = int((cursor or "0").strip() or "0")
        except Exception:
            offset = 0
        if offset < 0:
            offset = 0

        try:
            md = int(max_depth or 20)
        except Exception:
            md = 20
        if md < 1:
            md = 1
        # 과도한 재귀로 DB 부하가 커지는 것을 방지(Contract 변경 없이 내부 제한)
        md = min(md, 200)

        cte_base = """
WITH RECURSIVE downline AS (
    SELECT
        r.referred_user_id AS descendant_id,
        1 AS depth,
        ARRAY[r.referrer_user_id, r.referred_user_id] AS path
    FROM referral r
    WHERE r.referrer_user_id = :root_id
    UNION ALL
    SELECT
        r.referred_user_id AS descendant_id,
        d.depth + 1 AS depth,
        d.path || r.referred_user_id AS path
    FROM referral r
    JOIN downline d ON r.referrer_user_id = d.descendant_id
    WHERE d.depth < :max_depth
      AND NOT (r.referred_user_id = ANY(d.path))
)
"""

        total_sql = cte_base + """
SELECT COUNT(*) AS total_count
FROM (SELECT DISTINCT descendant_id FROM downline) s
"""

        total_row = db.execute(
            text(total_sql),
            {"root_id": int(root.id), "max_depth": md},
        ).first()
        total_count = int(getattr(total_row, "total_count", 0) or 0)

        items_sql = cte_base + """
, dedup AS (
    SELECT descendant_id, MIN(depth) AS depth
    FROM downline
    GROUP BY descendant_id
)
SELECT
    u.username AS nickname,
    d.depth AS depth,
    u.signup_date AS joined_at
FROM dedup d
JOIN community_users u ON u.id::bigint = d.descendant_id
ORDER BY d.depth ASC, u.signup_date ASC NULLS LAST, u.username ASC
OFFSET :offset
LIMIT :limit
"""

        rows = db.execute(
            text(items_sql),
            {
                "root_id": int(root.id),
                "max_depth": md,
                "offset": int(offset),
                "limit": int(limit),
            },
        ).fetchall()

        items = [
            {
                "nickname": r.nickname,
                "depth": int(r.depth or 0),
                "joined_at": r.joined_at.isoformat() if getattr(r, "joined_at", None) else None,
            }
            for r in rows
        ]

        next_cursor = str(offset + int(limit)) if (offset + int(limit)) < total_count else None

        # --- 100명 달성 보상(1회성, 동시요청 중복 지급 방지) ---
        reward_granted = False
        if total_count >= 100:
            try:
                # user row lock으로 동일 유저의 보상 지급을 직렬화
                locked = (
                    db.query(Community_User)
                    .filter(Community_User.id == root.id)
                    .with_for_update()
                    .first()
                )
                if locked:
                    already = (
                        db.query(Point.id)
                        .filter(Point.user_id == locked.id, Point.reason == "referral_network_100")
                        .first()
                        is not None
                    )
                    if already:
                        reward_granted = True
                    else:
                        locked.point_balance = int(getattr(locked, "point_balance", 0) or 0) + 1_000_000
                        db.add(Point(user_id=locked.id, reason="referral_network_100", amount=1_000_000))
                        db.add(locked)
                        db.commit()
                        reward_granted = True
            except Exception:
                db.rollback()
                # 보상 지급 중 오류가 나더라도 Contract에 맞춰 status=8로 반환
                return {"status": 8}

        return {
            "status": 0,
            "root_username": str(root.username),
            "total_count": total_count,
            "items": items,
            "next_cursor": next_cursor,
            "reward": {"threshold": 100, "amount": 1_000_000, "granted": bool(reward_granted)},
        }
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return {"status": 8}


@app.get("/community/points/{username}")
def list_points(username: str, db: Session = Depends(get_db)):
    """
    내 포인트 적립/사용 내역(원장).
    """
    def _to_kst_iso(dt: datetime | None) -> str | None:
        # tzinfo 없으면 UTC로 간주 후 KST(UTC+9)로 변환
        if not dt:
            return None
        try:
            if getattr(dt, "tzinfo", None) is None:
                dt = dt.replace(tzinfo=timezone.utc)
            kst = timezone(timedelta(hours=9))
            return dt.astimezone(kst).isoformat()
        except Exception:
            try:
                return dt.isoformat()
            except Exception:
                return None

    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1, "items": []}

    rows = (
        db.query(Point)
        .filter(Point.user_id == user.id)
        .order_by(Point.created_at.desc(), Point.id.desc())
        .limit(500)
        .all()
    )

    items = [
        {
            "id": p.id,
            "reason": p.reason,
            "amount": int(p.amount),
            "created_at": _to_kst_iso(p.created_at),
        }
        for p in rows
    ]

    return {"status": 0, "items": items}


ATTENDANCE_REASON = "attendance_daily"
ATTENDANCE_AMOUNT = 200
KST = timezone(timedelta(hours=9))


def _kst_today_bounds_utc():
    """
    한국시간(KST) 기준 '오늘'의 시작/끝을 UTC datetime으로 반환.
    """
    now_kst = datetime.now(tz=KST)
    start_kst = datetime.combine(now_kst.date(), datetime.min.time(), tzinfo=KST)
    end_kst = start_kst + timedelta(days=1)
    return start_kst.astimezone(timezone.utc), end_kst.astimezone(timezone.utc)


@app.get("/community/points/attendance/status/{username}")
def attendance_status(
    username: str,
    db: Session = Depends(get_db),
):
    """
    출석체크(일 1회) 수령 여부 조회.
    - KST 기준 '오늘'에 attendance_daily 기록이 있으면 claimed=True
    """
    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1, "claimed": False}

    # 신규 필드(last_attendance_date)가 있으면 우선 사용
    today_kst = datetime.now(tz=KST).date()
    if getattr(user, "last_attendance_date", None) == today_kst:
        return {"status": 0, "claimed": True, "amount": ATTENDANCE_AMOUNT}

    start_utc, end_utc = _kst_today_bounds_utc()
    exists = (
        db.query(Point.id)
        .filter(
            Point.user_id == user.id,
            Point.reason == ATTENDANCE_REASON,
            Point.created_at >= start_utc,
            Point.created_at < end_utc,
        )
        .first()
        is not None
    )

    return {"status": 0, "claimed": exists, "amount": ATTENDANCE_AMOUNT}


@app.post("/community/points/attendance/claim/{username}")
def attendance_claim(
    username: str,
    db: Session = Depends(get_db),
):
    """
    출석체크 포인트 지급 (KST 기준 하루 1회, 200P).
    - point 테이블에 기록되고 /community/points/{username}에서 조회 가능
    """
    # 동시 클릭(중복 지급) 방지: user row를 잠그고 확인 후 지급
    user = (
        db.query(Community_User)
        .filter(Community_User.username == username)
        .with_for_update()
        .first()
    )
    if not user:
        return {"status": 1, "claimed": False}

    today_kst = datetime.now(tz=KST).date()
    if getattr(user, "last_attendance_date", None) == today_kst:
        return {"status": 2, "claimed": True, "amount": 0, "point_balance": int(user.point_balance or 0)}

    start_utc, end_utc = _kst_today_bounds_utc()
    already = (
        db.query(Point.id)
        .filter(
            Point.user_id == user.id,
            Point.reason == ATTENDANCE_REASON,
            Point.created_at >= start_utc,
            Point.created_at < end_utc,
        )
        .first()
        is not None
    )
    if already:
        # 과거 방식(point 테이블)로 이미 지급된 경우에도 신규 필드 동기화
        try:
            user.last_attendance_date = today_kst
            db.commit()
            db.refresh(user)
        except Exception:
            db.rollback()
        return {"status": 2, "claimed": True, "amount": 0, "point_balance": int(user.point_balance or 0)}

    user.point_balance = int(user.point_balance or 0) + ATTENDANCE_AMOUNT
    user.last_attendance_date = today_kst
    db.add(Point(user_id=user.id, reason=ATTENDANCE_REASON, amount=ATTENDANCE_AMOUNT))
    db.commit()
    db.refresh(user)

    return {"status": 0, "claimed": True, "amount": ATTENDANCE_AMOUNT, "point_balance": int(user.point_balance or 0)}


@app.post("/community/popup/seen")
def mark_popup_seen(
    me: Community_User = Depends(get_current_community_user),
    db: Session = Depends(get_db),
):
    """
    팝업(공지/이벤트 등) 마지막 확인 시각 저장.
    - community_users.popup_last_seen_at 갱신
    """
    user = (
        db.query(Community_User)
        .filter(Community_User.id == me.id)
        .with_for_update()
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.popup_last_seen_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return {
        "status": 0,
        "popup_last_seen_at": user.popup_last_seen_at.isoformat() if user.popup_last_seen_at else None,
    }


@app.get("/community/stats/today")
def community_today_stats(db: Session = Depends(get_db)):
    """
    고객센터 '오늘의 현황' 용 집계.
    - 전체 회원 / 오늘 신규회원
    - 전체 방문자수(누적) / 오늘 방문자수(근사치: 오늘 popup_last_seen_at 갱신)
    - 전체 구인글/오늘 구인글 (post_type=1)
    - 전체 광고글/오늘 광고글 (post_type=4)
    - 전체 수다글/오늘 수다글 (post_type=3)
    - 기존 호환을 위해 new_sites/realtime_visitors도 함께 내려줍니다.
    """
    try:
        now_kst = datetime.now(tz=KST)
        today_kst = now_kst.date()
        start_utc, end_utc = _kst_today_bounds_utc()

        # posts: today
        today_job_posts = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.created_at >= start_utc,
                Community_Post.created_at < end_utc,
            )
            .scalar()
            or 0
        )

        today_ad_posts = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 4,
                Community_Post.status == "published",
                Community_Post.created_at >= start_utc,
                Community_Post.created_at < end_utc,
            )
            .scalar()
            or 0
        )

        today_chat_posts = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 3,
                Community_Post.status == "published",
                Community_Post.created_at >= start_utc,
                Community_Post.created_at < end_utc,
            )
            .scalar()
            or 0
        )

        # posts: total
        total_job_posts = (
            db.query(func.count(Community_Post.id))
            .filter(Community_Post.post_type == 1, Community_Post.status == "published")
            .scalar()
            or 0
        )

        total_ad_posts = (
            db.query(func.count(Community_Post.id))
            .filter(Community_Post.post_type == 4, Community_Post.status == "published")
            .scalar()
            or 0
        )

        total_chat_posts = (
            db.query(func.count(Community_Post.id))
            .filter(Community_Post.post_type == 3, Community_Post.status == "published")
            .scalar()
            or 0
        )

        new_users = (
            db.query(func.count(Community_User.id))
            .filter(Community_User.signup_date == today_kst)
            .scalar()
            or 0
        )

        today_visitors = (
            db.query(func.count(Community_User.id))
            .filter(
                Community_User.popup_last_seen_at.isnot(None),
                Community_User.popup_last_seen_at >= start_utc,
                Community_User.popup_last_seen_at < end_utc,
            )
            .scalar()
            or 0
        )

        total_visitors = (
            db.query(func.count(Community_User.id))
            .filter(Community_User.popup_last_seen_at.isnot(None))
            .scalar()
            or 0
        )

        total_users = (
            db.query(func.count(Community_User.id))
            .scalar()
            or 0
        )

        return {
            "status": 0,
            "date": today_kst.isoformat(),
            # required fields (new)
            "total_users": int(total_users),
            "new_users": int(new_users),
            "total_visitors": int(total_visitors),
            "today_visitors": int(today_visitors),
            "total_job_posts": int(total_job_posts),
            "today_job_posts": int(today_job_posts),
            "total_ad_posts": int(total_ad_posts),
            "today_ad_posts": int(today_ad_posts),
            "total_chat_posts": int(total_chat_posts),
            "today_chat_posts": int(today_chat_posts),
            # backward compatible aliases
            "new_sites": int(today_job_posts),
            "realtime_visitors": int(today_visitors),
        }
    except Exception:
        return {
            "status": 8,
            "date": None,
            "total_users": 0,
            "new_users": 0,
            "total_visitors": 0,
            "today_visitors": 0,
            "total_job_posts": 0,
            "today_job_posts": 0,
            "total_ad_posts": 0,
            "today_ad_posts": 0,
            "total_chat_posts": 0,
            "today_chat_posts": 0,
            # backward compatible aliases
            "new_sites": 0,
            "realtime_visitors": 0,
        }


@app.get("/community/cash/{username}")
def list_cash(username: str, db: Session = Depends(get_db)):
    """
    내 캐시 충전/사용 내역(원장).
    """
    def _to_kst_iso(dt: datetime | None) -> str | None:
        # tzinfo 없으면 UTC로 간주 후 KST(UTC+9)로 변환
        if not dt:
            return None
        try:
            if getattr(dt, "tzinfo", None) is None:
                dt = dt.replace(tzinfo=timezone.utc)
            kst = timezone(timedelta(hours=9))
            return dt.astimezone(kst).isoformat()
        except Exception:
            try:
                return dt.isoformat()
            except Exception:
                return None

    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        return {"status": 1, "items": []}

    rows = (
        db.query(Cash)
        .filter(Cash.user_id == user.id)
        .order_by(Cash.created_at.desc(), Cash.id.desc())
        .limit(500)
        .all()
    )

    items = [
        {
            "id": c.id,
            "reason": c.reason,
            "amount": int(c.amount),
            "created_at": _to_kst_iso(c.created_at),
        }
        for c in rows
    ]

    return {"status": 0, "items": items}


# ==================== TossPayments: 주문 생성 / 결제 페이지 / 승인(confirm) ====================

class TossOrderCreateRequest(BaseModel):
    username: str
    amount: int

class TossOrderCreateResponse(BaseModel):
    status: int
    orderId: str
    amount: int
    orderName: str
    customerName: str


@app.post("/orders/create", response_model=TossOrderCreateResponse)
def create_order_for_toss(req: TossOrderCreateRequest, db: Session = Depends(get_db)):
    """
    캐시 충전용 주문 생성(SSOT).
    - amount는 서버에서 허용된 값만 인정
    - payments 테이블에 PENDING row 생성
    """
    username = (req.username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    try:
        amount = int(req.amount)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid amount")

    if amount not in ALLOWED_CASH_AMOUNTS:
        raise HTTPException(status_code=400, detail="amount not allowed")

    user = db.query(Community_User).filter(Community_User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    order_id = uuid.uuid4()
    row = Payment(
        order_id=order_id,
        user_id=user.id,
        amount=amount,
        status="PENDING",
    )
    db.add(row)
    db.commit()

    order_name = "캐시 충전"
    customer_name = (user.name or user.username or "고객").strip()
    return TossOrderCreateResponse(
        status=0,
        orderId=str(order_id),
        amount=amount,
        orderName=order_name,
        customerName=customer_name,
    )


@app.get("/pay/toss")
def pay_toss_page(
    orderId: str = Query(...),
    amount: int = Query(...),
    orderName: str = Query("캐시 충전"),
    customerName: str = Query("고객"),
    customerEmail: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """
    TossPayments 결제창(개별 API) 요청 페이지(HTML).
    - orderId/amount는 DB(SSOT) 기준으로 검증
    """
    if not TOSS_CLIENT_KEY:
        raise HTTPException(status_code=500, detail="TOSS_CLIENT_KEY not configured")

    try:
        order_uuid = uuid.UUID(orderId)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid orderId")

    pay = db.query(Payment).filter(Payment.order_id == order_uuid).first()
    if not pay:
        raise HTTPException(status_code=404, detail="order not found")

    if pay.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"order not payable (status={pay.status})")

    if int(pay.amount) != int(amount):
        raise HTTPException(status_code=400, detail="amount mismatch")

    # Toss가 paymentKey/orderId/amount를 query로 붙여서 redirect
    success_url = f"{TOSS_APP_SCHEME}://toss/success"
    fail_url = f"{TOSS_APP_SCHEME}://toss/fail"

    # customerEmail은 선택값. (없으면 Toss가 무시)
    customer_email_js = (
        f'"{customerEmail}"' if customerEmail else "undefined"
    )

    html = f"""<!doctype html>
<html lang="ko">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <title>TossPayments 결제</title>
    <style>
      body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 24px; }}
      .box {{ max-width: 520px; margin: 0 auto; }}
      .muted {{ color: #666; font-size: 13px; }}
      .err {{ color: #b00020; white-space: pre-wrap; }}
    </style>
    <script src="https://js.tosspayments.com/v1/payment"></script>
  </head>
  <body>
    <div class="box">
      <h3>결제 진행 중...</h3>
      <p class="muted">잠시만 기다려주세요. 결제창이 자동으로 열립니다.</p>
      <pre id="err" class="err"></pre>
    </div>
    <script>
      (function() {{
        try {{
          var clientKey = "{TOSS_CLIENT_KEY}";
          var tossPayments = TossPayments(clientKey);
          tossPayments.requestPayment("카드", {{
            amount: {int(amount)},
            orderId: "{orderId}",
            orderName: {json.dumps(orderName)},
            customerName: {json.dumps(customerName)},
            customerEmail: {customer_email_js},
            successUrl: "{success_url}",
            failUrl: "{fail_url}",
          }});
        }} catch (e) {{
          var el = document.getElementById("err");
          el.textContent = (e && (e.stack || e.message)) ? (e.stack || e.message) : String(e);
        }}
      }})();
    </script>
  </body>
</html>"""

    return HTMLResponse(content=html, status_code=200)


class TossConfirmRequest(BaseModel):
    paymentKey: str
    orderId: str
    amount: int


@app.post("/payments/toss/confirm")
def confirm_toss_payment(req: TossConfirmRequest, db: Session = Depends(get_db)):
    """
    TossPayments 결제 승인(confirm) - SSOT 검증 필수.
    - orderId/amount는 DB와 일치해야 함
    - 이미 PAID면 중복 승인 방지(멱등 처리)
    - 성공 시 payments.status=PAID + cash_balance 증가 + cash 원장 기록
    """
    if not TOSS_SECRET_KEY:
        raise HTTPException(status_code=500, detail="TOSS_SECRET_KEY not configured")

    payment_key = (req.paymentKey or "").strip()
    if not payment_key:
        raise HTTPException(status_code=400, detail="paymentKey required")

    try:
        order_uuid = uuid.UUID(req.orderId)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid orderId")

    try:
        amount = int(req.amount)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid amount")

    # 동시 confirm 방지: row lock
    pay = (
        db.query(Payment)
        .filter(Payment.order_id == order_uuid)
        .with_for_update()
        .first()
    )
    if not pay:
        raise HTTPException(status_code=404, detail="order not found")

    if int(pay.amount) != amount:
        raise HTTPException(status_code=400, detail="amount mismatch")

    if pay.status == "PAID":
        return {"status": 0, "alreadyPaid": True, "orderId": str(pay.order_id), "amount": int(pay.amount), "paymentKey": pay.payment_key}

    if pay.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"order not confirmable (status={pay.status})")

    # Toss confirm API 호출
    auth = base64.b64encode(f"{TOSS_SECRET_KEY}:".encode("utf-8")).decode("utf-8")
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/json",
    }
    payload = {"paymentKey": payment_key, "orderId": str(order_uuid), "amount": amount}

    try:
        if httpx is not None:
            resp = httpx.post(
                "https://api.tosspayments.com/v1/payments/confirm",
                headers=headers,
                json=payload,
                timeout=20.0,
            )
            resp_status = resp.status_code
            resp_json = resp.json
            resp_text = resp.text
        else:
            r = requests.post(
                "https://api.tosspayments.com/v1/payments/confirm",
                headers=headers,
                json=payload,
                timeout=20,
            )
            resp_status = r.status_code
            resp_text = r.text
            resp_json = r.json
    except Exception as e:
        # 네트워크/타임아웃: 주문은 여전히 PENDING으로 유지
        raise HTTPException(status_code=502, detail=f"toss confirm request failed: {e}")

    if resp_status < 200 or resp_status >= 300:
        # 실패 기록
        pay.status = "FAILED"
        db.commit()
        try:
            detail = resp_json()
        except Exception:
            detail = {"message": resp_text}
        raise HTTPException(status_code=400, detail={"toss": detail})

    data = resp_json()

    # approvedAt는 ISO8601 문자열. 파싱 실패 시 None 허용
    approved_at = None
    try:
        approved_at_raw = data.get("approvedAt")
        if approved_at_raw:
            approved_at = datetime.fromisoformat(approved_at_raw.replace("Z", "+00:00"))
    except Exception:
        approved_at = None

    pay.status = "PAID"
    pay.payment_key = payment_key
    pay.approved_at = approved_at

    # 캐시 충전 반영(SSOT: payments.user_id 기준)
    user = (
        db.query(Community_User)
        .filter(Community_User.id == pay.user_id)
        .with_for_update()
        .first()
    )
    if not user:
        # 결제는 승인됐지만 유저가 없다면 치명적 -> 롤백 불가 상황 방지 위해 FAILED로 바꾸지 않고 에러만 반환
        db.commit()
        raise HTTPException(status_code=500, detail="user not found for payment")

    user.cash_balance = int(user.cash_balance or 0) + int(pay.amount)
    db.add(Cash(user_id=user.id, reason="toss_cash_charge", amount=int(pay.amount)))

    db.commit()

    return {
        "status": 0,
        "orderId": str(pay.order_id),
        "amount": int(pay.amount),
        "paymentKey": pay.payment_key,
        "approvedAt": pay.approved_at.isoformat() if pay.approved_at else None,
        "toss": {
            "method": data.get("method"),
            "status": data.get("status"),
        },
    }


@app.get("/community/user/{username}")
def get_user(username: str, db: Session = Depends(get_db)):

    user = db.query(Community_User).filter(Community_User.username == username).first()

    if not user:
        return {"status": 1}   

    # signup_date를 문자열로 변환 (None이면 None 유지)
    signup_date_str = user.signup_date.isoformat() if user.signup_date else None
    popup_last_seen_at_str = user.popup_last_seen_at.isoformat() if getattr(user, "popup_last_seen_at", None) else None
    last_attendance_date_str = user.last_attendance_date.isoformat() if getattr(user, "last_attendance_date", None) else None
    
    return {
        "status": 0,
        "user": {
            "username": username,
            "name": user.name,
            "phone_number": user.phone_number,
            "region": user.region,
            "signup_date": signup_date_str,
            "point_balance": user.point_balance if user.point_balance is not None else 0,
            "cash_balance": user.cash_balance if user.cash_balance is not None else 0,
            "admin_acknowledged": user.admin_acknowledged if user.admin_acknowledged is not None else False,
            "referral_code": user.referral_code,
            "custom_industry_codes": list(getattr(user, "custom_industry_codes", None) or []),
            "custom_region_codes": list(getattr(user, "custom_region_codes", None) or []),
            "popup_last_seen_at": popup_last_seen_at_str,
            "last_attendance_date": last_attendance_date_str,
            "marketing_consent": bool(getattr(user, "marketing_consent", False)),
        }
    }


class UserUpdateRequest(BaseModel):
    username: str | None = Field(default=None, min_length=2, max_length=50)  # 새 아이디
    password: str | None = Field(default=None, min_length=2, max_length=255)
    password_confirm: str | None = Field(default=None, min_length=2, max_length=255)
    name: str | None = Field(default=None, max_length=50)       # 실명
    phone_number: str | None = Field(default=None, max_length=20)
    phone_verification_id: str | None = Field(default=None, max_length=80)
    region: str | None = Field(default=None, max_length=100)
    # community_users 신규 필드(2026-01)
    marketing_consent: bool | None = None
    custom_industry_codes: list[str] | None = None
    custom_region_codes: list[str] | None = None

@app.put("/community/user/{username}")
def update_user(
    username: str,
    req: UserUpdateRequest,
    db: Session = Depends(get_db)
):
    # 🔹 1. 기존 유저 조회
    user = (
        db.query(Community_User)
        .filter(Community_User.username == username)
        .first()
    )

    if not user:
        return {"status": 1}  # 유저 없음

    old_username = None

    # 🔹 2. 닉네임 변경
    if req.username is not None and req.username != username:
        new_username = req.username

        # 중복 체크
        exists = (
            db.query(Community_User)
            .filter(Community_User.username == new_username)
            .first()
        )
        if exists:
            return {"status": 2}  # 닉네임 중복

        old_username = username

        user.username = new_username
        db.flush()  

        db.query(Post_Like).filter(
        Post_Like.username == old_username
        ).update(
        {"username": new_username},
        synchronize_session=False
        )

    if req.password is not None:
        if req.password_confirm is None:
            return {"status": 3} 

        if req.password != req.password_confirm:
            return {"status": 4}  

        user.password_hash = hashlib.sha256(
            req.password.encode()
        ).hexdigest()

    if req.name is not None:
        user.name = req.name

    if req.phone_number is not None:
        # phone_number는 digits 형태로 저장(하이픈 제거)
        new_digits = _normalize_phone(req.phone_number)
        old_digits = _normalize_phone(user.phone_number or "")

        # 실제 변경인 경우에만 휴대폰 인증을 강제
        if new_digits != old_digits:
            if not req.phone_verification_id:
                return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}
            try:
                verified_digits = _require_verified_phone(db, req.phone_number, req.phone_verification_id)
            except Exception:
                return {"status": 9, "detail": "휴대폰 인증이 필요합니다."}
            user.phone_number = verified_digits
        else:
            # 변경이 아니면 기존 값을 유지하되, 혹시 하이픈 포함 값이 들어있다면 정규화
            user.phone_number = old_digits if old_digits else user.phone_number

    if req.region is not None:
        user.region = req.region

    if req.marketing_consent is not None:
        user.marketing_consent = bool(req.marketing_consent)

    if req.custom_industry_codes is not None:
        user.custom_industry_codes = list(req.custom_industry_codes or [])

    if req.custom_region_codes is not None:
        user.custom_region_codes = list(req.custom_region_codes or [])

    db.commit()
    db.refresh(user)

    return {
        "status": 0,
        "username": user.username,      
        "old_username": old_username      
    }

@app.delete("/community/user/{username}")
def delete_user(username: str, db: Session = Depends(get_db)):

    user = db.query(Community_User).filter(Community_User.username == username).first()

    if not user:
        return {"status": 1}   

    deleted_username = user.username
    db.delete(user)
    db.commit()

    # 회원 탈퇴 푸쉬 알림(오너 대상) - 실패해도 탈퇴 성공 처리
    try:
        notify_owners_event(
            db,
            title="회원탈퇴 알림",
            body=f"회원 탈퇴: {deleted_username}",
            data={"event": "withdraw", "username": deleted_username},
        )
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        print("[WARN] notify_owners_event(withdraw) failed:", e)

    return {"status": 0}

@app.get("/community/mypage/{username}")
def get_mypage(username: str, db: Session = Depends(get_db)):

    user = (
        db.query(Community_User)
        .filter(Community_User.username == username)
        .first()
    )

    if not user:
        return {"status": 1}  

    rows = (
        db.query(
            Community_Post.post_type,
            func.count(Community_Post.id).label("cnt"),
        )
        .filter(
            Community_Post.user_id == user.id,
            Community_Post.post_type.in_([1, 3, 4]),
        )
        .group_by(Community_Post.post_type)
        .all()
    )

    counts = {1: 0, 3: 0, 4: 0}
    for post_type, cnt in rows:
        counts[post_type] = cnt

    # 내가 추천한 회원 수
    referral_count = (
        db.query(func.count(Referral.id))
        .filter(Referral.referrer_user_id == user.id)
        .scalar()
        or 0
    )

    # --- 추천인 수 기반 자동 등급 동기화(등급 상승 시 보상 지급) ---
    if _apply_user_grade_upgrade(db, user, int(referral_count)):
        db.commit()
        db.refresh(user)

    # signup_date를 문자열로 변환 (None이면 None 유지)
    signup_date_str = user.signup_date.isoformat() if user.signup_date else None
    
    return {
        "status": 0,
        "signup_date": signup_date_str,
        # user_grade: -1-일반회원 / 0-아마추어 / 1-세미프로 / 2-프로 / 3-마스터 / 4-레전드
        "user_grade": int(user.user_grade) if getattr(user, "user_grade", None) is not None else -1,
        "is_owner": bool(getattr(user, "is_owner", False)),
        "posts": {
            "type1": counts[1],
            "type3": counts[3],
            "type4": counts[4],
        },
        "point_balance": user.point_balance if user.point_balance is not None else 0,
        "cash_balance": user.cash_balance if user.cash_balance is not None else 0,
        "admin_acknowledged": user.admin_acknowledged if user.admin_acknowledged is not None else False,
        "referral_code": user.referral_code,
        "referral_count": int(referral_count),
    }


@app.post("/community/login", response_model=LoginResponse)
def community_login(req: LoginRequest2, db: Session = Depends(get_db)):

    user = db.query(Community_User).filter(Community_User.username == req.username).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()
    if user.password_hash != pw_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if req.push_token:
        user.push_token = req.push_token
        db.commit()

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": str(user.id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

    return LoginResponse(user_id=user.id, token=token)


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
    business_lat:  Optional[float] = None
    business_lng:  Optional[float] = None
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
    leader_use: Optional[bool] = None
    member_use: Optional[bool] = None
    total_fee: Optional[str] = None
    branch_fee: Optional[str] = None
    leader_fee: Optional[str] = None
    member_fee: Optional[str] = None
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
    business_lat:  Optional[float] = None
    business_lng:  Optional[float] = None
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
    leader_use: Optional[bool] = None
    member_use: Optional[bool] = None
    total_fee: Optional[str] = None
    branch_fee: Optional[str] = None
    leader_fee: Optional[str] = None
    member_fee: Optional[str] = None
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
    business_lat:  Optional[float] = None
    business_lng:  Optional[float] = None
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
    leader_use: Optional[bool] = None
    member_use: Optional[bool] = None
    total_fee: Optional[str] = None
    branch_fee: Optional[str] = None
    leader_fee: Optional[str] = None
    member_fee: Optional[str] = None
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

class UploadBase64Request(BaseModel):
    filename: str
    base64: str

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
    business_lat:  Optional[float] = None
    business_lng:  Optional[float] = None
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
    leader_use: Optional[bool] = None
    member_use: Optional[bool] = None
    total_fee: Optional[str] = None
    branch_fee: Optional[str] = None
    leader_fee: Optional[str] = None
    member_fee: Optional[str] = None
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

#--------------------Comments update-----------------------
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
    class Config: from_attributes = True

class CommentListOut(BaseModel):
    items: list[CommentOut]
    next_cursor: Optional[str] = None
#---------------------------------------------------------------

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
        .filter(
            Community_User_Restriction.user_id == int(user_id),
            Community_User_Restriction.post_type == pt,
        )
        .first()
    )
    if not r or not getattr(r, "restricted_until", None):
        return

    until = r.restricted_until
    if getattr(until, "tzinfo", None) is None:
        until = until.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    if now < until:
        raise HTTPException(
            status_code=403,
            detail=f"작성 제한 중입니다. post_type={pt}, 제한 만료: {until.isoformat()}",
        )

@app.post("/community/posts/{username}", response_model=PostOut)
def create_post(username: str, body: PostCreate, db: Session = Depends(get_db)):
    # 유저 row lock으로 캐시 차감/포스트 생성 원자성 보장
    user = (
        db.query(Community_User)
        .filter(Community_User.username == username)
        .with_for_update()
        .first()
    )
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
        workplace_lat = body.workplace_lat,
        workplace_lng = body.workplace_lng,
        business_lat = body.business_lat,
        business_lng = body.business_lng,
        job_industry=body.job_industry,
        job_category=body.job_category,
        province = body.province,
        city= body.city,
        pay_support=body.pay_support,
        meal_support=body.meal_support,
        house_support=body.house_support,
        company_developer=body.company_developer,
        company_constructor=body.company_constructor,
        company_trustee=body.company_trustee,
        company_agency=body.company_agency,
        agency_call=body.agency_call,
        status = body.status or "published",
        highlight_color = body.highlight_color,
        highlight_content = body.highlight_content,
        total_use = body.total_use,
        branch_use = body.branch_use,
        leader_use = body.leader_use,
        member_use = body.member_use,
        total_fee = body.total_fee,
        branch_fee = body.branch_fee,
        leader_fee = body.leader_fee,
        member_fee = body.member_fee,
        pay_use = body.pay_use,
        meal_use = body.meal_use,
        house_use = body.house_use,
        pay_sup = body.pay_sup,
        meal_sup = body.meal_sup,
        house_sup = body.house_sup,
        item1_use = body.item1_use,
        item1_type = body.item1_type,
        item1_sup = body.item1_sup,
        item2_use = body.item2_use,
        item2_type = body.item2_type,
        item2_sup = body.item2_sup,
        item3_use = body.item3_use,
        item3_type = body.item3_type,
        item3_sup = body.item3_sup,
        item4_use = body.item4_use,
        item4_type = body.item4_type,
        item4_sup = body.item4_sup,
        agent = body.agent,
        other_role_name=body.other_role_name,
        other_role_fee=body.other_role_fee,
        post_type= 1,
        card_type= card_type,
    )
   
    # ---- 구인글 작성 보상: 1000포인트 지급 + 마지막 작성 시각 갱신 ----
    if not is_admin_ack:
        user.point_balance = int(user.point_balance or 0) + 1000
        db.add(Point(user_id=userId, reason="recruit_post", amount=1000))
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
        workplace_lat = post.workplace_lat,
        workplace_lng = post.workplace_lng,
        business_lat = post.business_lat,
        business_lng = post.business_lng,
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
        status = post.status,
        highlight_color = post.highlight_color,
        highlight_content = post.highlight_content,
        total_use = post.total_use,
        branch_use = post.branch_use,
        leader_use = post.leader_use,
        member_use = post.member_use,
        total_fee = post.total_fee,
        branch_fee = post.branch_fee,
        leader_fee = post.leader_fee,
        member_fee = post.member_fee,
        pay_use = post.pay_use,
        meal_use = post.meal_use,
        house_use = post.house_use,
        pay_sup = post.pay_sup,
        meal_sup = post.meal_sup,
        house_sup = post.house_sup,
        item1_use = post.item1_use,
        item1_type = post.item1_type,
        item1_sup = post.item1_sup,
        item2_use = post.item2_use,
        item2_type = post.item2_type,
        item2_sup = post.item2_sup,
        item3_use = post.item3_use,
        item3_type = post.item3_type,
        item3_sup = post.item3_sup,
        item4_use = post.item4_use,
        item4_type = post.item4_type,
        item4_sup = post.item4_sup,
        agent = post.agent,
        other_role_name=getattr(post, "other_role_name", None),
        other_role_fee=getattr(post, "other_role_fee", None),
        post_type=post.post_type,
        card_type=post.card_type,
    )

@app.post("/community/posts/{username}/type/{post_type}", response_model=PostOut)
def create_post_plus(post_type:int, username: str, body: PostCreate, db: Session = Depends(get_db)):
    # 유저 row lock (포인트/캐시/작성제한 원자성 보장)
    user = (
        db.query(Community_User)
        .filter(Community_User.username == username)
        .with_for_update()
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="Invalid username")

    userId = user.id
    is_admin_ack = bool(getattr(user, "admin_acknowledged", False))

    # ---- 제재 enforcement: post_type(1/3/4) 작성 제한/차단 ----
    # 구인글(post_type=1)은 admin_acknowledged=True 이면 제재 우회(무제한 작성)
    if not (int(post_type) == 1 and is_admin_ack):
        _enforce_user_post_restriction(db, int(userId), int(post_type))

    # post_type == 1 (구인글): 하루 1회 제한 + 포인트 지급
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

        # 보상/작성시각 갱신
        user.last_recruit_posted_at = now_utc
        if not is_admin_ack:
            user.point_balance = int(user.point_balance or 0) + 1000
            db.add(Point(user_id=userId, reason="recruit_post", amount=1000))
    else:
        card_type = body.card_type

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
        workplace_lat = body.workplace_lat,
        workplace_lng = body.workplace_lng,
        business_lat = body.business_lat,
        business_lng = body.business_lng,
        job_industry=body.job_industry,
        job_category=body.job_category,
        pay_support=body.pay_support,
        meal_support=body.meal_support,
        house_support=body.house_support,
        company_developer=body.company_developer,
        company_constructor=body.company_constructor,
        company_trustee=body.company_trustee,
        company_agency=body.company_agency,
        agency_call=body.agency_call,
        status = body.status or "published",
        highlight_color = body.highlight_color,
        highlight_content = body.highlight_content,
        total_use = body.total_use,
        branch_use = body.branch_use,
        leader_use = body.leader_use,
        member_use = body.member_use,
        total_fee = body.total_fee,
        branch_fee = body.branch_fee,
        leader_fee = body.leader_fee,
        member_fee = body.member_fee,
        pay_use = body.pay_use,
        meal_use = body.meal_use,
        house_use = body.house_use,
        pay_sup = body.pay_sup,
        meal_sup = body.meal_sup,
        house_sup = body.house_sup,
        item1_use = body.item1_use,
        item1_type = body.item1_type,
        item1_sup = body.item1_sup,
        item2_use = body.item2_use,
        item2_type = body.item2_type,
        item2_sup = body.item2_sup,
        item3_use = body.item3_use,
        item3_type = body.item3_type,
        item3_sup = body.item3_sup,
        item4_use = body.item4_use,
        item4_type = body.item4_type,
        item4_sup = body.item4_sup,
        agent = body.agent,
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
        # 광고글(post_type=4): card_type=1 최대 5개 유지 (초과분은 오래된 순으로 2유형)
        _rollover_ad_card_types(db)
    db.commit()
    db.refresh(post)

    # 글 등록 푸쉬 알림(관리자 대상) - 실패해도 글 등록 성공 처리
    try:
        if int(post_type) in (1, 3, 4):
            notify_admin_acknowledged_post(
                db,
                post_id=int(post.id),
                post_type=int(post_type),
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
        workplace_lat = post.workplace_lat,
        workplace_lng = post.workplace_lng,
        business_lat = post.business_lat,
        business_lng = post.business_lng,
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
        status = post.status,
        highlight_color = post.highlight_color,
        highlight_content = post.highlight_content,
        total_use = post.total_use,
        branch_use = post.branch_use,
        leader_use = post.leader_use,
        member_use = post.member_use,
        total_fee = post.total_fee,
        branch_fee = post.branch_fee,
        leader_fee = post.leader_fee,
        member_fee = post.member_fee,
        pay_use = post.pay_use,
        meal_use = post.meal_use,
        house_use = post.house_use,
        pay_sup = post.pay_sup,
        meal_sup = post.meal_sup,
        house_sup = post.house_sup,
        item1_use = post.item1_use,
        item1_type = post.item1_type,
        item1_sup = post.item1_sup,
        item2_use = post.item2_use,
        item2_type = post.item2_type,
        item2_sup = post.item2_sup,
        item3_use = post.item3_use,
        item3_type = post.item3_type,
        item3_sup = post.item3_sup,
        item4_use = post.item4_use,
        item4_type = post.item4_type,
        item4_sup = post.item4_sup,
        agent = post.agent,
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

    q = (
        db.query(Community_Post)
        .filter(Community_Post.post_type == 1)
        .order_by(Community_Post.created_at.desc())
    )

    if status in ("published", "closed"):
        q = q.filter(Community_Post.status == status)

    # --- 산업(업종) 필터 ---
    industries = [str(x).strip() for x in (getattr(user, "custom_industry_codes", None) or []) if str(x).strip()]
    if industries and "전체" not in industries:
        q = q.filter(
            or_(*[Community_Post.job_industry.ilike(f"%{ind}%") for ind in industries])
        )

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
    q = (
        db.query(Community_Post)
          .filter(Community_Post.post_type == 1)
          .order_by(Community_Post.created_at.desc())
    )

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
                                Community_Post.city.like(f"%{c}%")
                            )
                        )
                    )
            if conds:
                q = q.filter(or_(*conds))
    elif province and province != "전체":
        q = q.filter(Community_Post.province.in_(province_candidates(province)))
        if city and city != "전체":
            # city 필터링 (정확히 일치하거나 부분 일치)
            q = q.filter(
                or_(
                    Community_Post.city == city,
                    Community_Post.city.like(f"%{city}%")
                )
            )

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
            highlight_color = p.highlight_color,
            highlight_content = p.highlight_content,
            total_use = p.total_use,
            branch_use = p.branch_use,
            leader_use = p.leader_use,
            member_use = p.member_use,
            total_fee = p.total_fee,
            branch_fee = p.branch_fee,
            leader_fee = p.leader_fee,
            member_fee = p.member_fee,
            pay_use = p.pay_use,
            meal_use = p.meal_use,
            house_use = p.house_use,
            pay_sup = p.pay_sup,
            meal_sup = p.meal_sup,
            house_sup = p.house_sup,
            item1_use = p.item1_use,
            item1_type = p.item1_type,
            item1_sup = p.item1_sup,
            item2_use = p.item2_use,
            item2_type = p.item2_type,
            item2_sup = p.item2_sup,
            item3_use = p.item3_use,
            item3_type = p.item3_type,
            item3_sup = p.item3_sup,
            item4_use = p.item4_use,
            item4_type = p.item4_type,
            item4_sup = p.item4_sup,
            agent = p.agent,
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
    q = (
        db.query(Community_Post)
          .filter(Community_Post.post_type == post_type)
          .order_by(Community_Post.created_at.desc())
    )

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
                                Community_Post.city.like(f"%{c}%")
                            )
                        )
                    )
            if conds:
                q = q.filter(or_(*conds))
    elif province and province != "전체":
        q = q.filter(Community_Post.province.in_(province_candidates(province)))
        if city and city != "전체":
            # city 필터링 (정확히 일치하거나 부분 일치)
            q = q.filter(
                or_(
                    Community_Post.city == city,
                    Community_Post.city.like(f"%{city}%")
                )
            )

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
            highlight_color = p.highlight_color,
            highlight_content = p.highlight_content,
            total_use = p.total_use,
            branch_use = p.branch_use,
            leader_use = p.leader_use,
            member_use = p.member_use,
            total_fee = p.total_fee,
            branch_fee = p.branch_fee,
            leader_fee = p.leader_fee,
            member_fee = p.member_fee,
            pay_use = p.pay_use,
            meal_use = p.meal_use,
            house_use = p.house_use,
            pay_sup = p.pay_sup,
            meal_sup = p.meal_sup,
            house_sup = p.house_sup,
            item1_use = p.item1_use,
            item1_type = p.item1_type,
            item1_sup = p.item1_sup,
            item2_use = p.item2_use,
            item2_type = p.item2_type,
            item2_sup = p.item2_sup,
            item3_use = p.item3_use,
            item3_type = p.item3_type,
            item3_sup = p.item3_sup,
            item4_use = p.item4_use,
            item4_type = p.item4_type,
            item4_sup = p.item4_sup,
            agent = p.agent,
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
    q = (
        db.query(Community_Post)
        .filter(Community_Post.post_type == post_type)
        .order_by(Community_Post.created_at.desc())
    )

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
            highlight_color = p.highlight_color,
            highlight_content = p.highlight_content,
            total_use = p.total_use,
            branch_use = p.branch_use,
            leader_use = p.leader_use,
            member_use = p.member_use,
            total_fee = p.total_fee,
            branch_fee = p.branch_fee,
            leader_fee = p.leader_fee,
            member_fee = p.member_fee,
            pay_use = p.pay_use,
            meal_use = p.meal_use,
            house_use = p.house_use,
            pay_sup = p.pay_sup,
            meal_sup = p.meal_sup,
            house_sup = p.house_sup,
            item1_use = p.item1_use,
            item1_type = p.item1_type,
            item1_sup = p.item1_sup,
            item2_use = p.item2_use,
            item2_type = p.item2_type,
            item2_sup = p.item2_sup,
            item3_use = p.item3_use,
            item3_type = p.item3_type,
            item3_sup = p.item3_sup,
            item4_use = p.item4_use,
            item4_type = p.item4_type,
            item4_sup = p.item4_sup,
            agent = p.agent,
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
        workplace_lat = p.workplace_lat,
        workplace_lng = p.workplace_lng,
        business_lat = p.business_lat,
        business_lng = p.business_lng,
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
        province = p.province,
        city=p.city,
        status=p.status,
        highlight_color = p.highlight_color,
        highlight_content = p.highlight_content,
        total_use = p.total_use,
        branch_use = p.branch_use,
        leader_use = p.leader_use,
        member_use = p.member_use,
        total_fee = p.total_fee,
        branch_fee = p.branch_fee,
        leader_fee = p.leader_fee,
        member_fee = p.member_fee,
        pay_use = p.pay_use,
        meal_use = p.meal_use,
        house_use = p.house_use,
        pay_sup = p.pay_sup,
        meal_sup = p.meal_sup,
        house_sup = p.house_sup,
        item1_use = p.item1_use,
        item1_type = p.item1_type,
        item1_sup = p.item1_sup,
        item2_use = p.item2_use,
        item2_type = p.item2_type,
        item2_sup = p.item2_sup,
        item3_use = p.item3_use,
        item3_type = p.item3_type,
        item3_sup = p.item3_sup,
        item4_use = p.item4_use,
        item4_type = p.item4_type,
        item4_sup = p.item4_sup,
        agent = p.agent,
        other_role_name=getattr(p, "other_role_name", None),
        other_role_fee=getattr(p, "other_role_fee", None),
        post_type=p.post_type,
        card_type=p.card_type,
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
    # post_type=4(광고글): card_type=1이 5개를 초과하지 않도록 오래된 글을 2유형으로 롤오버
    try:
        pt = int(getattr(post, "post_type", 0) or 0)
    except Exception:
        pt = 0
    try:
        ct = int(getattr(post, "card_type", 0) or 0)
    except Exception:
        ct = 0
    if pt == 1:
        _rollover_recruit_card_types(db)
    if pt == 4 and ct == 1:
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
        highlight_color = post.highlight_color,
        highlight_content = post.highlight_content,
        total_use = post.total_use,
        branch_use = post.branch_use,
        leader_use = post.leader_use,
        member_use = post.member_use,
        total_fee = post.total_fee,
        branch_fee = post.branch_fee,
        leader_fee = post.leader_fee,
        member_fee = post.member_fee,
        pay_use = post.pay_use,
        meal_use = post.meal_use,
        house_use = post.house_use,
        pay_sup = post.pay_sup,
        meal_sup = post.meal_sup,
        house_sup = post.house_sup,
        item1_use = post.item1_use,
        item1_type = post.item1_type,
        item1_sup = post.item1_sup,
        item2_use = post.item2_use,
        item2_type = post.item2_type,
        item2_sup = post.item2_sup,
        item3_use = post.item3_use,
        item3_type = post.item3_type,
        item3_sup = post.item3_sup,
        item4_use = post.item4_use,
        item4_type = post.item4_type,
        item4_sup = post.item4_sup,
        agent = post.agent,
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



STATIC_DIR = Path(os.getenv("STATIC_DIR", "/data/uploads")).resolve()
STATIC_DIR.mkdir(parents=True, exist_ok=True)
print("### STATIC_DIR =", STATIC_DIR)
print("### STATIC_DIR exists?", STATIC_DIR.exists())

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

def _strip_data_url(b64: str) -> str:
    return re.sub(r"^data:.*;base64,", "", b64)

def _ensure_ext(path: Path, raw_bytes: bytes) -> Path:
    if path.suffix:
        return path
    kind = imghdr.what(None, h=raw_bytes)  # 'jpeg' | 'png' ...
    ext = {"jpeg": ".jpg", "png": ".png", "gif": ".gif"}.get(kind, ".jpg")
    return path.with_suffix(ext)

@app.post("/upload/base64")
def upload_base64(payload: UploadBase64Request):
    if not payload.base64:
        raise HTTPException(400, "base64 required")

    raw_b64 = _strip_data_url(payload.base64)
    try:
        image_bytes = base64.b64decode(raw_b64)
    except Exception:
        raise HTTPException(400, "invalid base64")

    name = (payload.filename or f"{uuid.uuid4()}.jpg").strip()
    name = name.replace("\\", "/").split("/")[-1]  
 
    save_path = _ensure_ext(STATIC_DIR / name, image_bytes)

    print("SAVE TO:", save_path)
    with open(save_path, "wb") as f:
        f.write(image_bytes)

    public_url = f"https://api.smartgauge.co.kr/static/{save_path.name}"
    return {"url": public_url}


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
            .filter(
                Community_Comment.id == parent_id,
                Community_Comment.post_id == post_id,
            )
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

    rows = (
        q.order_by(Community_Comment.created_at.desc(), Community_Comment.id.desc())
        .limit(limit + 1)
        .all()
    )

    items = rows[:limit]
    next_cur = items[-1].created_at.isoformat() if len(rows) > limit else None

    return CommentListOut(items=items, next_cursor=next_cur)


@app.get("/community/users/export")
def export_users(
    db: Session = Depends(get_db),
):
    """
    커뮤니티 사용자 목록을 엑셀(xlsx)로 내보냅니다.
    - 인증 없이 다운로드 가능
    - Windows 환경에서도 파일이 손상되지 않도록, temp 파일 핸들 락을 피합니다.
    """
    users = db.query(Community_User).order_by(Community_User.id.asc()).all()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Users"

    ws.append(
        [
            "ID",
            "Username",
            "Name",
            "Phone",
            "Region",
            "Signup Date",
            "Is Owner",
            "User Grade",
            "Point Balance",
            "Cash Balance",
            "Marketing Consent",
            "Referral Code",
        ]
    )

    for u in users:
        ws.append(
            [
                u.id,
                u.username,
                u.name,
                u.phone_number,
                u.region,
                u.signup_date.isoformat() if getattr(u, "signup_date", None) else None,
                bool(getattr(u, "is_owner", False)),
                int(getattr(u, "user_grade", -1) or -1),
                int(getattr(u, "point_balance", 0) or 0),
                int(getattr(u, "cash_balance", 0) or 0),
                bool(getattr(u, "marketing_consent", False)),
                getattr(u, "referral_code", None),
            ]
        )

    # Windows에서 NamedTemporaryFile 핸들 락 이슈를 피하기 위해 mkstemp 사용
    fd, tmp_path = tempfile.mkstemp(suffix=".xlsx")
    os.close(fd)
    wb.save(tmp_path)
    try:
        wb.close()
    except Exception:
        pass

    download_name = f"users_{date.today().isoformat()}.xlsx"
    media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return FileResponse(
        tmp_path,
        filename=download_name,
        media_type=media_type,
        background=BackgroundTask(lambda p=tmp_path: os.path.exists(p) and os.remove(p)),
    )


# ==================== Community Admin/Owner: 회원 관리(목록/열람/제재/지급) ====================

def _dt_to_iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    try:
        if getattr(dt, "tzinfo", None) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        try:
            return dt.isoformat()
        except Exception:
            return None

def _load_restrictions_for_user(db: Session, user_id: int) -> dict[int, datetime | None]:
    rows = (
        db.query(Community_User_Restriction)
        .filter(
            Community_User_Restriction.user_id == user_id,
            Community_User_Restriction.post_type.in_([1, 3, 4]),
        )
        .all()
    )
    out: dict[int, datetime | None] = {1: None, 3: None, 4: None}
    for r in rows:
        try:
            out[int(r.post_type)] = r.restricted_until
        except Exception:
            continue
    return out

@app.get("/community/admin/users")
def community_admin_list_users(
    cursor: str | None = Query(None),
    limit: int | None = Query(50),
    q: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """
    Contract:
      GET /community/admin/users?cursor?&limit?&q?
      response: { status, items:[{nickname,name,signup_date,admin_acknowledged}], next_cursor }
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    try:
        lim = int(limit or 50)
        if lim <= 0:
            lim = 50
        if lim > 200:
            lim = 200

        # cursor: offset 문자열("0", "50") 기반
        try:
            offset = int((cursor or "0").strip() or "0")
        except Exception:
            offset = 0
        if offset < 0:
            offset = 0

        qry = (
            db.query(Community_User)
            .order_by(
                Community_User.signup_date.desc().nullslast(),
                Community_User.username.asc(),
            )
        )

        q_text = (q or "").strip()
        if q_text:
            # 닉네임(username) 또는 성함(name) 부분일치 검색
            pat = f"%{q_text}%"
            qry = qry.filter(
                or_(
                    Community_User.username.ilike(pat),
                    Community_User.name.ilike(pat),
                )
            )

        rows = qry.offset(offset).limit(lim + 1).all()
        items = rows[:lim]
        next_cursor = str(offset + lim) if len(rows) > lim else None

        return {
            "status": 0,
            "items": [
                {
                    "nickname": u.username,
                    "name": u.name,
                    "signup_date": u.signup_date.isoformat() if getattr(u, "signup_date", None) else None,
                    "admin_acknowledged": bool(getattr(u, "admin_acknowledged", False)),
                }
                for u in items
            ],
            "next_cursor": next_cursor,
        }
    except Exception:
        return {"status": 8, "items": [], "next_cursor": None}

@app.get("/community/admin/users/{nickname}")
def community_admin_get_user(
    nickname: str,
    actor_nickname: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """
    Contract:
      GET /community/admin/users/{nickname}?actor_nickname=...
      response:
        status
        user: { nickname,name,phone_number,signup_date,point_balance,cash_balance,user_grade,is_owner,admin_acknowledged,referral_count,posts:{type1,type3,type4} }
        restrictions: Array<{ post_type, restricted_until }>
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    try:
        user = db.query(Community_User).filter(Community_User.username == nickname).first()
        if not user:
            return {"status": 1}

        def _post_item(p: Community_Post) -> dict:
            return {
                "id": int(p.id),
                "title": str(getattr(p, "title", "") or ""),
                "created_at": _dt_to_iso(getattr(p, "created_at", None)),
                "status": str(getattr(p, "status", None) or "") if getattr(p, "status", None) is not None else None,
            }

        rows = (
            db.query(Community_Post.post_type, func.count(Community_Post.id).label("cnt"))
            .filter(
                Community_Post.user_id == user.id,
                Community_Post.post_type.in_([1, 3, 4]),
            )
            .group_by(Community_Post.post_type)
            .all()
        )
        counts = {1: 0, 3: 0, 4: 0}
        for pt, cnt in rows:
            try:
                counts[int(pt)] = int(cnt)
            except Exception:
                continue

        referral_count = (
            db.query(func.count(Referral.id))
            .filter(Referral.referrer_user_id == user.id)
            .scalar()
            or 0
        )

        restrictions_map = _load_restrictions_for_user(db, int(user.id))

        # (추가) 작성 글 목록(읽기 전용): 타입별 최근 N개
        # NOTE: Contract 기존 필드는 유지하고, 필드 추가만 합니다(프런트가 필요 시 사용).
        def _list_posts_by_type(pt: int, lim: int = 20) -> list[dict]:
            try:
                posts = (
                    db.query(Community_Post)
                    .filter(Community_Post.user_id == user.id, Community_Post.post_type == pt)
                    .order_by(Community_Post.created_at.desc(), Community_Post.id.desc())
                    .limit(lim)
                    .all()
                )
                return [_post_item(p) for p in posts]
            except Exception:
                return []

        return {
            "status": 0,
            "user": {
                "nickname": user.username,
                "name": user.name,
                "phone_number": getattr(user, "phone_number", None),
                "signup_date": user.signup_date.isoformat() if getattr(user, "signup_date", None) else None,
                "point_balance": int(user.point_balance or 0),
                "cash_balance": int(user.cash_balance or 0),
                "user_grade": int(getattr(user, "user_grade", 0) or 0),
                "is_owner": bool(getattr(user, "is_owner", False)),
                "admin_acknowledged": bool(getattr(user, "admin_acknowledged", False)),
                "referral_code": getattr(user, "referral_code", None),
                "referral_count": int(referral_count),
                "posts": {"type1": counts[1], "type3": counts[3], "type4": counts[4]},
            },
            "restrictions": [
                {"post_type": 1, "restricted_until": _dt_to_iso(restrictions_map[1])},
                {"post_type": 3, "restricted_until": _dt_to_iso(restrictions_map[3])},
                {"post_type": 4, "restricted_until": _dt_to_iso(restrictions_map[4])},
            ],
            "post_items": {
                "type1": _list_posts_by_type(1, 20),
                "type3": _list_posts_by_type(3, 20),
                "type4": _list_posts_by_type(4, 20),
            },
        }
    except Exception:
        return {"status": 8}

@app.post("/community/admin/users/{nickname}/restrictions")
def community_admin_update_user_restrictions(
    nickname: str,
    body: dict = Body(default_factory=dict),
    db: Session = Depends(get_db),
):
    """
    Contract:
      POST /community/admin/users/{nickname}/restrictions
      body: { actor_nickname, changes:[{post_type,days}], reason? }
      response: { status, restrictions:[{post_type,restricted_until}] }
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    actor_nickname = body.get("actor_nickname")
    changes = body.get("changes")
    reason = body.get("reason")

    if not isinstance(changes, list) or len(changes) == 0:
        return {"status": 1, "restrictions": []}

    try:
        user = db.query(Community_User).filter(Community_User.username == nickname).first()
        if not user:
            return {"status": 1, "restrictions": []}

        now = datetime.now(timezone.utc)
        for ch in changes:
            try:
                post_type = int(ch.get("post_type"))
                days = int(ch.get("days"))
            except Exception:
                continue
            if post_type not in (1, 3, 4):
                continue
            if days < 0:
                continue

            restricted_until = None if days == 0 else (now + timedelta(days=days))

            stmt = (
                insert(Community_User_Restriction)
                .values(
                    user_id=int(user.id),
                    post_type=post_type,
                    restricted_until=restricted_until,
                    reason=(str(reason) if reason is not None else None),
                    created_by_user_id=None,
                )
                .on_conflict_do_update(
                    index_elements=["user_id", "post_type"],
                    set_={
                        "restricted_until": restricted_until,
                        "reason": (str(reason) if reason is not None else None),
                        "created_by_user_id": (int(actor.id) if actor else None),
                        "created_at": func.now(),
                    },
                )
            )
            db.execute(stmt)

        db.commit()

        restrictions_map = _load_restrictions_for_user(db, int(user.id))
        return {
            "status": 0,
            "restrictions": [
                {"post_type": 1, "restricted_until": _dt_to_iso(restrictions_map[1])},
                {"post_type": 3, "restricted_until": _dt_to_iso(restrictions_map[3])},
                {"post_type": 4, "restricted_until": _dt_to_iso(restrictions_map[4])},
            ],
        }
    except Exception:
        db.rollback()
        return {"status": 8, "restrictions": []}


@app.post("/community/admin/users/{nickname}/notify")
def community_admin_notify_user(
    nickname: str,
    body: dict = Body(default_factory=dict),
    db: Session = Depends(get_db),
):
    """
    Contract:
      POST /community/admin/users/{nickname}/notify
      body: { actor_nickname, title, body }
      response: { status, notification_id? }
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    actor_nickname = body.get("actor_nickname")
    title = body.get("title")
    msg = body.get("body")

    if not isinstance(title, str) or not title.strip():
        return {"status": 1}
    if not isinstance(msg, str) or not msg.strip():
        return {"status": 1}

    try:
        user = db.query(Community_User).filter(Community_User.username == nickname).first()
        if not user:
            return {"status": 1}

        data = {"source": "admin", "actor_nickname": actor_nickname}
        noti = create_notification(
            db,
            user_id=int(user.id),
            title=title.strip(),
            body=msg.strip(),
            type="system",
            data=data,
        )

        if getattr(user, "push_token", None):
            send_push(getattr(user, "push_token"), title.strip(), msg.strip(), data)

        return {"status": 0, "notification_id": int(getattr(noti, "id", 0) or 0)}
    except Exception:
        db.rollback()
        return {"status": 8}

@app.post("/community/owner/users/{nickname}/points")
def community_owner_grant_points(
    nickname: str,
    body: dict = Body(default_factory=dict),
    db: Session = Depends(get_db),
):
    """
    Contract:
      POST /community/owner/users/{nickname}/points
      body: { actor_nickname, amount(양수), reason(필수) }
      response: { status, point_balance }
      권한 체크: 제거됨(클라이언트에서만 제어)
    """
    actor_nickname = body.get("actor_nickname")
    amount = body.get("amount")
    reason = body.get("reason")

    try:
        amt = int(amount)
    except Exception:
        return {"status": 1, "point_balance": 0}
    if amt <= 0:
        return {"status": 1, "point_balance": 0}
    if not isinstance(reason, str) or not reason.strip():
        return {"status": 1, "point_balance": 0}

    try:
        user = (
            db.query(Community_User)
            .filter(Community_User.username == nickname)
            .with_for_update()
            .first()
        )
        if not user:
            return {"status": 1, "point_balance": 0}

        user.point_balance = int(user.point_balance or 0) + amt
        db.add(Point(user_id=int(user.id), reason=reason.strip(), amount=amt))
        db.commit()
        db.refresh(user)

        return {"status": 0, "point_balance": int(user.point_balance or 0)}
    except Exception:
        db.rollback()
        return {"status": 8, "point_balance": 0}

@app.post("/community/owner/users/{nickname}/admin-acknowledged")
def community_owner_set_admin_acknowledged(
    nickname: str,
    body: dict = Body(default_factory=dict),
    db: Session = Depends(get_db),
):
    """
    오너 권한에서 관리자 권한 수정(부여/회수).
    body: { actor_nickname, admin_acknowledged?: true|false }  (미지정 시 true)
    response: { status, admin_acknowledged }
    status: 0|1|3|8
    """
    actor_nickname = body.get("actor_nickname")
    enabled_raw = body.get("admin_acknowledged", None)

    enabled = True
    if enabled_raw is None:
        enabled = True
    elif isinstance(enabled_raw, bool):
        enabled = enabled_raw
    elif isinstance(enabled_raw, (int, float)):
        try:
            enabled = bool(int(enabled_raw))
        except Exception:
            return {"status": 1, "admin_acknowledged": False}
    elif isinstance(enabled_raw, str):
        s = enabled_raw.strip().lower()
        if s in ("1", "true", "t", "yes", "y", "on"):
            enabled = True
        elif s in ("0", "false", "f", "no", "n", "off"):
            enabled = False
        else:
            return {"status": 1, "admin_acknowledged": False}
    else:
        return {"status": 1, "admin_acknowledged": False}

    try:
        user = (
            db.query(Community_User)
            .filter(Community_User.username == nickname)
            .with_for_update()
            .first()
        )
        if not user:
            return {"status": 1, "admin_acknowledged": False}

        user.admin_acknowledged = bool(enabled)
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"status": 0, "admin_acknowledged": bool(getattr(user, "admin_acknowledged", False))}
    except Exception:
        db.rollback()
        return {"status": 8, "admin_acknowledged": False}


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
        select(Post_Like).where(
            Post_Like.username == username, Post_Like.post_id == post_id
        )
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
        select(Post_Like).where(
            Post_Like.username == username, Post_Like.post_id == post_id
        )
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
    isUsername = db.execute(
        select(Community_User).where(Community_User.username == username)
    ).scalar()
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
    PostOut2.model_validate(p, from_attributes=True).model_copy(update={"liked": True})
    for p in rows
    ]

    return {"items": posts, "next_cursor": next_cursor}



@app.get("/internal/rss-refresh")
def rss_refresh(x_internal_token: str = Header(None), db: Session = Depends(get_db)):

    if x_internal_token != SECRET_RSS_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    fetch_rss_and_save(db)
    return {"status": "ok"}



class MyNotifyRequest(BaseModel):
    title: str
    body: str
    data: dict = {}
    type: str = "system"

def create_notification(
    db: Session,
    user_id: int,
    title: str,
    body: str,
    type: str = "system",
    data: dict = None,
    commit: bool = True,
):
    noti = Notification(
        user_id=user_id,
        title=title,
        body=body,
        type=type,
        data=data or {}
    )
    db.add(noti)
    if commit:
        db.commit()
        db.refresh(noti)
    return noti


def generate_referral_code(db: Session, phone_number: str) -> str:
    """
    phone_number 기반으로 referral_code를 생성합니다.
    규칙: phone_number의 마지막 4자리 + 숫자(0~9) 1자리
    
    Args:
        db: 데이터베이스 세션
        phone_number: 전화번호 문자열
        
    Returns:
        생성된 referral_code (5자리 문자열)
        
    Raises:
        HTTPException: phone_number가 4자리 미만이거나, 모든 후보 코드가 사용 중인 경우
    """
    # 1. phone_number에서 숫자만 추출
    digits_only = re.sub(r'[^0-9]', '', phone_number)
    
    # 2. 길이 확인
    if len(digits_only) < 4:
        raise HTTPException(
            status_code=400, 
            detail=f"phone_number must contain at least 4 digits (got: {len(digits_only)})"
        )
    
    # 3. 마지막 4자리 추출
    last4 = digits_only[-4:]
    
    # 4. 이미 사용 중인 referral_code 조회 (last4로 시작하는 것들)
    existing_codes = db.query(Community_User.referral_code).filter(
        Community_User.referral_code.like(f"{last4}%"),
        Community_User.referral_code.isnot(None)
    ).all()
    used_suffixes = {code[0][-1] for code in existing_codes if code[0] and len(code[0]) == 5}
    
    # 5. 사용 가능한 suffix 찾기 (0~9 중)
    available_suffixes = [str(d) for d in range(10) if str(d) not in used_suffixes]
    
    if not available_suffixes:
        # 모든 코드가 사용 중
        masked_phone = phone_number[:3] + "****" + phone_number[-2:] if len(phone_number) > 5 else "****"
        print(f"[ERROR] referral_code 생성 실패: last4={last4}, phone={masked_phone}, 모든 코드 소진")
        raise HTTPException(
            status_code=409,
            detail="referral_code 생성 불가: 해당 전화번호 마지막 4자리로 생성 가능한 코드가 모두 사용 중입니다"
        )
    
    # 6. 첫 번째 사용 가능한 suffix로 코드 생성
    selected_suffix = available_suffixes[0]
    referral_code = last4 + selected_suffix
    
    return referral_code


def assign_referral_code(db: Session, user: Community_User, phone_number: str) -> None:
    """
    유저에게 referral_code를 할당합니다.
    중복 발생 시 다른 suffix로 재시도합니다.
    
    Args:
        db: 데이터베이스 세션
        user: Community_User 객체
        phone_number: 전화번호 문자열
    """
    digits_only = re.sub(r'[^0-9]', '', phone_number)
    if len(digits_only) < 4:
        raise HTTPException(
            status_code=400,
            detail="phone_number must contain at least 4 digits"
        )
    
    last4 = digits_only[-4:]
    
    # 최대 10번 시도
    max_attempts = 10
    for attempt in range(max_attempts):
        try:
            # generate_referral_code가 최신 상태를 반영하므로 재호출
            referral_code = generate_referral_code(db, phone_number)
            user.referral_code = referral_code
            db.flush()  # DB에 반영 (아직 commit은 안 함)
            return  # 성공
        except HTTPException as e:
            # generate_referral_code에서 발생한 HTTPException은 그대로 전달
            db.rollback()
            raise
        except IntegrityError:
            # 동시성 문제로 인한 중복 발생 시 rollback 후 재시도
            db.rollback()
            # 다음 시도 전에 잠시 대기할 수도 있지만, 일단 바로 재시도
            if attempt == max_attempts - 1:
                # 마지막 시도 실패
                masked_phone = phone_number[:3] + "****" + phone_number[-2:] if len(phone_number) > 5 else "****"
                print(f"[ERROR] referral_code 할당 실패 (최대 시도 횟수 초과): last4={last4}, phone={masked_phone}")
                raise HTTPException(
                    status_code=409,
                    detail="referral_code 생성 불가: 코드 생성에 실패했습니다 (동시성 충돌 또는 코드 소진)"
                )
            continue
        except Exception as e:
            db.rollback()
            masked_phone = phone_number[:3] + "****" + phone_number[-2:] if len(phone_number) > 5 else "****"
            print(f"[ERROR] referral_code 할당 중 예상치 못한 오류: last4={last4}, phone={masked_phone}, error={e}")
            raise HTTPException(
                status_code=500,
                detail="referral_code 생성 중 오류가 발생했습니다"
            )


def get_user_id_by_username(db: Session, username: str):
    user_id = db.query(Community_User.id).filter(Community_User.username == username).scalar()
    
    if user_id is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user_id


def notify_admin_post(db: Session, title: str, body: str, post_id: int, target_user_id: int, post_type: int = 3 ):
    noti = create_notification(
        db,
        user_id=target_user_id,
        title=title,
        body=body,
        type="post",
        data={"post_id": post_id, "post_type": post_type}
    )

    user = db.query(Community_User).filter(Community_User.id == target_user_id).first()

    if user and user.push_token:
        send_push(
            user.push_token,
            title,
            body,
            {"post_id": post_id, "post_type": post_type}
        )

    return noti


def notify_admin_acknowledged_post(
    db: Session,
    *,
    post_id: int,
    post_type: int,
    author_username: str,
    post_title: str,
    exclude_user_id: int | None = None,
):
    """
    구인/수다/광고 글 등록 시 관리자(admin_acknowledged=True)에게 푸쉬 + 미확인 알림 저장.
    - 알림 실패는 글 등록 결과에 영향을 주지 않도록 호출부에서 try/except 처리 권장.
    """
    pt = int(post_type)
    label = "글"
    if pt == 1:
        label = "구인글"
    elif pt == 3:
        label = "수다글"
    elif pt == 4:
        label = "광고글"

    title = f"새 {label}이 등록되었습니다"
    body = f"{author_username}님이 새로운 {label}을 작성했습니다: {post_title}"
    data = {"post_id": int(post_id), "post_type": int(pt)}

    admins = (
        db.query(Community_User)
        .filter(Community_User.admin_acknowledged.is_(True))
        .all()
    )

    for a in admins:
        if exclude_user_id is not None and int(getattr(a, "id", 0) or 0) == int(exclude_user_id):
            continue
        try:
            create_notification(
                db,
                user_id=int(a.id),
                title=title,
                body=body,
                type="post",
                data=data,
                commit=True,
            )
        except Exception:
            # 세션이 실패 상태가 되면 다음 루프에서 계속 실패하므로 롤백
            try:
                db.rollback()
            except Exception:
                pass
            continue

        try:
            token = getattr(a, "push_token", None)
            if token:
                send_push(token, title, body, data)
        except Exception:
            # 푸쉬 실패는 무시
            pass


def notify_owners_event(db: Session, title: str, body: str, data: dict | None = None):
    """
    회원가입/탈퇴 등 시스템 이벤트를 오너(is_owner=True)에게 푸쉬 + 미확인 알림 저장.
    """
    owners = (
        db.query(Community_User)
        .filter(Community_User.is_owner.is_(True))
        .all()
    )
    payload = data or {}
    for o in owners:
        try:
            create_notification(
                db,
                user_id=int(o.id),
                title=title,
                body=body,
                type="system",
                data=payload,
                commit=True,
            )
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            continue

        try:
            token = getattr(o, "push_token", None)
            if token:
                send_push(token, title, body, payload)
        except Exception:
            pass


def send_push(token, title, body, data=None, badge=1):
    message = {
        "to": token,
        "sound": "default",
        "title": title,
        "body": body,
        "data": data or {},
        "badge":badge,
        "priority":"high",
        "channelId": "default",
    }

    resp = requests.post(
        "https://exp.host/--/api/v2/push/send",
        json=message,
        headers={"Content-Type": "application/json"}
    )
    try:
        print("Expo push response:", resp.json())
    except:
        print("Push response parse failed:", resp.text)


@app.post("/notify/my/{username}")
def notify_my(username: str, req: MyNotifyRequest, db: Session = Depends(get_db)):

    user_id = get_user_id_by_username(db, username)

    noti = create_notification(
        db,
        user_id=user_id,
        title=req.title,
        body=req.body,
        type=req.type,
        data=req.data
    )

    token_row = db.execute(
        "SELECT push_token FROM community_users WHERE id = :uid",
        {"uid": user_id}
    ).fetchone()

    if token_row and token_row[0]:
        send_push(
            token_row[0],
            req.title,
            req.body,
            req.data
        )

    return {"status": "ok", "notification_id": noti.id}


@app.get("/notify/my/{username}/unread")
def get_unread_notifications(username: str, db: Session = Depends(get_db)):
    user_id = get_user_id_by_username(db, username)

    rows = (
        db.query(Notification)
        .filter(
        Notification.user_id == user_id,
        Notification.is_read == False
    )
    .order_by(Notification.id.desc())
    .all()
    )
    return rows


@app.get("/notify/my/{username}/unread/count")
def unread_count_by_username(username: str, db: Session = Depends(get_db)):
    user_id = get_user_id_by_username(db, username)

    count = (
        db.query(Notification)
        .filter(
            Notification.user_id == user_id,
            Notification.is_read == False
        )
        .count()
    )

    return {"unread_count": count}


@app.post("/notify/read/{notification_id}")
def mark_notification_read(notification_id: int, db: Session = Depends(get_db)):

    db.query(Notification).filter(
        Notification.id == notification_id
    ).update({"is_read": True})

    db.commit()

    return {"status": "ok"}