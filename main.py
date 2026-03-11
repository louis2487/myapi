import os
import calendar
from datetime import datetime, timedelta, timezone, date
try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore
from fastapi import FastAPI, Depends, HTTPException, status, Request, Header, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from database import SessionLocal, engine
from deps import get_db, get_current_community_user
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

import settings
from recode import ensure_recode_columns, router as recode_router
from research import register_research_startup, router as research_router
from routers.auth import router as auth_router
from routers.billing import router as billing_router
from routers.internal import register_rss_startup, router as internal_router
from routers.notify import create_notification, get_user_id_by_username, router as notify_router, send_push
from routers.payments import router as payments_router
from routers.play import router as play_router
from routers.parking_play import router as parking_play_router
from routers.parking_popup import router as parking_popup_router
from routers.upload import mount_static, router as upload_router
from routers.community import router as community_router
from routers.parking import router as parking_router

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
SECRET_RSS_TOKEN = settings.SECRET_RSS_TOKEN

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

mount_static(app)

app.include_router(recode_router)
app.include_router(research_router)
app.include_router(auth_router)
app.include_router(play_router)
app.include_router(billing_router)
app.include_router(payments_router)
app.include_router(upload_router)
app.include_router(internal_router)
app.include_router(notify_router)
app.include_router(community_router)
app.include_router(parking_router)
app.include_router(parking_play_router)
app.include_router(parking_popup_router)

register_research_startup(app)
register_rss_startup(app)

from routers.community.logic import (
    AD_CARD1_MAX,
    AD_CATEGORIES,
    AD_CATEGORY_ALIASES,
    AD_PRIMARY_CATEGORY,
    CARD1_MAX,
    _ad_category_db_values,
    _apply_user_grade_upgrade,
    _normalize_ad_job_industry,
    _rollover_ad_card_types,
    _rollover_recruit_card_types,
)
from routers.community.phone import _is_valid_korean_phone, _normalize_phone, _require_verified_phone
from routers.community.referral_code import assign_referral_code, generate_referral_code
from routers.community.notifications import (
    notify_admin_acknowledged_event,
    notify_admin_acknowledged_post,
    notify_admin_post,
    notify_all_push_post,
    notify_owners_event,
)
from routers.community.startup import ensure_schema as _community_ensure_schema
from routers.community.startup import register_startup as _register_community_startup

# 커뮤니티 스키마/제약조건 보정(기존 main.py import-time 동작 유지)
_community_ensure_schema()
# 커뮤니티 startup 핸들러 등록
_register_community_startup(app)

# 커뮤니티 게시글/댓글/좋아요 API 및 관련 스키마/헬퍼는 `routers\community\posts.py`로 이동됨.

 # notify 관련 API는 `routers/notify.py`로 분리됨.