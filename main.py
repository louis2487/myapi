import os
from datetime import datetime, timedelta, timezone, date
from fastapi import FastAPI, Depends, HTTPException, status, Request, Header, Query, Body
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from database import SessionLocal, engine
import models
from models import Base, RuntimeRecord, User, Recode, RangeSummaryOut, PurchaseVerifyIn, SubscriptionStatusOut, Community_User, Community_Phone_Verification, Community_Post, Community_Comment, Post_Like, Notification, Referral, Point, Cash, Payment
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

# 앱 시작 시 referral/point 테이블의 제약조건을 모두 제거
_drop_all_constraints_on_table("referral")
_drop_all_constraints_on_table("point")
_drop_all_constraints_on_table("cash")

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

class RecodeOut(BaseModel):
    username: str
    date: str
    ontime: str
    offtime: str
    duration: int
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
    recodes = (
        db.query(Recode)
        .filter(Recode.username == username, Recode.date == date)
        .all()
    )
    return {"recodes": recodes}


@app.post("/recode/add")
def add_recode(recode: RecodeCreate, db: Session = Depends(get_db)):
    new_r = Recode(  
        username=recode.username,
        date=recode.date,
        ontime=recode.ontime,
        offtime=recode.offtime,
        duration=recode.duration
    )
    db.add(new_r)
    db.commit()
    return {"status":"success"}



@app.get("/recode/summary/{username}/{start}/{end}", response_model=RangeSummaryOut)
def recode_summary(username: str, start: str, end: str, db: Session = Depends(get_db)):
    cnt, total = db.query(
        func.count(Recode.id),
        func.coalesce(func.sum(Recode.duration), 0)
    ).filter(
        Recode.username == username,
        Recode.date >= start,
        Recode.date <= end
    ).one()
    return RangeSummaryOut(
        username=username, start=start, end=end,
        on_count=int(cnt), runtime_seconds=int(total or 0)
    )

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

    if req.region is None:
        return {"status": 3}    

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()

    user = Community_User(
        username      = req.username,
        password_hash = pw_hash,
        name          = req.name,
        phone_number  = digits,
        region        = req.region,  
        signup_date   = date.today(), 
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
    
    # 추천인코드가 있으면 referral/point 기록 + 포인트 지급
    input_code = (req.referral_code or "").strip()
    if input_code:
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

            bonus = 1000

            # 추천인 포인트 적립
            referrer.point_balance = int(referrer.point_balance or 0) + bonus
            db.add(Point(user_id=referrer.id, reason="referral_bonus_referrer", amount=bonus))

            # 피추천인 포인트 적립
            user.point_balance = int(user.point_balance or 0) + bonus
            db.add(Point(user_id=user.id, reason="referral_bonus_referred", amount=bonus))

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

    return {"status": 0}


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


@app.get("/community/points/{username}")
def list_points(username: str, db: Session = Depends(get_db)):
    """
    내 포인트 적립/사용 내역(원장).
    """
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
            "created_at": p.created_at.isoformat() if p.created_at else None,
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
    me: Community_User = Depends(get_current_community_user),
    db: Session = Depends(get_db),
):
    """
    출석체크(일 1회) 수령 여부 조회.
    - KST 기준 '오늘'에 attendance_daily 기록이 있으면 claimed=True
    """
    if me.username != username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No permission")

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
    me: Community_User = Depends(get_current_community_user),
    db: Session = Depends(get_db),
):
    """
    출석체크 포인트 지급 (KST 기준 하루 1회, 200P).
    - point 테이블에 기록되고 /community/points/{username}에서 조회 가능
    """
    if me.username != username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No permission")

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


@app.get("/community/cash/{username}")
def list_cash(username: str, db: Session = Depends(get_db)):
    """
    내 캐시 충전/사용 내역(원장).
    """
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
            "created_at": c.created_at.isoformat() if c.created_at else None,
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
        user.phone_number = req.phone_number

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

    db.delete(user)
    db.commit()

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

    # signup_date를 문자열로 변환 (None이면 None 유지)
    signup_date_str = user.signup_date.isoformat() if user.signup_date else None
    
    return {
        "status": 0,
        "signup_date": signup_date_str,
        "posts": {
            "type1": counts[1],
            "type3": counts[3],
            "type4": counts[4],
        },
        "point_balance": user.point_balance if user.point_balance is not None else 0,
        "cash_balance": user.cash_balance if user.cash_balance is not None else 0,
        "admin_acknowledged": user.admin_acknowledged if user.admin_acknowledged is not None else False,
        "referral_code": user.referral_code,
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

    # card_type: 1(유료1), 2(유료2), 3(무료) - 미지정이면 기본 3
    try:
        card_type = int(body.card_type) if body.card_type is not None else 3
    except Exception:
        card_type = 3

    if card_type not in (1, 2, 3):
        card_type = 3

    cost = 0
    if card_type == 1:
        cost = 80000
    elif card_type == 2:
        cost = 30000

    # 유료 유형일 때 캐시 차감 + 원장 기록
    if cost > 0:
        balance = int(user.cash_balance or 0)
        if balance < cost:
            raise HTTPException(status_code=400, detail="캐시가 부족합니다.")
        user.cash_balance = balance - cost
        db.add(Cash(user_id=userId, reason=f"post_card_type_{card_type}", amount=-cost))

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
        post_type= 1,
        card_type= card_type,
    )
   
    db.add(post)
    db.commit()
    db.refresh(post)

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
        post_type=post.post_type,
        card_type=post.card_type,
    )

@app.post("/community/posts/{username}/type/{post_type}", response_model=PostOut)
def create_post_plus(post_type:int, username: str, body: PostCreate, db: Session = Depends(get_db)):
    userId = db.query(Community_User.id).filter(Community_User.username == username).scalar()
    if not userId:
        raise HTTPException(status_code=404, detail="Invalid username")

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
        post_type=post_type,
        card_type=body.card_type,
    )
   
    db.add(post)
    db.commit()
    db.refresh(post)

    if post_type == 3:
        admin_ids = [1, 10, 13, 20, 21, 22, 23, 24, 25, 26, 27, 28]

        for admin_id in admin_ids:
            notify_admin_post(
                db,
                title="새 수다글이 등록되었습니다",
                body=f"{username}님이 새로운 수다글을 작성했습니다: {post.title}",
                post_id=post.id,
                target_user_id=admin_id,
                post_type=3,
            )
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
        post_type=post.post_type,
        card_type=post.card_type,
    )


class PostsOut2(BaseModel):
    items: list[PostOut2]
    next_cursor: str | None = None


@app.get("/community/posts/custom", response_model=PostsOut2)
def list_posts_custom_by_user_settings(
    cursor: Optional[str] = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(100, ge=1, le=100),
    status: Optional[str] = Query(None, description="published | closed"),
    me: Community_User = Depends(get_current_community_user),
    db: Session = Depends(get_db),
):
    """
    맞춤현장(유저 설정) 기반 구인글(post_type=1) 목록.

    - 로그인 필요(Authorization Bearer 토큰)
    - 필터 기준:
      - community_users.custom_industry_codes: job_industry(문자열/CSV)에 포함되는지 LIKE로 매칭
      - community_users.custom_region_codes:
        - "전체" 포함 시 지역 필터 없음
        - "서울" => province="서울"
        - "서울 강남구" => province="서울" AND city LIKE "%강남구%"
    """
    q = (
        db.query(Community_Post)
        .filter(Community_Post.post_type == 1)
        .order_by(Community_Post.created_at.desc())
    )

    if status in ("published", "closed"):
        q = q.filter(Community_Post.status == status)

    # --- 산업(업종) 필터 ---
    industries = [str(x).strip() for x in (getattr(me, "custom_industry_codes", None) or []) if str(x).strip()]
    if industries and "전체" not in industries:
        q = q.filter(
            or_(*[Community_Post.job_industry.ilike(f"%{ind}%") for ind in industries])
        )

    # --- 지역 필터 ---
    regions = [str(x).strip() for x in (getattr(me, "custom_region_codes", None) or []) if str(x).strip()]
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

            if city == "전체":
                conds.append(Community_Post.province == prov)
            else:
                conds.append(
                    and_(
                        Community_Post.province == prov,
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

    # 좋아요 여부는 me.username 기준으로 계산
    liked_ids = set()
    if rows and me.username:
        post_ids = [p.id for p in rows]
        liked_rows = (
            db.query(Post_Like.post_id)
            .filter(Post_Like.username == me.username, Post_Like.post_id.in_(post_ids))
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
    if province and province != "전체":
        q = q.filter(Community_Post.province == province)
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
    if province and province != "전체":
        q = q.filter(Community_Post.province == province)
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
 
    db.delete(post)
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
def export_users(db: Session = Depends(get_db)):
    users = db.query(Community_User).all()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Users"

    ws.append(["ID", "Username", "Name", "Phone", "Region", "Signup Date"])

    for u in users:
        ws.append([u.id, u.username, u.name, u.phone_number, u.position, u.region, u.signup_date])

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
    wb.save(tmp.name)

    return FileResponse(tmp.name, filename=f"users_{date.today()}.xlsx")


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
    data: dict = None
):
    noti = Notification(
        user_id=user_id,
        title=title,
        body=body,
        type=type,
        data=data or {}
    )
    db.add(noti)
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