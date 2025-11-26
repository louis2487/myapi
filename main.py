import os
from datetime import datetime, timedelta, timezone, date
from fastapi import FastAPI, Depends, HTTPException, status, Request, Header, Query, Body
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from database import SessionLocal, engine
import models
from models import Base, RuntimeRecord, User, Recode, RangeSummaryOut, PurchaseVerifyIn, SubscriptionStatusOut, Community_User, Community_Post, Community_Comment, Post_Like
import hashlib
import jwt 
from sqlalchemy import func ,select, or_, and_
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
from fastapi.responses import FileResponse
import openpyxl, tempfile
Base.metadata.create_all(bind=engine)
app = FastAPI()
bearer = HTTPBearer(auto_error=True)

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

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
    region: str | None = Field(default=None, max_length=100)

   
@app.post("/community/signup")
def community_signup(req: SignupRequest_C, db: Session = Depends(get_db)):

    if db.query(Community_User).filter(Community_User.username == req.username).first():
        return {"status": 1} 

    if req.password != req.password_confirm:
        return {"status": 2} 

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()

    user = Community_User(
        username      = req.username,
        password_hash = pw_hash,
        name          = req.name,
        phone_number  = req.phone_number,
        region        = req.region,  
        signup_date   = date.today(), 
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"status": 0}


@app.get("/community/user/{username}")
def get_user(username: str, db: Session = Depends(get_db)):

    user = db.query(Community_User).filter(Community_User.username == username).first()

    if not user:
        return {"status": 1}   

    return {
        "status": 0,
        "user": {
            "username": username,
            "name": user.name,
            "phone_number": user.phone_number,
            "region": user.region,
            "signup_date": user.signup_date,
        }
    }


class UserUpdateRequest(BaseModel):
    username: str | None = Field(default=None, min_length=2, max_length=50)  # 새 아이디
    password: str | None = Field(default=None, min_length=2, max_length=255)
    password_confirm: str | None = Field(default=None, min_length=2, max_length=255)
    name: str | None = Field(default=None, max_length=50)       # 실명
    phone_number: str | None = Field(default=None, max_length=20)
    region: str | None = Field(default=None, max_length=100)


@app.put("/community/user/{username}")
def update_user(username: str, req: UserUpdateRequest, db: Session = Depends(get_db)):

    user = db.query(Community_User).filter(Community_User.username == username).first()

    if not user:
        return {"status": 1}  

    if req.username is not None and req.username != username:
        new_username = req.username

        exists = db.query(Community_User).filter(Community_User.username == new_username).first()
        if exists:
            return {"status": 2}  

        old_username = username

        db.query(Post_Like).filter(
            Post_Like.username == old_username
        ).update(
            {"username": new_username},
            synchronize_session=False
        )

        user.username = new_username

    if req.password is not None:
        if req.password_confirm is None:
            return {"status": 3}  

        if req.password != req.password_confirm:
            return {"status": 4}  

        user.password_hash = hashlib.sha256(req.password.encode()).hexdigest()

    if req.name is not None:
        user.name = req.name

    if req.phone_number is not None:
        user.phone_number = req.phone_number

    if req.region is not None:
        user.region = req.region


    db.commit()
    db.refresh(user)

    return {"status": 0, "username" : user.username}


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

    return {
        "status": 0,
        "signup_date": user.signup_date,  
        "posts": {
            "type1": counts[1],
            "type3": counts[3],
            "type4": counts[4],
        },
    }


@app.post("/community/login", response_model=LoginResponse)
def community_login(req: LoginRequest, db: Session = Depends(get_db)):

    user = db.query(Community_User).filter(Community_User.username == req.username).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()
    if user.password_hash != pw_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

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
        card_type= body.card_type,
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


@app.get("/community/posts", response_model=PostsOut2)
def list_posts(
    username: Optional[str] = Query(None, description="좋아요 여부 계산용 유저명"),
    cursor: Optional[str] = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(1000, ge=1, le=1000),
    status: Optional[str] = Query(None, description="published | closed"),
    db: Session = Depends(get_db),
):
    q = (
        db.query(Community_Post)
          .filter(Community_Post.post_type == 1)
          .order_by(Community_Post.created_at.desc())
    )

    if status in ("published", "closed"):
        q = q.filter(Community_Post.status == status)

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
    limit: int = Query(1000, ge=1, le=1000),
    status: Optional[str] = Query(None, description="published | closed"),
    db: Session = Depends(get_db),
):
    q = (
        db.query(Community_Post)
          .filter(Community_Post.post_type == post_type)
          .order_by(Community_Post.created_at.desc())
    )

    if status in ("published", "closed"):
        q = q.filter(Community_Post.status == status)

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
    q = (
        db.query(Community_Post)
          .filter(Community_Post.post_type == post_type)
          .filter(Community_Post.author.has(username=username)) 
          .order_by(Community_Post.created_at.desc())
    )

    if status in ("published", "closed"):
        q = q.filter(Community_Post.status == status)

    if cursor:
        try:
            cur_dt = datetime.fromisoformat(cursor)
            q = q.filter(Community_Post.created_at < cur_dt)
        except Exception:
            pass

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