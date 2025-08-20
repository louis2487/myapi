import os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from database import SessionLocal, engine
import models
from models import Base, RuntimeRecord, User, Recode, RangeSummaryOut, PurchaseVerifyIn, SubscriptionStatusOut
import hashlib
import jwt 
from sqlalchemy import func ,select 
from google_play import get_service, PACKAGE_NAME
import crud
from fastapi import status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import base64, json
from googleapiclient.errors import HttpError

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
            subscriptionId="smartgauge_yearly",
            token=purchase_token,
        ).execute()
        _ack_if_needed(service, payload.product_id, payload.purchase_token, developer_payload=f"user:{user_id}")

        expiry_ms = int(res.get("expiryTimeMillis", "0"))
        if not expiry_ms:
            return {"ok": True, "invalid_expiry": True}

        expires_at = _to_dt_utc(expiry_ms)
        auto_renewing = bool(res.get("autoRenewing", True))
        order_id = res.get("orderId")
        status = _derive_status(expiry_ms)  

    
        row = crud.get_subscription_by_token(db, purchase_token)
        if row:
            crud.update_subscription_fields(
                db,
                row,
                product_id="smartgauge_yearly",
                order_id=order_id,
                expires_at=expires_at,
                auto_renewing=auto_renewing,
                status=status,
                active=(status == "ACTIVE"),
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
                    product_id="smartgauge_yearly",
                    purchase_token=purchase_token,
                    order_id=order_id,
                    expires_at=expires_at,
                    auto_renewing=auto_renewing,
                    status=status,
                )
                db.commit()
                return {"ok": True, "migrated_from_linked": True}

        return {"ok": True, "unknown_token": True}

    except Exception as e:
        raise HTTPException(status_code=200, detail=str(e))
        return {"ok": False, "error": str(e)}



        
def _ack_if_needed(service, product_id: str, purchase_token: str, developer_payload: str = "") -> None:
    try:
        service.purchases().subscriptions().acknowledge(
            packageName=PACKAGE_NAME,
            subscriptionId=product_id,
            token=purchase_token,
            body={"developerPayload": developer_payload or ""}
        ).execute()
    except HttpError as e:
        code = getattr(e, "status_code", None) or (e.resp.status if hasattr(e, "resp") else None)
        if code in (400, 409):
            return
        raise


def get_current_user_id(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> int:
    token = creds.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    uid = payload.get("sub") or payload.get("user_id")
    try:
        uid = int(uid)
    except:
        raise HTTPException(status_code=401, detail="Invalid user id")

    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return uid


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
    user_id: int = Depends(get_current_user_id),
):
    try:
        service = get_service()
        res = service.purchases().subscriptions().get(
            packageName="kr.co.smartgauge",
            subscriptionId="smartgauge_yearly",
            token=payload.purchase_token,
        ).execute()
        _ack_if_needed(service, payload.product_id, payload.purchase_token, developer_payload=f"user:{user_id}")

    except HttpError as e:
        code = getattr(e, "status_code", None) or (e.resp.status if hasattr(e, "resp") else None)
        msg = e.reason if hasattr(e, "reason") else str(e)
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

    crud.deactivate_active_for_user(db, user_id)
    crud.insert_active_subscription(
        db=db,
        user_id=user_id,
        product_id="smartgauge_yearly",
        purchase_token=payload.purchase_token,
        order_id=order_id,
        expires_at=expires_at,
        auto_renewing=auto_renewing,
        status=status,
    )
    db.commit()

    return SubscriptionStatusOut(
        active=(status == "ACTIVE"),
        product_id=payload.product_id,
        expires_at=expires_at,
        status=status,
        auto_renewing=auto_renewing,
    )


@app.get("/billing/status", response_model=SubscriptionStatusOut)
def get_subscription_status(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    
    sub = crud.get_active_subscription(db, user_id)
    if not sub:
        return SubscriptionStatusOut(active=False)

    return SubscriptionStatusOut(
        active=(sub.status == "ACTIVE"),
        product_id=sub.product_id,
        expires_at=sub.expires_at,
        status=sub.status,
        auto_renewing=sub.auto_renewing,
    )