from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from googleapiclient.errors import HttpError
from sqlalchemy.orm import Session

import crud
from deps import get_db
from google_play import get_service
from models import PurchaseVerifyIn, SubscriptionStatusOut, User
from services.subscriptions import (
    ack_subscription_if_needed,
    derive_subscription_status,
    to_dt_utc,
)


router = APIRouter()


@router.post("/billing/verify", response_model=SubscriptionStatusOut)
def verify_subscription_endpoint(payload: PurchaseVerifyIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username")
    user_id = user.id

    try:
        service = get_service()
        res = (
            service.purchases()
            .subscriptions()
            .get(
                packageName="kr.co.smartgauge",
                subscriptionId=payload.product_id,
                token=payload.purchase_token,
            )
            .execute()
        )

        ack_subscription_if_needed(
            service,
            product_id=payload.product_id,
            purchase_token=payload.purchase_token,
            developer_payload=f"user:{user.username}",
        )
    except HttpError as e:
        code = getattr(e, "status_code", None) or (
            e.resp.status if hasattr(e, "resp") else None
        )
        msg = e.reason if hasattr(e, "reason") else str(e)
        print(f"[Google API Error] code={code}, msg={msg}")
        if code in (400, 404, 410):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid purchase token/product ({code}): {msg}",
            )
        raise HTTPException(status_code=502, detail=f"Google API error ({code}): {msg}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Google API error: {e}")

    expiry_ms = int(res.get("expiryTimeMillis", "0"))
    if not expiry_ms:
        raise HTTPException(
            status_code=400, detail="Invalid expiryTimeMillis from Google API"
        )

    expires_at = to_dt_utc(expiry_ms)
    auto_renewing = bool(res.get("autoRenewing", True))
    order_id = res.get("orderId")
    status = derive_subscription_status(res)
    active = status in ["ACTIVE", "CANCELED"]

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
            active=active,
        )
    db.commit()

    return SubscriptionStatusOut(
        active=active,
        product_id=payload.product_id,
        expires_at=expires_at,
        status=status,
        auto_renewing=auto_renewing,
    )


@router.get("/billing/status", response_model=SubscriptionStatusOut)
def get_subscription_status(username: str, db: Session = Depends(get_db)):
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

