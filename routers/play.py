from __future__ import annotations

import base64
import json

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

import crud
from deps import get_db
from google_play import get_service
from services.subscriptions import (
    ack_subscription_if_needed,
    derive_subscription_status,
    to_dt_utc,
)


router = APIRouter()


@router.post("/play/rtdn")
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
        res = (
            service.purchases()
            .subscriptions()
            .get(
                packageName="kr.co.smartgauge",
                subscriptionId=product_id,
                token=purchase_token,
            )
            .execute()
        )

        ack_subscription_if_needed(
            service,
            product_id=product_id,
            purchase_token=purchase_token,
            developer_payload="rtdn",
        )

        expiry_ms = int(res.get("expiryTimeMillis", "0"))
        if not expiry_ms:
            return {"ok": True, "invalid_expiry": True}

        expires_at = to_dt_utc(expiry_ms)
        auto_renewing = bool(res.get("autoRenewing", True))
        order_id = res.get("orderId")
        status = derive_subscription_status(res)
        active = status in ["ACTIVE", "CANCELED"]

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

