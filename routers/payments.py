from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime

import requests
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from deps import get_db
from models import Cash, Community_User, Payment

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None


router = APIRouter()


# -------------------- TossPayments (SSOT) --------------------
# clientKey: 결제 페이지(HTML)에서만 사용
# secretKey: 서버에서 confirm 호출에만 사용 (절대 앱/웹에 노출 금지)
TOSS_CLIENT_KEY = os.getenv("TOSS_CLIENT_KEY", "").strip()
TOSS_SECRET_KEY = os.getenv("TOSS_SECRET_KEY", "").strip()

# 결제 성공/실패 시 앱으로 돌아오는 딥링크 스킴
TOSS_APP_SCHEME = os.getenv("TOSS_APP_SCHEME", "smartgauge").strip() or "smartgauge"

# 캐시 충전 허용 금액(서버가 최종 결정)
ALLOWED_CASH_AMOUNTS = {10000, 30000, 50000, 80000, 100000}


class TossOrderCreateRequest(BaseModel):
    username: str
    amount: int


class TossOrderCreateResponse(BaseModel):
    status: int
    orderId: str
    amount: int
    orderName: str
    customerName: str


class TossConfirmRequest(BaseModel):
    paymentKey: str
    orderId: str
    amount: int


@router.post("/orders/create", response_model=TossOrderCreateResponse)
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
    row = Payment(order_id=order_id, user_id=user.id, amount=amount, status="PENDING")
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


@router.get("/pay/toss")
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
        raise HTTPException(
            status_code=400, detail=f"order not payable (status={pay.status})"
        )

    if int(pay.amount) != int(amount):
        raise HTTPException(status_code=400, detail="amount mismatch")

    # Toss가 paymentKey/orderId/amount를 query로 붙여서 redirect
    success_url = f"{TOSS_APP_SCHEME}://toss/success"
    fail_url = f"{TOSS_APP_SCHEME}://toss/fail"

    # customerEmail은 선택값. (없으면 Toss가 무시)
    customer_email_js = f'"{customerEmail}"' if customerEmail else "undefined"

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


@router.post("/payments/toss/confirm")
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
        db.query(Payment).filter(Payment.order_id == order_uuid).with_for_update().first()
    )
    if not pay:
        raise HTTPException(status_code=404, detail="order not found")

    if int(pay.amount) != amount:
        raise HTTPException(status_code=400, detail="amount mismatch")

    if pay.status == "PAID":
        return {
            "status": 0,
            "alreadyPaid": True,
            "orderId": str(pay.order_id),
            "amount": int(pay.amount),
            "paymentKey": pay.payment_key,
        }

    if pay.status != "PENDING":
        raise HTTPException(
            status_code=400, detail=f"order not confirmable (status={pay.status})"
        )

    # Toss confirm API 호출
    auth = base64.b64encode(f"{TOSS_SECRET_KEY}:".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
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
        "toss": {"method": data.get("method"), "status": data.get("status")},
    }

