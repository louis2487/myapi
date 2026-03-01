from __future__ import annotations

from datetime import datetime, timezone

from googleapiclient.errors import HttpError

from google_play import PACKAGE_NAME


def ack_subscription_if_needed(
    service,
    *,
    product_id: str,
    purchase_token: str,
    developer_payload: str = "",
) -> None:
    """
    Google Play 구독 acknowledge.
    - 이미 acknowledge 된 토큰은 409가 날 수 있어 무시합니다.
    - 400은 토큰/상태에 따라 발생할 수 있어 무시합니다(기존 동작 유지).
    """
    try:
        service.purchases().subscriptions().acknowledge(
            packageName=PACKAGE_NAME,
            subscriptionId=product_id,
            token=purchase_token,
            body={"developerPayload": developer_payload or ""},
        ).execute()
    except HttpError as e:
        code = getattr(e, "status_code", None) or (
            e.resp.status if hasattr(e, "resp") else None
        )
        if code in (400, 409):
            return
        raise


def to_dt_utc(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


def derive_subscription_status(res: dict) -> str:
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

