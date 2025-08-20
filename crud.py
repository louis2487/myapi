from sqlalchemy.orm import Session
from datetime import datetime, timezone
from models import Subscription
from sqlalchemy.orm import Session
from sqlalchemy import func 
def deactivate_active_for_user(db: Session, user_id: int):
    db.query(Subscription).filter(
        Subscription.user_id == user_id,
        Subscription.active == True
    ).update({Subscription.active: False})

def insert_active_subscription(
    db: Session, user_id: int, product_id: str, purchase_token: str,
    order_id: str | None, expires_at: datetime, auto_renewing: bool, status: str
):
    sub = Subscription(
        user_id=user_id,
        product_id=product_id,
        purchase_token=purchase_token,
        order_id=order_id,
        expires_at=expires_at,
        auto_renewing=auto_renewing,
        status=status,
        active=True
    )
    sub.last_verified_at = func.now()
    db.add(sub)
    return sub

def get_active_subscription(db: Session, user_id: int) -> Subscription | None:
    return db.query(Subscription).filter(
        Subscription.user_id == user_id,
        Subscription.active == True
    ).one_or_none()

def get_subscription_by_token(db: Session, purchase_token: str) -> Subscription | None:
    return db.query(Subscription).filter(
        Subscription.purchase_token == purchase_token
    ).one_or_none()

def update_subscription_fields(
    db: Session,
    sub: Subscription,
    *,
    product_id: str | None = None,
    order_id: str | None = None,
    expires_at: datetime | None = None,
    auto_renewing: bool | None = None,
    status: str | None = None,
    active: bool | None = None,
):
    if product_id is not None:
        sub.product_id = product_id
    if order_id is not None:
        sub.order_id = order_id
    if expires_at is not None:
        sub.expires_at = expires_at
    if auto_renewing is not None:
        sub.auto_renewing = auto_renewing
    if status is not None:
        sub.status = status
    if active is not None:
        sub.active = active
    sub.last_verified_at = datetime.now(timezone.utc)
    db.add(sub)
    return sub