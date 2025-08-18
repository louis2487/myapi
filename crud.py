from sqlalchemy.orm import Session
from datetime import datetime
from .models import Subscription
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

