from sqlalchemy import Column, Integer, String, DateTime, BigInteger, Boolean, Text, ForeignKey, Date, UniqueConstraint, Index, JSON, text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, date
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import DOUBLE_PRECISION, ARRAY
from sqlalchemy.dialects.postgresql import UUID
import uuid as _uuid
Base = declarative_base()

class RuntimeRecord(Base):
    __tablename__ = "time"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True,unique=True)
    runtime_seconds = Column(Integer)


class User(Base):
    __tablename__ = "users"
    
    id   =  Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False, unique=True, index=True) 
    email = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    
    subscriptions = relationship("Subscription", back_populates="user")

class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    product_id = Column(Text, nullable=False)
    purchase_token = Column(Text, nullable=False)
    order_id = Column(Text, nullable=True)
    subscribed_at = Column(DateTime(timezone=True), nullable=False, default=datetime.now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    auto_renewing = Column(Boolean, nullable=False, default=True)
    status = Column(Text, nullable=False)  
    last_verified_at = Column(DateTime(timezone=True), nullable=False, default=datetime.now, onupdate=datetime.now)
    active = Column(Boolean, nullable=False, default=False)

    user = relationship("User", back_populates="subscriptions")

class Recode(Base):
    __tablename__ = "recode"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    date = Column(String)
    ontime = Column(String)  
    offtime = Column(String)   
    duration = Column(Integer)  


class RangeSummaryOut(BaseModel):
    username: str
    start: str
    end: str
    on_count: int
    runtime_seconds: int

class PurchaseVerifyIn(BaseModel):
    username: str 
    product_id: str
    purchase_token: str

class SubscriptionStatusOut(BaseModel):
    active: bool
    product_id: str | None = None
    expires_at: datetime | None = None
    status: str | None = None
    auto_renewing: bool | None = None

    model_config = ConfigDict(from_attributes=True)

#---------------community-app-mvp-----------------------------------------------------------

class Community_User(Base):
    __tablename__ = "community_users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    name          = Column(String(50),  nullable=True)
    phone_number  = Column(String(20),  nullable=True)  
    region        = Column(String(100), nullable=True)
    signup_date = Column(Date, nullable=True, default=date.today)
    push_token = Column(String(255), nullable=True)
    point_balance = Column(BigInteger, nullable=False, server_default="0")
    cash_balance = Column(BigInteger, nullable=False, server_default="0")
    admin_acknowledged = Column(Boolean, nullable=False, server_default="false")
    referral_code = Column(String(20), nullable=True)
    # --- 2026-01: community_users 신규 필드(서버/앱 연동용) ---
    custom_industry_codes = Column(
        ARRAY(Text),
        nullable=False,
        server_default=text("'{}'::text[]"),
    )
    custom_region_codes = Column(
        ARRAY(Text),
        nullable=False,
        server_default=text("'{}'::text[]"),
    )
    popup_last_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_attendance_date = Column(Date, nullable=True)
    marketing_consent = Column(Boolean, nullable=False, server_default="false")

class Community_Phone_Verification(Base):
    """
    커뮤니티 회원가입 휴대폰 인증번호 발송/검증 이력.
    - 회원가입 단계에서만 사용 (phone_number + verified_at으로 검증)
    """
    __tablename__ = "community_phone_verifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid.uuid4)
    phone_number = Column(String(20), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    verified_at = Column(DateTime(timezone=True), nullable=True, index=True)

    attempts = Column(Integer, nullable=False, server_default="0")

class Community_Post(Base):
    __tablename__ = "community_posts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("community_users.id", ondelete="RESTRICT"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    image_url = Column(String(512))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    contract_fee = Column(String(255))               
    workplace_address = Column(String(255))          
    workplace_map_url = Column(String(512))   
    workplace_lat= Column(DOUBLE_PRECISION, nullable=True)   
    workplace_lng= Column(DOUBLE_PRECISION, nullable=True)   
    business_lat= Column(DOUBLE_PRECISION, nullable=True)   
    business_lng= Column(DOUBLE_PRECISION, nullable=True)          
    business_address = Column(String(255))           
    business_map_url = Column(String(512))            
    job_industry = Column(String(100))               
    job_category = Column(String(100))                
    pay_support = Column(Boolean)                      
    meal_support = Column(Boolean)                   
    house_support = Column(Boolean)               
    company_developer = Column(String(255))            
    company_constructor = Column(String(255))       
    company_trustee = Column(String(255))              
    company_agency = Column(String(255))          
    agency_call = Column(String(50))
    province = Column(String(50), nullable=True)   
    city     = Column(String(50), nullable=True)
    status = Column(String(20), nullable=False, default="published")
    highlight_color = Column(String(255))
    highlight_content = Column(String(255))
    total_use = Column(Boolean) 
    branch_use =Column(Boolean) 
    leader_use = Column(Boolean) 
    member_use =Column(Boolean)
    total_fee = Column(String(255)) 
    branch_fee = Column(String(255))  
    leader_fee = Column(String(255))  
    member_fee = Column(String(255))
    pay_use = Column(Boolean)  
    meal_use = Column(Boolean)                   
    house_use = Column(Boolean)
    pay_sup = Column(String(255)) 
    meal_sup = Column(Boolean)                   
    house_sup  = Column(String(255))
    item1_use = Column(Boolean)  
    item1_type = Column(String(255))
    item1_sup = Column(String(255)) 
    item2_use = Column(Boolean)  
    item2_type = Column(String(255))
    item2_sup = Column(String(255))
    item3_use = Column(Boolean)     
    item3_type = Column(String(255))
    item3_sup = Column(String(255)) 
    item4_use = Column(Boolean)  
    item4_type = Column(String(255))
    item4_sup = Column(String(255)) 
    agent = Column(String(255))
    post_type= Column(DOUBLE_PRECISION, nullable=True)   
    card_type= Column(DOUBLE_PRECISION, nullable=True)                 

    author = relationship("Community_User", foreign_keys=[user_id], lazy="joined")
    comments = relationship("Community_Comment", back_populates="post", cascade="all, delete-orphan")

class Community_Comment(Base):
    __tablename__ = "community_comments"
    id = Column(BigInteger, primary_key=True, index=True)  
    post_id = Column(Integer, ForeignKey("community_posts.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("community_users.id", ondelete="RESTRICT"), nullable=False, index=True)
    username = Column(String(50), nullable=False, index=True)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    parent_id = Column(BigInteger, ForeignKey("community_comments.id", ondelete="CASCADE"), nullable=True, index=True)
    is_deleted = Column(Boolean, nullable=False, server_default="false")
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    post = relationship("Community_Post", back_populates="comments", lazy="joined")
    user = relationship("Community_User", lazy="joined")


class Post_Like(Base):
    __tablename__ = "post_likes"

    username = Column(String(50), ForeignKey("community_users.username"), primary_key=True)
    post_id = Column(Integer, ForeignKey("community_posts.id"), primary_key=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_post_likes_user_created", "username", "created_at"),
        Index("ix_post_likes_post", "post_id"),
    )

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("community_users.id", ondelete="CASCADE"), nullable=False)
    user = relationship("Community_User")  

    type = Column(String(50), nullable=True)            
    title = Column(Text, nullable=True)
    body = Column(Text, nullable=True)

    data = Column(JSON, nullable=True)                  

    is_read = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)


class Referral(Base):
    """
    커뮤니티 추천(추천인/피추천인) 이벤트 테이블.
    - 사용자 요청: FK/UNIQUE 등 제약조건 제거 (DB에서 강제하지 않음)
    """
    __tablename__ = "referral"

    # PostgreSQL BIGSERIAL과 호환되도록 autoincrement 보장
    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)
    referrer_user_id = Column(BigInteger, nullable=False, index=True)
    referred_user_id = Column(BigInteger, nullable=False, index=True)
    referrer_code = Column(String(20), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __table_args__ = (
        Index("idx_referral_events_referrer", "referrer_user_id", "created_at"),
    )


class Point(Base):
    """
    포인트 원장(적립/사용 내역) 테이블.
    - 사용자 요청: FK 등 제약조건 제거 (DB에서 강제하지 않음)
    """
    __tablename__ = "point"

    # PostgreSQL BIGSERIAL과 호환되도록 autoincrement 보장
    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    reason = Column(String(50), nullable=False)
    amount = Column(BigInteger, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __table_args__ = (
        Index("idx_point_ledger_user_time", "user_id", "created_at"),
    )


class Cash(Base):
    """
    캐시 원장(충전/사용 내역) 테이블.
    - 사용자 요청: FK 등 제약조건 제거 (DB에서 강제하지 않음)
    """
    __tablename__ = "cash"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    reason = Column(String(50), nullable=False)
    amount = Column(BigInteger, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __table_args__ = (
        Index("idx_cash_ledger_user_time", "user_id", "created_at"),
    )


class Payment(Base):
    """
    TossPayments 결제 상태 저장 (orders/payments SSOT).
    DB 스키마는 사용자가 제공한 payments 테이블을 기준으로 매핑합니다.
    """
    __tablename__ = "payments"

    id = Column(BigInteger, primary_key=True, index=True, autoincrement=True)
    order_id = Column(UUID(as_uuid=True), nullable=False, unique=True, index=True, default=_uuid.uuid4)
    user_id = Column(BigInteger, nullable=False, index=True)
    amount = Column(BigInteger, nullable=False)
    status = Column(String(20), nullable=False)  # PENDING | PAID | FAILED | CANCELED

    payment_key = Column(String(200), nullable=True, unique=True, index=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())