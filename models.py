from sqlalchemy import Column, Integer, String, DateTime, BigInteger, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

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
    
    id   =  Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False, unique=True, index=True) 
    email = Column(String(255), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)

class Community_Post(Base):
    __tablename__ = "community_posts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("community_users.id"), index=True) 
    content = Column(Text)
    image_url = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    author = relationship("Community_User", foreign_keys=[user_id], lazy="joined")