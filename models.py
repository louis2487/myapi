from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

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
