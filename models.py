from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class RuntimeRecord(Base):
    __tablename__ = "time"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True,unique=True)
    runtime_seconds = Column(Integer)
