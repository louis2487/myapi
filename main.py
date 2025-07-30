# main.py

import os
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from database import SessionLocal, engine
from models import Base, RuntimeRecord

# (기존) 메타데이터 생성
Base.metadata.create_all(bind=engine)

app = FastAPI()

# 의존성: 요청마다 세션 생성/종료
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic 모델
class RuntimePayload(BaseModel):
    user_id: str
    runtime_seconds: int

@app.post("/runtime/update")
def update_runtime(payload: RuntimePayload, db: Session = Depends(get_db)):
    # 1) INSERT 문 생성 + ON CONFLICT 처리
    stmt = insert(RuntimeRecord).values(
        user_id=payload.user_id,
        runtime_seconds=payload.runtime_seconds
    ).on_conflict_do_update(
        index_elements=["user_id"],  # UNIQUE 제약을 건 컬럼
        set_={
            "runtime_seconds": RuntimeRecord.runtime_seconds + payload.runtime_seconds,
            "timestamp": datetime.utcnow()
        }
    )

    # 2) 실행 & 커밋
    try:
        db.execute(stmt)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="데이터베이스 업데이트 실패") from e

    # 3) 누적된 총 런타임 조회
    total = db.query(RuntimeRecord.runtime_seconds)\
              .filter(RuntimeRecord.user_id == payload.user_id)\
              .scalar()

    return {
        "status": "ok",
        "user_id": payload.user_id,
        "total_runtime": total
    }
