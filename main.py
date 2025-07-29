from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from models import Base, RuntimeRecord
from database import SessionLocal, engine

Base.metadata.create_all(bind=engine)  

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RuntimePayload(BaseModel):
    user_id: str
    runtime_seconds: int

@app.post("/runtime/update")
def update_runtime(payload: RuntimePayload, db: Session = Depends(get_db)):
    record = RuntimeRecord(
        user_id=payload.user_id,
        runtime_seconds=payload.runtime_seconds
    )
    db.add(record)
    db.commit()
    return {"status": "saved", "runtime": payload.runtime_seconds}
