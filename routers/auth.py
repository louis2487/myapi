from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

import jwt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from deps import get_db
from models import User
from settings import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY


router = APIRouter()


class SignupRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    user_id: int
    token: str


@router.post("/auth/signup")
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()
    user = User(username=req.username, email=req.email, password_hash=pw_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"status": "ok", "user_id": user.id}


@router.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    pw_hash = hashlib.sha256(req.password.encode()).hexdigest()
    if user.password_hash != pw_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": str(user.id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    return LoginResponse(user_id=user.id, token=token)

