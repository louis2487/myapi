from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from deps import get_db
from rss_service import fetch_rss_and_save
from settings import SECRET_RSS_TOKEN


router = APIRouter()


@router.get("/internal/rss-refresh")
def rss_refresh(x_internal_token: str = Header(None), db: Session = Depends(get_db)):
    if x_internal_token != SECRET_RSS_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    fetch_rss_and_save(db)
    return {"status": "ok"}

