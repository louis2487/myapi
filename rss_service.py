# rss_service.py
import requests
import xml.etree.ElementTree as ET
from sqlalchemy.orm import Session
from datetime import datetime
from urllib.parse import urlparse
from models import Community_Post

RSS_URL = "https://www.mk.co.kr/rss/50300009/"
REAL_ESTATE_PATH_PREFIX = "/news/realestate/"

def parse_pubdate(pub_date: str) -> datetime:
    try:
        return datetime.strptime(pub_date, "%a, %d %b %Y %H:%M:%S %z")
    except:
        return datetime.utcnow()

def fetch_rss_and_save(db: Session):
    resp = requests.get(RSS_URL, timeout=5)
    resp.raise_for_status()

    root = ET.fromstring(resp.text)
    items = root.findall("./channel/item")

    for item in items:
        title = (item.find("title").text or "").strip()
        link = (item.find("link").text or "").strip()
        pub_date_str = (item.find("pubDate").text or "").strip()
        pub_date = parse_pubdate(pub_date_str)
        summary = (item.find("description").text or "").strip()

        # mk RSS(50300009)에서 기업/정치 등 다른 섹션 링크가 섞여 내려오는 경우가 있어
        # URL 경로 기준으로 부동산 섹션만 저장합니다.
        try:
            path = urlparse(link).path or ""
        except Exception:
            path = ""
        if not path.startswith(REAL_ESTATE_PATH_PREFIX):
            continue

        exists = db.query(Community_Post).filter(Community_Post.agent == link).first()
        if exists:
            continue

        post = Community_Post(
            title=title,
            agent=link,
            created_at=pub_date,
            user_id=1,
            post_type=2,
            content=summary
        )

        db.add(post)

    db.commit()
