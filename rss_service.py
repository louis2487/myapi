# rss_service.py
import requests
import xml.etree.ElementTree as ET
from sqlalchemy.orm import Session
from datetime import datetime
from models import Community_Post

RSS_URL = "https://www.mk.co.kr/rss/50300009/"

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

        exists = db.query(Community_Post).filter(Community_Post.agent == link).first()
        if exists:
            continue

        post = Community_Post(
            title=title,
            agent=link,
            created_at=pub_date,
            user_id=1,
            post_type=2
        )

        db.add(post)

    db.commit()
