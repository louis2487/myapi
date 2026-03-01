import os

# .env 로드(로컬/개발 편의). 운영 환경에서는 플랫폼의 환경변수 주입을 권장.
try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except Exception:
    pass

# JWT / Auth
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# RSS
SECRET_RSS_TOKEN = os.getenv("SECRET_RSS_TOKEN", "rss-secret-token")

# Kakao (recode: geocode + route distance)
SMART_KAKAO_KEY = os.getenv("SMART_KAKAO_KEY", "").strip()
KAKAO_REST_API_KEY = os.getenv("KAKAO_REST_API_KEY", "").strip() or SMART_KAKAO_KEY
KAKAO_MOBILITY_API_KEY = os.getenv("KAKAO_MOBILITY_API_KEY", "").strip() or KAKAO_REST_API_KEY

