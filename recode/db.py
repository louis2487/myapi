from sqlalchemy import text

from database import engine


def ensure_recode_columns() -> None:
    """
    recode 테이블을 운행일지 스펙(smartgauge.md)에 맞춰 확장합니다.
    - 기존 테이블이 있어도 컬럼이 없으면 ADD COLUMN IF NOT EXISTS로 보강
    - 기존 앱 하위호환을 위해 username/duration(초) 컬럼은 유지
    """
    try:
        with engine.begin() as conn:
            exists = conn.execute(
                text("SELECT to_regclass('public.recode') IS NOT NULL")
            ).scalar()
            if not exists:
                return

            conn.execute(
                text(
                    """
                    ALTER TABLE public.recode
                      ADD COLUMN IF NOT EXISTS user_id integer NULL,
                      ADD COLUMN IF NOT EXISTS duration_minutes integer NULL,
                      ADD COLUMN IF NOT EXISTS start_location text NULL,
                      ADD COLUMN IF NOT EXISTS end_location text NULL,
                      ADD COLUMN IF NOT EXISTS trip_km numeric(10,2) NULL,
                      ADD COLUMN IF NOT EXISTS trip_purpose text NULL,
                      ADD COLUMN IF NOT EXISTS business_use boolean NOT NULL DEFAULT false;
                    """
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_recode_user_id ON public.recode (user_id);"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_recode_date ON public.recode (date);"
                )
            )
    except Exception as e:
        print(f"[WARN] ensure recode columns failed: {e}")

