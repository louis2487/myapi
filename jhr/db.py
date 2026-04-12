from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

_JHR_SCHEMA_READY = False


def _ensure_jhr_schema(db: Session):
    global _JHR_SCHEMA_READY
    if _JHR_SCHEMA_READY:
        return
    try:
        db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS jhr_classes (
                    id BIGSERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    price NUMERIC(12,2) NOT NULL DEFAULT 0,
                    capacity INTEGER NOT NULL,
                    current_count INTEGER NOT NULL DEFAULT 0,
                    start_date TIMESTAMPTZ NOT NULL,
                    end_date TIMESTAMPTZ NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
                    creator_user_id BIGINT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
        )
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS creator_user_id BIGINT"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS title VARCHAR(255)"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS description TEXT"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS price NUMERIC(12,2)"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS capacity INTEGER"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS current_count INTEGER"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS start_date TIMESTAMPTZ"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS end_date TIMESTAMPTZ"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS status VARCHAR(20)"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ"))
        db.execute(text("ALTER TABLE jhr_classes ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ"))

        db.execute(
            text(
                """
                UPDATE jhr_classes
                SET title = COALESCE(NULLIF(title, ''), '제목 없음')
                WHERE title IS NULL OR title = ''
                """
            )
        )
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN title SET NOT NULL"))

        db.execute(text("UPDATE jhr_classes SET price = 0 WHERE price IS NULL"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN price SET DEFAULT 0"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN price SET NOT NULL"))

        db.execute(text("UPDATE jhr_classes SET capacity = 1 WHERE capacity IS NULL OR capacity < 1"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN capacity SET DEFAULT 1"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN capacity SET NOT NULL"))

        db.execute(text("UPDATE jhr_classes SET current_count = 0 WHERE current_count IS NULL OR current_count < 0"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN current_count SET DEFAULT 0"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN current_count SET NOT NULL"))

        db.execute(text("UPDATE jhr_classes SET created_at = now() WHERE created_at IS NULL"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN created_at SET DEFAULT now()"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN created_at SET NOT NULL"))

        db.execute(text("UPDATE jhr_classes SET updated_at = now() WHERE updated_at IS NULL"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN updated_at SET DEFAULT now()"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN updated_at SET NOT NULL"))

        db.execute(
            text(
                """
                UPDATE jhr_classes
                SET start_date = COALESCE(start_date, created_at, now())
                WHERE start_date IS NULL
                """
            )
        )
        db.execute(
            text(
                """
                UPDATE jhr_classes
                SET end_date = COALESCE(end_date, start_date + interval '1 day', now() + interval '1 day')
                WHERE end_date IS NULL
                """
            )
        )
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN start_date SET NOT NULL"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN end_date SET NOT NULL"))

        db.execute(
            text(
                """
                UPDATE jhr_classes
                SET status = 'DRAFT'
                WHERE status IS NULL OR status NOT IN ('DRAFT', 'OPEN', 'CLOSED')
                """
            )
        )
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN status SET DEFAULT 'DRAFT'"))
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN status SET NOT NULL"))

        db.execute(
            text(
                """
                UPDATE jhr_classes
                SET creator_user_id = 0
                WHERE creator_user_id IS NULL
                """
            )
        )
        db.execute(text("ALTER TABLE jhr_classes ALTER COLUMN creator_user_id SET NOT NULL"))
        db.execute(text("ALTER TABLE jhr_classes DROP CONSTRAINT IF EXISTS jhr_classes_status_check"))
        db.execute(
            text(
                """
                ALTER TABLE jhr_classes
                ADD CONSTRAINT jhr_classes_status_check
                CHECK (status IN ('DRAFT', 'OPEN', 'CLOSED'))
                """
            )
        )
        db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS ix_jhr_classes_status_created
                ON jhr_classes (status, created_at DESC)
                """
            )
        )

        db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS jhr_enrollments (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    class_id BIGINT NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    confirmed_at TIMESTAMPTZ NULL,
                    canceled_at TIMESTAMPTZ NULL
                );
                """
            )
        )
        db.execute(text("ALTER TABLE jhr_enrollments DROP CONSTRAINT IF EXISTS jhr_enrollments_status_check"))
        db.execute(
            text(
                """
                ALTER TABLE jhr_enrollments
                ADD CONSTRAINT jhr_enrollments_status_check
                CHECK (status IN ('PENDING', 'CONFIRMED', 'CANCELLED'))
                """
            )
        )
        db.execute(
            text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS uq_jhr_enrollments_user_class
                ON jhr_enrollments (user_id, class_id)
                """
            )
        )
        db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS ix_jhr_enrollments_class_status
                ON jhr_enrollments (class_id, status)
                """
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        _JHR_SCHEMA_READY = True
