from __future__ import annotations

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from models import Community_Post, Community_User, Point, Referral

# -------------------- Community Post card_type rollover --------------------
# 요구사항:
# - 구인글(post_type=1)은 write.tsx에서 항상 card_type=1로 등록됨
# - 서버에서 card_type=1 글이 30개 초과 시: 가장 오래된 1유형을 2유형으로 변경
CARD1_MAX = 30
# 광고글(post_type=4): 카테고리(job_industry)별 목록 개수 제한
AD_CARD1_MAX = 5  # (=카테고리별 최대 published 개수)
AD_PRIMARY_CATEGORY = "광고"
# legacy(하위호환): 기존 DB/앱은 "광고업체"를 사용했음
AD_CATEGORY_ALIASES: dict[str, str] = {"광고업체": AD_PRIMARY_CATEGORY}
AD_CATEGORIES: tuple[str, ...] = (AD_PRIMARY_CATEGORY, "대출", "급매물", "중고장터")


def _normalize_ad_job_industry(job_industry: str | None) -> str:
    v = (job_industry or "").strip()
    v = AD_CATEGORY_ALIASES.get(v, v)
    return v if v in AD_CATEGORIES else AD_PRIMARY_CATEGORY


def _ad_category_db_values(cat: str) -> list[str]:
    """
    UI/서버 표준 카테고리(cat)를, DB에 남아있는 레거시 값까지 포함한
    job_industry 필터 목록으로 변환합니다.
    """
    if cat == AD_PRIMARY_CATEGORY:
        # 레거시 "광고업체" 포함
        return [AD_PRIMARY_CATEGORY, "광고업체"]
    return [cat]


GRADE_REWARD_BY_GRADE: dict[int, int] = {
    # 등급 달성 보상 포인트(1회성)
    # -1: 일반회원(보상 없음)
    0: 50_000,  # 아마추어
    1: 100_000,  # 세미프로
    2: 200_000,  # 프로
    3: 500_000,  # 마스터
    4: 1_000_000,  # 레전드
}


def _grade_from_referral_count(referral_count: int) -> int:
    """
    추천인 수 기준 user_grade 자동 등업.
    user_grade:
      -1: 일반회원(기본)
       0: 아마추어(5명 이상)
       1: 세미프로(10명 이상)
       2: 프로(20명 이상)
       3: 마스터(50명 이상)
       4: 레전드(100명 이상)
    """
    c = int(referral_count or 0)
    if c >= 100:
        return 4
    if c >= 50:
        return 3
    if c >= 20:
        return 2
    if c >= 10:
        return 1
    if c >= 5:
        return 0
    return -1


def _grant_user_grade_reward_if_needed(db: Session, user: Community_User, grade: int) -> int:
    """
    등급 달성 보상 포인트를 1회만 지급.
    - 이미 지급된 경우: 0 반환
    - 지급 시: 지급 금액 반환 + point_balance/원장(Point) 반영
    """
    g = int(grade or 0)
    amount = int(GRADE_REWARD_BY_GRADE.get(g, 0) or 0)
    # 0(아마추어)부터 보상 지급 대상. 음수 등급은 보상 없음.
    if g < 0 or amount <= 0:
        return 0

    reason = f"user_grade_reward_{g}"
    already = db.query(Point.id).filter(Point.user_id == user.id, Point.reason == reason).first() is not None
    if already:
        return 0

    user.point_balance = int(getattr(user, "point_balance", 0) or 0) + amount
    db.add(Point(user_id=user.id, reason=reason, amount=amount))
    return amount


def _apply_user_grade_upgrade(db: Session, user: Community_User, referral_count: int) -> bool:
    """
    추천인 수 기반 user_grade 동기화 + 달성 보너스 지급(원장/잔액 반영).
    - 등급은 referral_count 기준으로 항상 동기화(다운그레이드 포함)
    - 보상은 등급이 올라갈 때만(중간 등급 포함) 1회성으로 지급
    Returns: 변경 여부(등급이 실제로 변경됐는지)
    """
    target = _grade_from_referral_count(referral_count)
    current = int(getattr(user, "user_grade", -1) or -1)
    if target == current:
        return False

    # 등급이 올라가는 경우에만(예: -1 -> 0, 1 -> 3) 중간 등급 보너스도 누락 없이 지급
    if target > current:
        for g in range(current + 1, target + 1):
            _grant_user_grade_reward_if_needed(db, user, g)

    user.user_grade = target
    db.add(user)
    return True


def _rollover_recruit_card_types(db: Session) -> None:
    """
    구인글(post_type=1) 카드 타입을 개수 제한에 맞춰 롤오버합니다.
    - card_type=1 -> 2 (30개 초과분을 오래된 순으로)
    - card_type=2 -> 1 (card_type=1이 30개 미만이면, 가장 최신 2유형을 1유형으로 승격)
    같은 트랜잭션 안에서 호출되어야 합니다.
    """
    # 1유형: 30개 유지
    while True:
        c1 = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 1,
            )
            .scalar()
            or 0
        )
        if c1 <= CARD1_MAX:
            break

        oldest1 = (
            db.query(Community_Post)
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 1,
            )
            .order_by(Community_Post.created_at.asc(), Community_Post.id.asc())
            # Community_Post.author 가 lazy="joined"라 LEFT OUTER JOIN이 붙음.
            # PostgreSQL은 OUTER JOIN의 nullable side에 FOR UPDATE를 적용할 수 없어 500이 남.
            # 롤오버는 Post row만 잠그면 되므로 eager load를 끄고 row lock만 수행.
            .enable_eagerloads(False)
            .with_for_update()
            .first()
        )
        if not oldest1:
            break
        oldest1.card_type = 2
        db.add(oldest1)

    # 1유형: 30개 미만이면 2유형에서 승격하여 채움
    # - 삭제/수정 등으로 1유형이 줄어든 경우에도 30개를 유지하기 위함
    while True:
        c1 = (
            db.query(func.count(Community_Post.id))
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 1,
            )
            .scalar()
            or 0
        )
        if c1 >= CARD1_MAX:
            break

        newest2 = (
            db.query(Community_Post)
            .filter(
                Community_Post.post_type == 1,
                Community_Post.status == "published",
                Community_Post.card_type == 2,
            )
            .order_by(Community_Post.created_at.desc(), Community_Post.id.desc())
            .enable_eagerloads(False)
            .with_for_update()
            .first()
        )
        if not newest2:
            break
        newest2.card_type = 1
        db.add(newest2)

    # 참고: card_type=2/3은 더 이상 개수 상한(강등/승격)을 강제하지 않습니다.


def _rollover_ad_card_types(db: Session) -> None:
    """
    광고글(post_type=4): 카테고리(job_industry)별로 card_type=1을 최대 5개만 유지합니다.
    - 초과분(오래된 순)은 card_type=2로 강등
    같은 트랜잭션 안에서 호출되어야 합니다.
    """
    for cat in AD_CATEGORIES:
        # 기존 레거시 데이터(카테고리 누락)는 '광고'로 취급(프론트 list4.tsx의 기본 매핑과 동일)
        if cat == AD_PRIMARY_CATEGORY:
            cat_filter = or_(
                Community_Post.job_industry.in_(_ad_category_db_values(AD_PRIMARY_CATEGORY)),
                Community_Post.job_industry.is_(None),
                Community_Post.job_industry == "",
            )
        else:
            cat_filter = Community_Post.job_industry.in_(_ad_category_db_values(cat))

        while True:
            c1 = (
                db.query(func.count(Community_Post.id))
                .filter(
                    Community_Post.post_type == 4,
                    Community_Post.status == "published",
                    cat_filter,
                    Community_Post.card_type == 1,
                )
                .scalar()
                or 0
            )
            if c1 <= AD_CARD1_MAX:
                break

            oldest1 = (
                db.query(Community_Post)
                .filter(
                    Community_Post.post_type == 4,
                    Community_Post.status == "published",
                    cat_filter,
                    Community_Post.card_type == 1,
                )
                .order_by(Community_Post.created_at.asc(), Community_Post.id.asc())
                .enable_eagerloads(False)
                .with_for_update()
                .first()
            )
            if not oldest1:
                break
            oldest1.card_type = 2
            db.add(oldest1)

