from __future__ import annotations

import re

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import Community_User


def generate_referral_code(db: Session, phone_number: str) -> str:
    """
    phone_number 기반으로 referral_code를 생성합니다.
    규칙: phone_number의 마지막 4자리 + 숫자(0~9) 1자리
    """
    # 1. phone_number에서 숫자만 추출
    digits_only = re.sub(r"[^0-9]", "", phone_number)

    # 2. 길이 확인
    if len(digits_only) < 4:
        raise HTTPException(
            status_code=400,
            detail=f"phone_number must contain at least 4 digits (got: {len(digits_only)})",
        )

    # 3. 마지막 4자리 추출
    last4 = digits_only[-4:]

    # 4. 이미 사용 중인 referral_code 조회 (last4로 시작하는 것들)
    existing_codes = (
        db.query(Community_User.referral_code)
        .filter(Community_User.referral_code.like(f"{last4}%"), Community_User.referral_code.isnot(None))
        .all()
    )
    used_suffixes = {code[0][-1] for code in existing_codes if code[0] and len(code[0]) == 5}

    # 5. 사용 가능한 suffix 찾기 (0~9 중)
    available_suffixes = [str(d) for d in range(10) if str(d) not in used_suffixes]

    if not available_suffixes:
        # 모든 코드가 사용 중
        masked_phone = phone_number[:3] + "****" + phone_number[-2:] if len(phone_number) > 5 else "****"
        print(f"[ERROR] referral_code 생성 실패: last4={last4}, phone={masked_phone}, 모든 코드 소진")
        raise HTTPException(
            status_code=409,
            detail="referral_code 생성 불가: 해당 전화번호 마지막 4자리로 생성 가능한 코드가 모두 사용 중입니다",
        )

    # 6. 첫 번째 사용 가능한 suffix로 코드 생성
    selected_suffix = available_suffixes[0]
    return last4 + selected_suffix


def assign_referral_code(db: Session, user: Community_User, phone_number: str) -> None:
    """
    유저에게 referral_code를 할당합니다.
    중복 발생 시 다른 suffix로 재시도합니다.
    """
    digits_only = re.sub(r"[^0-9]", "", phone_number)
    if len(digits_only) < 4:
        raise HTTPException(status_code=400, detail="phone_number must contain at least 4 digits")

    last4 = digits_only[-4:]

    # 최대 10번 시도
    max_attempts = 10
    for attempt in range(max_attempts):
        try:
            # generate_referral_code가 최신 상태를 반영하므로 재호출
            referral_code = generate_referral_code(db, phone_number)
            user.referral_code = referral_code
            db.flush()  # DB에 반영 (아직 commit은 안 함)
            return
        except HTTPException:
            db.rollback()
            raise
        except IntegrityError:
            # 동시성 문제로 인한 중복 발생 시 rollback 후 재시도
            db.rollback()
            if attempt == max_attempts - 1:
                masked_phone = phone_number[:3] + "****" + phone_number[-2:] if len(phone_number) > 5 else "****"
                print(f"[ERROR] referral_code 할당 실패 (최대 시도 횟수 초과): last4={last4}, phone={masked_phone}")
                raise HTTPException(
                    status_code=409,
                    detail="referral_code 생성 불가: 코드 생성에 실패했습니다 (동시성 충돌 또는 코드 소진)",
                )
            continue
        except Exception as e:
            db.rollback()
            masked_phone = phone_number[:3] + "****" + phone_number[-2:] if len(phone_number) > 5 else "****"
            print(f"[ERROR] referral_code 할당 중 예상치 못한 오류: last4={last4}, phone={masked_phone}, error={e}")
            raise HTTPException(status_code=500, detail="referral_code 생성 중 오류가 발생했습니다")

