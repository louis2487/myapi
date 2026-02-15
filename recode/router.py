import calendar
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import func, or_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from database import SessionLocal
from models import RangeSummaryOut, Recode, RuntimeRecord, User
from settings import KAKAO_MOBILITY_API_KEY

from .auth import get_current_user, try_get_current_user
from .kakao import kakao_coord2_sigungu, kakao_driving_info, kakao_route_distance_km
from .schemas import (
    KakaoDrivingInfoOut,
    RecodeCreate,
    RecodeEndIn,
    RecodeListOut,
    RecodeOut,
    RecodePatchIn,
    RecodeStartIn,
    RecodeStartOut,
    RuntimePayload,
    RuntimeUpdateIn,
)

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def current_user(
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> User:
    return get_current_user(db, authorization)


@router.get("/kakao/driving-info", response_model=KakaoDrivingInfoOut)
def kakao_driving_info_endpoint(
    start_lat: float = Query(..., description="출발 위도"),
    start_lng: float = Query(..., description="출발 경도"),
    end_lat: float = Query(..., description="도착 위도"),
    end_lng: float = Query(..., description="도착 경도"),
):
    """
    안드로이드 앱에서 카카오 API 키를 들고 있지 않도록,
    서버가 Kakao Mobility 길찾기 API를 대신 호출해 distance/duration을 내려줍니다.
    """
    if not KAKAO_MOBILITY_API_KEY:
        raise HTTPException(status_code=503, detail="Kakao API key is not configured")
    try:
        return kakao_driving_info(start_lat, start_lng, end_lat, end_lng)
    except Exception as e:
        raise HTTPException(
            status_code=502, detail=f"Kakao directions request failed: {e}"
        )


@router.post("/runtime/update")
def update_runtime(payload: RuntimeUpdateIn, db: Session = Depends(get_db)):
    stmt = (
        insert(RuntimeRecord)
        .values(user_id=payload.user_id, runtime_seconds=payload.runtime_seconds)
        .on_conflict_do_update(
            index_elements=["user_id"],
            set_={"runtime_seconds": RuntimeRecord.runtime_seconds + payload.runtime_seconds},
        )
    )
    try:
        db.execute(stmt)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="데이터베이스 업데이트 실패") from e

    total = (
        db.query(RuntimeRecord.runtime_seconds)
        .filter(RuntimeRecord.user_id == payload.user_id)
        .scalar()
    )

    recode_updated = False
    # ✅ recode 진행상황(도착지/거리/운행시간) 반영
    if payload.recode_id is not None:
        try:
            r = (
                db.query(Recode)
                .filter(Recode.id == payload.recode_id, Recode.username == payload.user_id)
                .first()
            )
            if r:
                end_loc = (payload.end_location or "").strip()
                if end_loc:
                    r.end_location = end_loc
                if payload.trip_km is not None:
                    try:
                        r.trip_km = float(payload.trip_km)
                    except Exception:
                        pass
                if payload.duration_seconds is not None:
                    try:
                        r.duration = max(int(payload.duration_seconds), 0)
                        r.duration_minutes = int(r.duration) // 60
                    except Exception:
                        pass
                off = (payload.offtime or "").strip()
                if off:
                    r.offtime = off

                # 출발지가 비어있으면 도착지를 출발지로 보정
                if (not (r.start_location or "").strip()) and (r.end_location or "").strip():
                    r.start_location = r.end_location

                db.add(r)
                db.commit()
                recode_updated = True
        except Exception:
            db.rollback()

    return {
        "status": "ok",
        "user_id": payload.user_id,
        "total_runtime": total,
        "recode_updated": recode_updated,
    }


@router.get("/runtime/{user_id}", response_model=RuntimePayload)
def read_runtime(user_id: str, db: Session = Depends(get_db)):
    record = db.query(RuntimeRecord).filter(RuntimeRecord.user_id == user_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="런타임 기록을 찾을 수 없습니다.")
    return record


@router.get("/recode/{username}/{date}", response_model=RecodeListOut)
def get_recode(username: str, date: str, db: Session = Depends(get_db)):
    # 하위호환: 기존 데이터(username 기반) + 신규 데이터(user_id 기반) 모두 조회
    user = db.query(User).filter(User.username == username).first()
    conds = [Recode.username == username]
    if user:
        conds.append(Recode.user_id == user.id)
    q = db.query(Recode).filter(or_(*conds))

    # date 파라미터 지원:
    # - YYYY-MM-DD: 해당 날짜(일간)
    # - YYYY-MM: 해당 월 전체(월간)
    if len(date) == 10 and date[4] == "-" and date[7] == "-":
        q = q.filter(Recode.date == date)
    elif len(date) == 7 and date[4] == "-":
        try:
            y = int(date[0:4])
            m = int(date[5:7])
            last_day = calendar.monthrange(y, m)[1]
            start = f"{y:04d}-{m:02d}-01"
            end = f"{y:04d}-{m:02d}-{last_day:02d}"
            q = q.filter(Recode.date >= start, Recode.date <= end)
        except Exception:
            # 파싱 실패 시 하위호환(정확 일치)
            q = q.filter(Recode.date == date)
    else:
        # 예상 외 포맷은 하위호환(정확 일치)
        q = q.filter(Recode.date == date)

    recodes = q.all()
    return {"recodes": recodes}


@router.post("/recode/add")
def add_recode(recode: RecodeCreate, db: Session = Depends(get_db)):
    # 신규 스펙: 가능하면 user_id를 채워서 저장(기존 클라이언트는 username만 보냄)
    uid = recode.user_id
    if uid is None and recode.username:
        u = db.query(User).filter(User.username == recode.username).first()
        uid = u.id if u else None

    duration_minutes = None
    try:
        # 기존 클라이언트 duration은 초 단위로 들어오므로 분 컬럼도 함께 채움(바닥 나눗셈)
        duration_minutes = int(recode.duration) // 60 if recode.duration is not None else None
    except Exception:
        duration_minutes = None

    # ✅ 출발지가 비어있으면 도착지를 출발지로 보정(클라이언트/지오코딩 실패 대비)
    start_loc = (recode.start_location or "").strip()
    end_loc = (recode.end_location or "").strip()
    if (not start_loc) and end_loc:
        start_loc = end_loc

    new_r = Recode(
        username=recode.username,
        user_id=uid,
        date=recode.date,
        ontime=recode.ontime,
        offtime=recode.offtime,
        duration=recode.duration,
        duration_minutes=duration_minutes,
        start_location=start_loc or None,
        end_location=end_loc or None,
        trip_km=recode.trip_km,
        trip_purpose=recode.trip_purpose,
        business_use=bool(recode.business_use),
    )
    db.add(new_r)
    db.commit()
    db.refresh(new_r)
    return {"status": "success", "id": new_r.id}


@router.get("/recode/summary/{username}/{start}/{end}", response_model=RangeSummaryOut)
def recode_summary(username: str, start: str, end: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    conds = [Recode.username == username]
    if user:
        conds.append(Recode.user_id == user.id)
    cnt, total = (
        db.query(func.count(Recode.id), func.coalesce(func.sum(Recode.duration), 0))
        .filter(or_(*conds), Recode.date >= start, Recode.date <= end)
        .one()
    )
    return RangeSummaryOut(
        username=username,
        start=start,
        end=end,
        on_count=int(cnt),
        runtime_seconds=int(total or 0),
    )


@router.post("/recode/start", response_model=RecodeStartOut)
def recode_start(
    payload: RecodeStartIn,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    now = datetime.now()
    date_str = payload.date or now.strftime("%Y-%m-%d")
    on_str = payload.ontime or now.strftime("%H:%M:%S")

    user = try_get_current_user(db, authorization)
    username = user.username if user else (payload.username or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="username or Authorization required")

    uid = user.id if user else None
    if uid is None:
        u = db.query(User).filter(User.username == username).first()
        uid = u.id if u else None

    start_loc = kakao_coord2_sigungu(payload.start_lat, payload.start_lng)
    r = Recode(
        user_id=uid,
        username=username,  # legacy 병행
        date=date_str,
        ontime=on_str,
        offtime="",
        duration=0,
        duration_minutes=0,
        start_location=start_loc,
        end_location=None,
        trip_km=None,
        trip_purpose=None,
        business_use=False,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return RecodeStartOut(
        id=r.id, date=r.date, ontime=r.ontime, start_location=r.start_location
    )


@router.post("/recode/end", response_model=RecodeOut)
def recode_end(
    payload: RecodeEndIn,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    user = try_get_current_user(db, authorization)
    username = user.username if user else (payload.username or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="username or Authorization required")

    q = db.query(Recode).filter(Recode.id == payload.recode_id)
    if user:
        q = q.filter(or_(Recode.user_id == user.id, Recode.username == user.username))
    else:
        q = q.filter(Recode.username == username)
    r = q.first()
    if not r:
        raise HTTPException(status_code=404, detail="recode not found")

    now = datetime.now()
    off_str = payload.offtime or now.strftime("%H:%M:%S")
    r.offtime = off_str
    r.end_location = kakao_coord2_sigungu(payload.end_lat, payload.end_lng)

    # 도로거리 계산: 출발/도착 좌표가 모두 있는 경우에만 수행
    if payload.start_lat is not None and payload.start_lng is not None:
        r.trip_km = kakao_route_distance_km(
            payload.start_lat, payload.start_lng, payload.end_lat, payload.end_lng
        )

    # duration: 클라이언트가 주면 그대로 사용, 아니면 문자열로 계산(가능할 때만)
    if payload.duration_seconds is not None:
        try:
            r.duration = max(int(payload.duration_seconds), 0)
            r.duration_minutes = int(r.duration) // 60
        except Exception:
            pass
    else:
        # HH:MM[:SS] 파싱 지원
        try:
            def _parse_hms(s: str) -> int:
                parts = (s or "").split(":")
                if len(parts) == 2:
                    h, m = int(parts[0]), int(parts[1])
                    return h * 3600 + m * 60
                if len(parts) == 3:
                    h, m, sec = int(parts[0]), int(parts[1]), int(parts[2])
                    return h * 3600 + m * 60 + sec
                return 0

            start_sec = _parse_hms(r.ontime)
            end_sec = _parse_hms(off_str)
            dur_sec = end_sec - start_sec
            if dur_sec < 0:
                dur_sec = 0
            r.duration = int(dur_sec)
            r.duration_minutes = int(dur_sec) // 60
        except Exception:
            pass

    db.add(r)
    db.commit()
    db.refresh(r)
    return r


@router.patch("/recode/{recode_id}", response_model=RecodeOut)
def recode_patch(
    recode_id: int,
    payload: RecodePatchIn,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    r = db.query(Recode).filter(Recode.id == recode_id, Recode.user_id == user.id).first()
    if not r:
        raise HTTPException(status_code=404, detail="recode not found")
    if payload.trip_purpose is not None:
        r.trip_purpose = payload.trip_purpose
    if payload.business_use is not None:
        r.business_use = bool(payload.business_use)
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


@router.get("/recode", response_model=RecodeListOut)
def recode_list(
    date: str = Query(..., description="YYYY-MM-DD"),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    recodes = db.query(Recode).filter(Recode.user_id == user.id, Recode.date == date).all()
    return {"recodes": recodes}

