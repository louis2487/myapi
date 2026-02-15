from pydantic import BaseModel


class KakaoDrivingInfoOut(BaseModel):
    distance_meters: int
    duration_seconds: int


class RuntimePayload(BaseModel):
    user_id: str
    runtime_seconds: int


class RuntimeUpdateIn(RuntimePayload):
    """
    주기 업데이트:
    - runtime_seconds 누적(/runtime/update 기존 기능)
    - (선택) 운행일지(recode)의 도착지/거리/운행시간을 실시간 반영
    """

    recode_id: int | None = None
    end_location: str | None = None
    trip_km: float | None = None
    duration_seconds: int | None = None
    offtime: str | None = None


class RecodeCreate(BaseModel):
    username: str
    date: str
    ontime: str
    offtime: str
    duration: int
    # 스펙 확장(선택): GPS/사용자 입력
    start_location: str | None = None
    end_location: str | None = None
    trip_km: float | None = None
    trip_purpose: str | None = None
    business_use: bool = False
    # 선택: 서버에서 username -> user_id 매핑용 (신규 클라이언트)
    user_id: int | None = None


class RecodeOut(BaseModel):
    id: int | None = None
    username: str | None = None
    user_id: int | None = None
    date: str
    ontime: str
    offtime: str
    duration: int
    duration_minutes: int | None = None
    start_location: str | None = None
    end_location: str | None = None
    trip_km: float | None = None
    trip_purpose: str | None = None
    business_use: bool = False

    class Config:
        orm_mode = True


class RecodeListOut(BaseModel):
    recodes: list[RecodeOut]


class RecodeStartIn(BaseModel):
    """
    시동 ON 시작 기록 생성.

    인증/식별:
    - (권장) Authorization: Bearer <JWT(sub=users.id)>
    - (하위호환) username 필드

    위치/거리:
    - 서버는 좌표를 저장하지 않고, 시/군/구만 `start_location`에 저장합니다.
    """

    username: str | None = None
    date: str | None = None  # YYYY-MM-DD (없으면 오늘)
    ontime: str | None = None  # HH:MM[:SS] (없으면 현재)
    start_lat: float
    start_lng: float


class RecodeStartOut(BaseModel):
    id: int
    date: str
    ontime: str
    start_location: str | None = None


class RecodeEndIn(BaseModel):
    """
    시동 OFF 종료 기록 확정.
    - 도착 시점 좌표로 `end_location`(시/군/구) 저장
    - 출발/도착 좌표로 카카오 길찾기 기반 `trip_km`(도로거리) 계산
    """

    username: str | None = None
    recode_id: int
    offtime: str | None = None  # HH:MM[:SS]
    duration_seconds: int | None = None
    start_lat: float | None = None
    start_lng: float | None = None
    end_lat: float
    end_lng: float


class RecodePatchIn(BaseModel):
    trip_purpose: str | None = None
    business_use: bool | None = None

