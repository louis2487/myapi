import requests

from settings import KAKAO_MOBILITY_API_KEY, KAKAO_REST_API_KEY


def _kakao_auth_header(api_key: str) -> dict:
    """
    Kakao REST/Mobility API 공통 인증 헤더.
    """
    k = (api_key or "").strip()
    if not k:
        return {}
    return {"Authorization": f"KakaoAK {k}"}


def kakao_coord2_sigungu(lat: float, lng: float) -> str | None:
    """
    좌표(위도/경도)를 시/군/구 문자열로 변환합니다.
    - 요구사항: 도/시군구 단위만 기록
    - 저장 형태: "{region_1depth_name} {region_2depth_name}" (예: "경기도 평택시")
    """
    if not KAKAO_REST_API_KEY:
        return None
    try:
        r = requests.get(
            "https://dapi.kakao.com/v2/local/geo/coord2regioncode.json",
            params={"x": lng, "y": lat},
            headers=_kakao_auth_header(KAKAO_REST_API_KEY),
            timeout=8,
        )
        r.raise_for_status()
        data = r.json() or {}
        docs = data.get("documents") or []
        if not docs:
            return None
        # 우선순위: 행정동(H) -> 법정동(B) -> 첫번째
        pick = None
        for d in docs:
            if d.get("region_type") == "H":
                pick = d
                break
        if pick is None:
            for d in docs:
                if d.get("region_type") == "B":
                    pick = d
                    break
        if pick is None:
            pick = docs[0]
        r1 = (pick.get("region_1depth_name") or "").strip()
        r2 = (pick.get("region_2depth_name") or "").strip()
        sigungu = " ".join([x for x in [r1, r2] if x])
        return sigungu or None
    except Exception as e:
        print(f"[WARN] kakao coord2regioncode failed: {e}")
        return None


def kakao_route_distance_km(
    start_lat: float, start_lng: float, end_lat: float, end_lng: float
) -> float | None:
    """
    출발/도착 좌표 사이 도로거리(km)를 카카오 모빌리티 길찾기 API로 계산합니다.
    - 성공 시 km(float) 반환 (소수 2자리 반올림)
    """
    if not KAKAO_MOBILITY_API_KEY:
        return None
    try:
        r = requests.get(
            "https://apis-navi.kakaomobility.com/v1/directions",
            params={
                "origin": f"{start_lng},{start_lat}",
                "destination": f"{end_lng},{end_lat}",
                "priority": "RECOMMEND",
            },
            headers=_kakao_auth_header(KAKAO_MOBILITY_API_KEY),
            timeout=10,
        )
        r.raise_for_status()
        data = r.json() or {}
        routes = data.get("routes") or []
        if not routes:
            return None
        summary = (routes[0] or {}).get("summary") or {}
        dist_m = summary.get("distance")
        if dist_m is None:
            return None
        km = float(dist_m) / 1000.0
        return round(km, 2)
    except Exception as e:
        print(f"[WARN] kakao directions distance failed: {e}")
        return None


def kakao_driving_info(start_lat: float, start_lng: float, end_lat: float, end_lng: float) -> dict:
    """
    Kakao Mobility 길찾기 API를 대신 호출해 distance/duration을 반환합니다.
    """
    if not KAKAO_MOBILITY_API_KEY:
        raise RuntimeError("Kakao API key is not configured")

    r = requests.get(
        "https://apis-navi.kakaomobility.com/v1/directions",
        params={
            "origin": f"{start_lng},{start_lat}",
            "destination": f"{end_lng},{end_lat}",
            "priority": "RECOMMEND",
            "summary": "true",
        },
        headers=_kakao_auth_header(KAKAO_MOBILITY_API_KEY),
        timeout=10,
    )
    r.raise_for_status()
    data = r.json() or {}
    routes = data.get("routes") or []
    if not routes:
        raise RuntimeError("Kakao directions returned empty routes")

    summary = (routes[0] or {}).get("summary") or {}
    dist_m = summary.get("distance")
    dur_s = summary.get("duration")
    if dist_m is None or dur_s is None:
        raise RuntimeError("Kakao directions returned invalid summary")

    return {
        "distance_meters": int(dist_m),
        "duration_seconds": int(dur_s),
    }

