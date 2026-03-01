-- 목적: "내 아래로 추천인 인맥 100명 달성 보상" 1회성 지급의 멱등성 강화
-- 대상: public.point 테이블
--
-- 주의:
-- - 본 프로젝트는 포인트 원장(point.reason)이 다양한 이벤트에서 반복 발생(예: attendance_daily)할 수 있어
--   (user_id, reason) 전체 유니크는 위험합니다.
-- - 따라서 특정 reason("referral_network_100")에 대해서만 부분 유니크 인덱스를 권장합니다.
--
-- 운영 적용 시 참고:
-- - CONCURRENTLY는 트랜잭션 블록 안에서 실행할 수 없습니다.
-- - 트래픽이 낮은 시간대에 실행 권장.

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ux_point_referral_network_100_per_user
ON public.point (user_id)
WHERE reason = 'referral_network_100';

