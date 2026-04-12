## 프로젝트 개요
과제 A — 수강 신청 시스템
라이브클래스 채용팀으로부터 받은 테스트 과제입니다.


## 기술 스택
front : React Native(app)
client : Axio Fetch
server : fastAPI
DB : postgreSQL
Hosting : Railway


## 실행 방법
Google PlayStore에서 '스마트파킹-청북세종헤르메스 주차관리'앱을 검색하고 설치합니다.

ID : 라이브클래스
PASSWORD : 123

해당 테스트 계정으로 로그인합니다.

홈 화면에서 조홍래 지원자 백엔드 과제 항목을 클릭해서 들어갑니다.

역할설정을 통해 크리에이터/수강생 의 역할을 변경해가면서 결과물을 테스트합니다.


## API 목록 및 예시
GET /jhr/role
사용자 역할(수강생/크리에이터) 조회

PUT /jhr/role
사용자 역할(수강생/크리에이터) 변경

POST /jhr/classes
클래스 생성

GET /jhr/classes
클래스 목록 조회

GET /jhr/classes/{class_id}
클래스 상세 조회

PUT /jhr/classes/{class_id}
클래스 상세 수정

PUT /jhr/class-status/change
클래스 상태 변경
초안 -> 모집 중 -> 모집 마감 순으로 상태 전이 

POST /jhr/enrollments
수강 신청 생성
상태는 결제 대기

PUT /jhr/enrollments/confirm
수강 신청 수정
대기 -> 결제 확정 상태 전이

PUT /jhr/enrollments/cancel
수강 신청 수정
결제 확정 -> 결제 취소 상태 전이

GET /jhr/enrollments/me
내 수강 신청 목록 확인

GET /jhr/classes/{class_id}/students
강의 수강 신청 학생 목록 확인


## 데이터 모델 설명

1. jhr_classes
강의 정보를 담고 있는 테이블입니다.
| 필드명 | 데이터 타입 | 제약 사항 | 비고 |
| :--- | :--- | :--- | :--- |
| **id** | `bigint` | **PRIMARY KEY**, Auto Inc. | 고유 식별자 |
| **title** | `varchar(255)` | **NOT NULL** | 강의 제목 |
| **description** | `text` | - | 강의 상세 설명 |
| **price** | `numeric(10,2)` | **NOT NULL**, Default: `0` | 수강료 |
| **capacity** | `integer` | **NOT NULL**, **CHECK (>=0)** | 최대 수강 인원 |
| **current_count** | `integer` | **NOT NULL**, **CHECK (>=0)** | 현재 신청 인원 |
| **start_date** | `timestamp` | **NOT NULL** | 강의 시작 일시 |
| **end_date** | `timestamp` | **NOT NULL** | 강의 종료 일시 |
| **status** | `varchar(10)` | **NOT NULL**, **CHECK** | `DRAFT`, `OPEN`, `CLOSED` |
| **creator_user_id** | `bigint` | **NOT NULL** | 등록자 식별 ID |
| **created_at** | `timestamp` | **DEFAULT: now()** | 레코드 생성 일시 |
| **updated_at** | `timestamp` | **DEFAULT: now()** | 레코드 수정 일시 |




## 요구사항 해석 및 가정
## 설계 결정과 이유
## 테스트 실행 방법
## 미구현 / 제약사항
## AI 활용 범위