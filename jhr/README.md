## 프로젝트 개요  

라이브클래스 채용팀으로부터 받은 백엔드 테스트 과제입니다.  

선택 : 과제 A — 수강 신청 시스템  
  
FRONT : https://github.com/louis2487/smartparking/tree/master/app/jhr  

BACKEND : https://github.com/louis2487/myapi/tree/main/jhr (현재 경로)  
  

## 기술 스택  

front : React Native(app)  

client : Axio Fetch  

server : FastAPI  

DB : PostgreSQL  

Hosting : Railway  



## 실행 방법  

Google PlayStore에서 '스마트파킹-청북세종헤르메스 주차관리'앱을 검색하고 설치합니다.  

ID : 라이브클래스  

PASSWORD : 123    

해당 테스트 계정으로 로그인합니다.  

홈 화면에서 조홍래 지원자 백엔드 과제 항목을 클릭해서 들어갑니다.  

역할 설정 메뉴를 통해 크리에이터/수강생 의 역할을 변경해가면서 결과물을 테스트합니다.  
  

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

### 1. jhr_classes 
> 클래스 테이블로 제목, 상세, 가격, 신청 인원, 정원, 시작일, 종료일 등의 정보를 저장합니다. 

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

  
    
### 2. jhr_enrollments 
> 수강 신청 테이블로 유저와 클래스에 대한 상태, 신청일, 결제일, 취소일을 저장합니다.

| 필드명 | 데이터 타입 | 제약 사항 | 비고 |
| :--- | :--- | :--- | :--- |
| **id** | `integer` | **PRIMARY KEY**, Auto Inc. | 신청 고유 식별자 |
| **user_id** | `bigint` | **NOT NULL** | 신청자(사용자) ID |
| **class_id** | `integer` | **NOT NULL** | 신청한 강의 ID |
| **status** | `varchar(20)` | **NOT NULL**, Default: `'PENDING'` |
| **applied_at** | `timestamp` | Default: `now()` (KST) | 수강 신청 일시 |
| **confirmed_at** | `timestamp` | - | 수강 확정 일시 |
| **canceled_at** | `timestamp` | - | 수강 취소 일시 |

  
  
### 3. parking_users  
> 서비스 유저 테이블로 테스터 계정의 역할을 저장합니다.  

| 필드명 | 데이터 타입 | 제약 사항 | 비고 |
| :--- | :--- | :--- | :--- |
| **id** | `bigint` | **PRIMARY KEY**, Auto Inc. | 사용자 고유 식별자 |
| **username** | `varchar(30)` | **NOT NULL** | 사용자 계정명 |
| **password_hash** | `text` | **NOT NULL** | 암호화된 비밀번호 |
| **signup_date** | `timestamp` | **NOT NULL**, Default: `now()` | 가입 일시 |
| **floor** | `varchar(20)` | - | 주차 층 정보 |
| **grade** | `varchar(10)` | **NOT NULL**, Default: `'normal'` | 사용자 등급 |
| **pillar_number** | `varchar(20)` | - | 기둥 번호 |
| **action_date** | `timestamp` | Default: `now()` | 최근 활동 일시 |
| **role** | `varchar(20)` | **NOT NULL**, Default: `'STUDENT'` | 사용자 권한 |

  
  
## 요구사항 해석 및 가정  

정원 체크 : PENDING 신청은 현재 수강인원이 정원 미만일 때에 가능하지만, 수강인원의 카운팅 처리는 CONFIRMED에서 일어나야 하며,  
CANCELLED로 변경 시에 다시 현재 수강인원이 감소.  

수강 신청 : 클래스의 상태가 DRAFT이거나 CLOSE일 때, 또는 OPEN임에도 현재 수강인원이 정원에 도달한 경우는 수강 신청이 불가능.   

동시성 제어 : 마지막 1자리가 남은 경우, 여러명이 PENDING 상태에서, 동시에 CONFIRMED 결제 신청을 한 경우,  
비관적 락(FOR UPDATE)를 사용하여, DB를 LOCK -> 먼저 온 트랜잭션 진행 -> DB UNLOCK -> 후 트랜잭션 진행의 로직으로 구현.    

수강 취소 : 결제일(CONFIRMED)을 기준으로 현재일이 7일 이내인가에 따라 CANCELLED 진행.    

강의별 수강생 목록 조회 : jhr_enrollments 테이블에서 class_id에 해당하는 user_id 쿼리 조회, username으로 목록 리스트 출력.    

목록 페이지네이션 : GET /jhr/classes 클래스 목록 조회 시에, 한 페이지에 3개씩 가지고오도록 처리.    
  
  
## 설계 결정과 이유  

포트폴리오에 적힌 풀스택 개발 역량을 보여주는 가장 좋은 방법은, 실제 운영 중인 자사 상용 앱 화면에서 구현된 백엔드 로직을 테스트 가능하게  

만드는 것이라 생각했습니다.  

수강생과 크리에이터라는 역할을 손쉽게 오가며, 강의 개설, 상태 전이, 수강생 조회, 강의 신청, 결제, 취소 기능을 자연스럽게 체험할 수 있게 하는 것을  

가장 중점적인 우선 순위로 두었습니다. 

테스터의 역할 선택을 저장하기 위해, 서비스 중인 기존 유저 테이블을 확장해서 재사용했으며, 강의 정보와 상태를 저장하는 테이블을 만들고, 

class_id와 user_id를 FK키로 참조하는 수강 신청 테이블을 통해, 강의 신청, 결제, 취소 상태 전이를 기능하게 하였습니다.    

  
## 테스트 실행 방법  

FastAPI에서 자동 생성되는 Swagger UI를 통해 실시간 원격 테스트 환경을 제공합니다.  

Swagger UI 주소 : https://api.smartgauge.co.kr/docs#/  

테스트 범위   
API 목록 및 예시 참조  
/JHR/.. 상기 형태의 RESTful API   
  
테스터 파라미터  
username : 라이브클래스  
password : 123  
  
테스트 방법  
  1. 위 링크 접속 후 원하는 API 엔드포인트 클릭  
  2. **Try it out** 버튼 클릭 후 데이터 입력  
  3. **Execute** 버튼을 눌러 실시간 서버 응답(JSON) 확인  

  

## 미구현 / 제약사항  

Spring Boot (Java 또는 Kotlin) 대신 FastAPI(python)을 사용한 것은 제한된 시간이내에 가장 완성도 높은 산출물을 만들어낼 수 있는 익숙한 기술 스택이면서, 이미 

출시 된 상용 앱 내에서의 테스트 환경 구축을 위한 선택이었습니다.  

  
  
## AI 활용 범위  

CURSOR AI Agent를 사용하여 프론트 및 백엔드 코드 구현    

  