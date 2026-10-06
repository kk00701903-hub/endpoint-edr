# 종단 통합 테스트

실제 구성 요소를 모두 띄워 처음부터 끝까지 시험한다. GitHub Actions(`.github/workflows/ci.yml`)가 푸시·PR 마다 실행한다.

| 단계 | 파일 | 확인하는 것 |
|---|---|---|
| DB | `supabase/tests/rls_and_detection_test.sql` | RLS·조직 격리, 탐지 규칙, 인시던트 묶음, 늦게 도착한 무차별 대입, 유지보수 작업, 시스템 상태, 감사 기록 |
| 1 | `01-enroll.mjs` | 콘솔 로그인(실패 안내 포함), 로그인 후 원래 화면 복귀, 설정 화면에서 등록키 발급 |
| 2 | `02-agents.mjs` | 에이전트 3대 등록·전송(공격 시나리오), 자산 정보·보안 상태 기준선(NUL 제거·OS 수명 주기·잘못된 점검 결과·5000개 초과 거부), 재전송 중복 제거, 잘못된 입력·위조 토큰·압축 폭탄·과대 배치·요청 제한 거부, 시계 보정 |
| 탐지 | `run.sh` | enricher 를 pg_cron 대체 모드(`RUN_DETECTIONS=1`)로 띄워 탐지·파티션 작업 실행 |
| 3 | `03-console.mjs` | 악성 판정 → 즉시 경보, 인시던트 묶음·자동 요약·공격 그래프·엔터티·ATT&CK·헌팅, 조사 시작·메모·종결, 규칙 끄기, 시스템 상태, 감사 기록, 뷰어 권한, API 직접 호출 차단, 로그아웃 |
| 6 | `06-assets.mjs` | 자산·소프트웨어 화면(지원 종료·일련번호 검색·취약 소프트웨어)·CSV, 금지 소프트웨어 정책 → EDR-SW-001, 보안 기능 꺼짐 → EDR-POS-001(처음부터 실패는 경보 없음), 보안 상태 화면·점수 반영 끄기, 위협 지표 등록(잘못된 대역 안내·7일 소급 EDR-IOC-001/002·끄기·감사), 설치·업데이트 이력, 장치 상세 자산·보안 상태 탭, 현황 보안 위생 |
| 6-2 | `08-docscan.mjs` | 문서 감사: 기본 꺼짐, 직원 고지 확인 없이는 켤 수 없음, 에이전트 정책(`GET /v1/policy`)·"지금 검사" 요청 번호, 결과 배치 합산·요청 완료·잘못된 배치 거부, 개인정보·키워드·오래된 문서·검사 현황 화면, CSV, 분석가 차단, 조회·내려받기 감사 기록 |
| 6-3 | `09-remediation.mjs` | PC 조치 목록: 보안 점검 실패·금지 프로그램·개인정보 문서가 목록에 계산됨, 한 건·여러 건 처리(상태·담당자·기한), 내 담당, 분석가는 문서 항목 안 보임·열람자는 처리 불가, 고치면 목록에서 빠지고 "해결 확인됨", CSV, 감사 기록 |
| 6-4 | `10-notify.mjs` | 알림 연동: 콘솔에서 채널 추가(슬랙·심각도 하한), 경보 발생 → enricher 가 SINK 로 발송(MITRE 전술 포함)·낮은 심각도는 적재 안 됨, 테스트 발송, 분석가에겐 패널 안 보임, 수정·감사 기록 |
| 6-5 | `11-wazuh.mjs` | Wazuh 경보 수집: 웹훅 `POST /v1/wazuh` 잘못된 비밀 차단, level→심각도·호스트 매칭·중복 방지·배열 수신, 콘솔 경보 화면 출처=Wazuh 필터·배지 |
| 5 | `05-sso.mjs` | 회사 계정(SSO): 로그인 버튼 → Keycloak 흉내(같은 입력칸 id) → Supabase PKCE → AD 그룹으로 역할 결정, 관리자 OTP 등록·입력, 그룹 없음·잠긴 계정·틀린 비밀번호, 그룹 변경·제거 반영, 감사 기록 |
| 7 | `07-sso-switch.mjs` | SSO 실험 구성 스위치(`deploy/sso-lab/lab.mjs`): 가짜 docker 로 on/off/reset, 다른 줄·CRLF·사용자 비밀값 유지, docker 실패 시 설정 그대로 |
| 4 | `04-load.mjs` | PC 150대 동시 전송 — 모든 배치 수락, p95 3초 이내, 수집 서버 교착 0건 |

## 로컬에서 실행

**테스트 전용** PostgreSQL 16 이 필요하다(`edr_it` DB 를 지우고 다시 만들고, `edr_ingest`·`edr_enricher` 역할에 LOGIN 을 켠다). 운영 DB·Supabase 프로젝트에 절대 연결하지 말 것.

```bash
cd tests/integration && npm ci && npx playwright install chromium && cd ../..
# PostgreSQL 접속 정보는 PG* 환경 변수로
PGHOST=localhost PGPORT=5432 PGUSER=postgres POSTGREST_BIN=/path/to/postgrest bash tests/integration/run.sh
```

Docker 가 있으면 테스트 DB 는 이렇게 띄우면 된다.

```bash
docker run --rm -d --name edr-it-pg -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16
```

- 필요한 도구: psql, Go, Node 22, pnpm, [PostgREST 12](https://github.com/PostgREST/postgrest/releases)
- 실제 Supabase 대신 `fake-supabase.mjs`(로그인만 흉내, 나머지는 PostgREST)와 `supabase-stub.sql`(auth 스키마)을 쓴다. 콘솔 → PostgREST → RLS 경로는 실제와 같다.
- 로그는 실행 끝에 표시되는 폴더(`.../logs`)에 남는다. 포트 18080·3301·54321·3300 을 쓴다.

## 개인 PC SSO 실험실 확인
실제 테스트용 AD + Keycloak 으로 같은 흐름을 확인하는 스크립트는 `sso-lab-verify.mjs` (절차: `docs/SSO_LAB.md`).

## 실제 환경과 다른 점
- 에이전트는 Windows 에서만 동작하므로 데이터 형식(`contracts/ingest.schema.json`)대로 만든 흉내 프로그램으로 보낸다.
- VirusTotal 조회 결과는 enricher 가 저장하는 것과 같은 UPDATE 로 대신한다.
- Supabase Realtime(실시간 알림)은 시험하지 않는다.
- 05 단계의 Keycloak 은 `fake-supabase.mjs` 가 흉내 낸 로그인 화면이다. 실제 Keycloak·AD 연결은 `sso-lab-verify.mjs` 로 확인한다.
