# 작업 기록

## 2026-10-02 — 초기 설계·뼈대 생성 (Claude)

### 만든 것
- `docs/ARCHITECTURE.md` : 전체 아키텍처(Mermaid 흐름도), 충돌 제로 설계표, 탐지 규칙표, RLS 요약, 판매용 권장 구조·라이선스
- `docs/CURSOR_GUIDE.md` : Cursor Composer 단계별 셋업, Next.js 콘솔 생성 프롬프트, 템플릿
- `agent/` : Go Windows 서비스 — 프로세스/네트워크/이벤트로그/자동실행 수집기, 공유모드 해시, 저자원 모드, DPAPI 토큰, gzip 전송·디스크 스풀
- `services/` : ingest(장치 등록·수집 게이트웨이), enricher(VirusTotal·MalwareBazaar 해시 평판), Dockerfile
- `supabase/migrations/` : core(멀티테넌트·월 파티션) / rls / detection(탐지 10종·pg_cron·악성 해시 트리거)
- `supabase/tests/rls_and_detection_test.sql`
- `deploy/` : docker-compose(ingest·enricher·Caddy·Grafana), Grafana 데이터소스·대시보드·알림 규칙
- `contracts/ingest.schema.json`, `scripts/check-passive.sh`, `.cursor/rules/*.mdc`

### 검증한 것
- 에이전트: `GOOS=windows go build` / `go vet` 통과 (golang.org/x/sys v0.30.0 기준). 실제 Windows 실행은 아직 안 함 → 테스트 VM 에서 `edr-agent.exe console` 로 확인 필요.
- 서버: ingest·enricher 빌드·vet 통과. 로컬 PostgreSQL 16 + Supabase 흉내 스키마에서 등록 → gzip 수집 → 중복 제거 → 탐지 → 경보 E2E 확인.
- DB: RLS 테넌트 격리, 경보 내용 변조 차단, 텔레메트리 쓰기 차단, 파티션 직접 접근 차단, anon 차단 테스트 통과. Grafana 쿼리 12개를 grafana_reader 권한으로 실행 확인.

### 특이사항
- COPY FROM 은 RLS 가 켜진 테이블에 쓸 수 없어서 ingest 는 unnest 배열 다중행 INSERT 로 적재한다.
- `go.sum` 은 포함하지 않았다 → 처음에 `go mod tidy` 1회 필요(agent, services 각각).
- VirusTotal Public API 는 비상업 약관 → 판매 시 상용 라이선스 또는 고객 BYOK + 법무 검토.
- Grafana OSS 는 AGPLv3 → 고객용 화면은 Next.js 로, Grafana 는 내부 운영용으로 분리 권장.
- 커밋은 하지 않음(사용자가 Cursor 에서 직접).
- 원격 전송 도구가 `Makefile` 파일명 쓰기를 막아 `agent/build.mk` 로 저장함 (`make -f build.mk build`, 필요하면 이름 변경).

## 2026-10-02 — 용도 변경: 외부 판매 → 회사 내부 전용 (Claude)

### 바꾼 것 (문서·주석·설정 문구만, 코드 동작과 DB 구조는 그대로)
- `docs/ARCHITECTURE.md` §7 을 "사내 운영 권장 구조"로 교체: Grafana 중심 + Next.js 관리 콘솔, DB 위치(클라우드 vs 사내 셀프호스팅), 직원 PC 모니터링 개인정보 고지, VirusTotal 한도·약관, 사내 도입 순서
- 같은 문서의 고객/판매 표현 정리(§1 표·흐름도, §2 파일럿 문구, §5 tenant 설명, §6 GPO, §8)
- `docs/CURSOR_GUIDE.md` : "고객 콘솔" → "관리 콘솔", 단일 조직이면 조직 선택 UI 생략, 9단계 제목
- `.cursor/rules/00-project.mdc`, `30-web-nextjs.mdc` : 사내 전용 명시, 판매용 기능 만들지 않기
- `deploy/Caddyfile` : 사내망 인증서(사내 CA / tls internal) 옵션 주석 추가
- `deploy/.env.example`, `deploy/docker-compose.yml`, `services/internal/intel/intel.go`, 마이그레이션 2개, `README.md` : 주석·안내 문구

### 특이사항
- tenant(조직) 구조는 지우지 않았다. 회사 1개면 tenant 1개로 쓰면 되고, 계열사 분리가 필요해질 때 그대로 쓸 수 있다.
- 마이그레이션 파일은 주석만 바뀌었다(아직 어디에도 적용 전이라 수정해도 무방).

## 2026-10-02 — 개발 방식 변경: Cursor 개발 → Claude 개발, Cursor 는 커밋·빌드·푸시만 (Claude)

### 바꾼 것
- 추가 `CLAUDE.md` : 기존 `.cursor/rules` 4개(공통·에이전트·DB·콘솔 규칙)를 합쳐 Claude 개발 규칙으로 정리. 작업 후 검증·작업기록·커밋 메시지 제안 절차 추가
- 추가 `docs/DEV_GUIDE.md` : 역할 분담(Claude 개발 / Cursor 확인·빌드·커밋·푸시), Cursor 작업 순서, Supabase·Docker·에이전트 설치, Claude 요청 예시
- 추가 `scripts/build.ps1` : Cursor 터미널용 빌드(가드레일 검사 → 에이전트 amd64/arm64 → 서버 컴파일·vet, `-Tidy` 옵션). Windows PowerShell 한글 깨짐 방지를 위해 UTF-8 BOM 으로 저장
- 삭제 `docs/CURSOR_GUIDE.md`, `.cursor/rules/` (내용은 위 두 파일로 이전)
- 수정 `README.md`, `docs/ARCHITECTURE.md`(가이드 링크·디렉토리 표), `agent/build.mk`(머리 주석)

### 특이사항
- `build.ps1` 은 이 환경에 PowerShell 이 없어 실행 검증을 못 했다. 첫 실행 결과를 확인할 것(실패 시 출력 전체를 Claude 에게 전달).

## 2026-10-02 — 성능·UI/UX 보강: 관리 콘솔 구축 + 에이전트/DB 성능 (Claude)

### 바꾼 것
- 에이전트
  - `agent/internal/collector/process_windows.go` : 이미 아는 프로세스는 시작 시각만 확인, 경로·사용자·명령줄·해시는 새 프로세스에만 조회. 종료된 프로세스 목록 반환
  - 추가 `agent/internal/sysutil/health_windows.go` : 에이전트 자신의 CPU%·메모리·수집 소요 시간·최근 오류 집계
  - `agent/cmd/edr-agent/main.go` : 프로세스 종료 전송, 5분마다 상태 보고, 수집기별 소요 시간 측정
  - `agent/internal/transport/transport_windows.go` : 전송 대기(스풀) 통계
  - `agent/internal/model/types.go`, `services/internal/contract/types.go`, `contracts/ingest.schema.json` : `process_exits`, `health` 필드 추가
- 서버 `services/cmd/ingest/main.go` : 장치 상태 저장, `processes_current` 갱신(전체 교체/시작/종료)
- DB 추가 `supabase/migrations/20261002000004_console_and_performance.sql`
  - `devices.health`, `processes_current`, BRIN·복합 인덱스, `detection_rules`(MITRE ATT&CK 매핑, 켜기/끄기), 경보 판정 `resolution`, `alert_comments`, `alert_suppressions`(예외 → 자동 종결) + 트리거, 콘솔 집계 함수 5개(`console_overview`, `console_alert_trend`, `console_logon_failures`, `console_device_timeline`, `console_members`)
  - `supabase/tests/rls_and_detection_test.sql` 에 0004 테스트 추가
- 콘솔 추가 `apps/web/` (Next.js 16 + Tailwind v4): 현황, 경보(분할 작업대·키보드·일괄 처리·판정·메모·예외), 장치, 장치 상세(상태 6지표·타임라인·프로세스 트리·네트워크·자동실행), 위협 헌팅, 탐지 규칙, 설정(등록키), 로그인, 명령 팔레트, 실시간 알림, 밝은/어두운 테마, 모바일, 예시 데이터 모드(`EDR_DEMO=1`), Dockerfile
- 배포 `deploy/docker-compose.yml`·`Caddyfile`·`.env.example` : `console` 서비스와 `CONSOLE_DOMAIN`
- `scripts/build.ps1` : 콘솔 빌드 단계 추가
- 문서 `docs/ARCHITECTURE.md`(§7-1 화면 역할, §9 콘솔, §10 성능), `docs/DEV_GUIDE.md`(6단계 콘솔 실행), `CLAUDE.md`(콘솔 규칙), `README.md`

### 검증한 것
- 에이전트: Windows 대상 `go vet`·빌드(amd64/arm64) 통과, 가드레일 통과. 실제 Windows 실행은 미검증
- 서버: `go vet`·빌드 통과. ingest E2E — 전체 스냅샷·종료 반영·상태 보고가 DB 에 맞게 들어감
- DB: 새 DB 에 마이그레이션 4개 적용 후 테스트 전부 통과(규칙 끄기, 예외 자동 종결, 집계 함수 RLS 격리, 역할별 권한)
- 콘솔: `tsc`·`eslint`·`next build` 통과. 예시 데이터 모드로 9개 화면 스크린샷 확인(밝은·어두운·모바일), 경보 처리·메모·예외·규칙 토글·등록키·명령 팔레트 자동 조작 테스트 통과, 화면 오류 없음
- 콘솔 + 실제 DB: PostgREST 와 가짜 인증 서버로 Supabase 를 흉내 내 로그인→전 화면 조회→경보 처리→메모→등록키 RPC 까지 확인

### 특이사항
- 실시간 알림(Supabase Realtime)은 이 환경에 Realtime 서버가 없어 미검증 — 실제 Supabase 에서 확인 필요
- Windows 로컬 빌드는 일반 모드, Docker 이미지만 standalone(`NEXT_OUTPUT=standalone`) — pnpm 심볼릭 링크 권한 문제 회피
- 로그인 실패 후 이메일 칸이 지워지던 문제(React 19 폼 초기화)를 테스트 중 발견해 수정

## 2026-10-02 — 콘솔 재설계: 최신 EDR 공통 구조(인시던트 중심) + 다크 우선 (Claude)

사용자 선택: 최신 EDR 공통 패턴 종합, 기능 4종(인시던트+공격 그래프, ATT&CK 매트릭스, 엔터티 페이지, 쿼리 헌팅+자동 요약), 다크 우선.

### 바꾼 것
- DB 추가 `supabase/migrations/20261002000005_incidents_entities_hunting.sql` : `incidents`(+ 경보 자동 묶음 트리거 `edr_attach_alert`, 기존 미처리 경보 소급 묶음), `alerts.incident_id`, `incident_comments`, `saved_queries`, `console_close_incident`(포함 경보 일괄 종결), `console_entity`(IP·해시·계정 프로필), `console_attack_matrix`, RLS
- 테스트 `supabase/tests/rls_and_detection_test.sql` : 묶음 규칙(장치·공유 IP·dedup), 종결 연쇄, 엔터티, 매트릭스, 조직 간 격리
- 콘솔
  - 새 화면: `incidents`, `incidents/[id]`(자동 요약·공격 그래프·증거), `attack`(ATT&CK 매트릭스), `entities/[kind]/[value]`, `hunt`(쿼리 편집기로 교체), 현황 재구성
  - 새 모듈: `lib/hunt/query.ts`(쿼리 언어), `lib/incident-summary.ts`(규칙 기반 요약), `lib/attack-graph.ts`(그래프 빌더), `lib/attack-catalog.ts`(기법 45개·가시성)
  - 새 컴포넌트: `attack-graph-view`(확대/축소), `killchain`, `incident-triage`, `query-console`
  - 디자인: 다크 우선 토큰 + ATT&CK 빈도용 파랑 명도 단계(두 테마 검증), 그룹형 내비게이션, 명령 팔레트 엔터티 이동, 상태 문구 "조사 중"으로 통일
  - 데이터 계층: DataSource 에 인시던트·엔터티·매트릭스·쿼리 실행/저장 추가(Supabase·데모 양쪽), 예전 단순 검색 `hunt()` 제거
- 문서: ARCHITECTURE §9 전면 개정, DEV_GUIDE 6단계, CLAUDE.md 콘솔 규칙, README

### 검증한 것
- DB: 새 DB 에 마이그레이션 5개 적용, 테스트 16개 항목 통과
- 콘솔: tsc·eslint·next build 통과. 예시 데이터로 다크·밝은·모바일 캡처 확인, 인시던트 조사 시작·메모·그래프 노드·탭·엔터티 이동·종결 연쇄·헌팅 실행/저장·문법 오류 표시·ATT&CK 칸 이동·명령 팔레트·테마 전환 자동 테스트 통과
- 실제 DB 흉내(PostgREST + 가짜 인증): 17개 화면 조회, 쿼리 저장, 인시던트 조사·메모·종결 → DB 에서 경보까지 종결 확인

### 특이사항
- 테스트 중 발견: 텔레메트리 테이블에 devices 외래키가 없어 헌팅의 장치 이름 조건이 실패 → 장치 id 목록으로 바꿔 거는 방식으로 수정
- ATT&CK 매트릭스는 Windows 에서 자주 쓰이는 45개 기법만 보여 준다(전체 매트릭스 아님). "볼 수 없음" 9개는 수동형 설계상 의도된 공백

## 2026-10-02 콘솔 기본 화면을 밝은(흰 바탕) 테마로 변경

### 바꾼 것
- `apps/web/src/app/layout.tsx` : 테마 쿠키가 없으면 `light` 로 시작(이전엔 `dark`). 쿠키 `edr_theme=dark` 일 때만 어두운 화면
- `apps/web/src/app/(console)/layout.tsx` : 상단 테마 버튼에 넘기는 기본값을 `light` 로 맞춤

### 검증한 것
- tsc·eslint·next build 통과
- 예시 데이터로 쿠키 없이 접속 → `<html class="light">`, 흰 바탕 화면 캡처 확인. 테마 버튼으로 어두운 화면 전환 후 새로고침해도 유지됨

### 특이사항
- 색 토큰은 바꾸지 않았다. 밝은 테마의 패널은 흰색(#ffffff), 패널 사이 바깥 바탕은 아주 옅은 회색(#edf0f4), 왼쪽 메뉴는 기존대로 남색
- 이미 어두운 화면을 골라 둔 브라우저는 쿠키가 남아 있어 계속 어두운 화면으로 보인다(상단 테마 버튼으로 전환)

## 2026-10-02 통합 테스트 · 글로벌 제품 대비 수준 점검

### 바꾼 것
- 새 문서 `docs/QUALITY_REVIEW.md` : 통합 테스트 결과, 성능·접근성 측정, 발견한 문제 12건, 글로벌 SaaS(CRM·그룹웨어 기본기)·상용 EDR 대비 점수, 추가 과제 순서
- 코드 변경 없음(점검만)

### 검증한 것
- 에이전트 vet·Windows 빌드(amd64/arm64)·수동형 가드레일, 서버 vet·빌드, 새 DB 에 마이그레이션 5개 + 테스트 16항목 통과
- 종단 시험(콘솔 등록키 발급 → 에이전트 흉내 3대 → 실제 ingest·enricher → 탐지·인시던트 → 콘솔 조사·종결): 수집 16/16, 콘솔 41/44(실패 2건은 문제 G·H, 1건은 테스트 기대값 오류)
- 권한·조직 격리: 뷰어·API 직접 호출·다른 조직 URL 모두 차단 확인
- 텔레메트리 4백만 행에서 화면 응답, Lighthouse, axe(WCAG 2.1 AA), pnpm audit

### 특이사항
- **수집 서버 교착 상태(문제 A)**: PC 300대 동시 전송 시 deadlock 다수로 처리 정지. 임시 사본에서 해시 기록 순서 정렬 + 최근 본 해시 갱신 생략으로 교착 0·5초 처리 확인. 실제 코드는 승인 후 수정 예정
- 늦게 도착한 로그온 실패가 EDR-AUTH-001 에서 빠짐(문제 B), pg_cron 없을 때 파티션·보존 작업 미실행(문제 C)
- 시험용 스크립트는 저장소 밖(작업 환경)에 있음. 저장소 반입은 승인 후

## 2026-10-02 1단계 보강: 수집 교착 해소 · 늦은 이벤트 탐지 · 유지보수 대체 실행 · 감사 기록 · 통합 테스트/CI

### 바꾼 것
- 수집 서버 `services/cmd/ingest/main.go` : 해시 등록(`registerHashes`)을 본 트랜잭션 밖에서 정렬된 한 문장으로 처리, 1시간 안에 본 해시는 last_seen 갱신 생략 → 동시 전송 교착 해소
- enricher `services/cmd/enricher/main.go` : `RUN_DETECTIONS=1` 일 때 탐지(1분)와 함께 `edr_maintenance()`(시작 시·6시간마다) 실행
- DB 새 마이그레이션 `supabase/migrations/20261002000006_ops_audit.sql`
  - `edr_run_detections()` 교체: EDR-AUTH-001 을 발생 시각 기준 10분 이동 창으로(늦게 도착한 실패도 탐지, `delayed` 표시)
  - `edr_maintenance()`(파티션 생성 + 보존 정리 + 실행 시각 기록), pg_cron 일정 edr-partitions·edr-retention → edr-maintenance
  - `console_system_status()` (시스템 상태), `audit_log` + `edr_audit()` 트리거(인시던트·경보·규칙·예외·등록키·구성원·장치), `console_update_incident()`(조사 시작·다시 열기를 경보까지 한 번에), `console_close_incident()` 감사 기록 한 줄 처리
- DB 테스트 `supabase/tests/rls_and_detection_test.sql` : 늦은 무차별 대입, 유지보수, 시스템 상태, 감사 기록(불변·권한) 6항목 추가
- 콘솔: DataSource 에 `systemStatus`·`auditLog` 추가(Supabase·데모 모두), 설정 화면에 "시스템 상태"·"감사 기록"(관리자, 종류별 필터·페이지), 인시던트 상태 변경을 RPC 로, `format.ts` 에 `fullDay`
- 통합 테스트 `tests/integration/`(run.sh, 01~04 단계 스크립트, Supabase 흉내, README), CI `.github/workflows/ci.yml`
- `deploy/docker-compose.yml` RUN_DETECTIONS 주석, 문서: ARCHITECTURE(§4·§5-4·§8·§9·§10), DEV_GUIDE(CI 확인, pg_cron 일정), CLAUDE.md(검증표·감사·정기 작업 규칙), QUALITY_REVIEW(§7 조치 현황)

### 검증한 것
- 서버 gofmt·vet·빌드, 에이전트 수동형 가드레일
- 새 DB 에 마이그레이션 6개 + SQL 테스트 22항목 통과, 기존 DB(0005 까지 적용)에 0006 증분 적용 확인
- 콘솔 tsc·eslint·next build 통과, 설정 화면 밝은·어두운·모바일 캡처 확인
- `tests/integration/run.sh` 전체 통과: 로그인·등록키 7, 수집 21, 콘솔 43, 부하 2(150대×3회 450건 모두 202, p95 0.34초), 수집 서버 교착 0
- 고치기 전 수집 코드로 같은 부하 시험을 돌리면 450건 중 365건 오류·교착 365건으로 실패 → 회귀 시험이 문제를 잡는 것 확인
- 대용량 DB(텔레메트리 4백만 행)에서 PC 300대×6회: 초당 약 240요청·2만4천 행, p95 0.46초, 교착 0

### 특이사항
- GitHub Actions 워크플로는 이 환경에서 실제로 돌려 보지 못함(첫 푸시 때 Actions 탭 확인 필요). go.sum 이 없으면 CI 가 `go mod tidy` 로 만든다
- 시험 중 새로 찾은 문제 2건(QUALITY_REVIEW §7): M 인시던트가 둘로 나뉘는 경우 병합 안 됨, N DB 장애 시 ingest 가 401 응답 — 승인 후 수정
- MFA·SSO(문제 D)는 회사 계정 체계 결정 후 진행

## 2026-10-02 회사 계정(SSO) 실험 구성 — 테스트용 AD + Keycloak + AD 그룹 → 콘솔 역할

### 배경
- 사내 인증은 온프레미스 AD(`bing.co.kr`, NetBIOS `BING`), Entra ID 연결 없음. 우선 개인 PC 에서 SSO 를 시험하기로 함(사용자 요청: Keycloak 포함)

### 바꾼 것
- 새 실험실 `deploy/sso-lab/`
  - `samba/Dockerfile`, `samba/entrypoint.sh` : 테스트용 AD(Samba AD DC, `BING.TEST`/`BING`) — 첫 실행 때 OU=EDR, 권한 그룹 3개, Keycloak 서비스 계정, 테스트 사용자 5명(그룹 없음·비활성 포함) 생성
  - `keycloak/bing-realm.json` : 렐름 bing — AD 읽기 전용 연결(MSAD 계정 상태 반영), AD 그룹 → 역할, 콘솔 클라이언트(groups 클레임), 관리자(EDR-Admins) OTP 필수 로그인 흐름, Kerberos 자리(꺼 둠), 로그인 이벤트 기록
  - `docker-compose.yml` : AD + Keycloak(개발 모드), 비밀값은 환경 변수 자리
- DB `supabase/migrations/20261002000007_sso_ad_groups.sql` : `sso_group_roles`(AD 그룹 → 역할, RLS), `tenant_members.managed_by`, `auth.users` 트리거 `edr_sync_sso_membership`(로그인마다 역할 맞춤·그룹 없으면 접근 제거·수동 구성원 유지·감사 기록), 대응표 변경 감사, `console_members` 에 출처 추가
- `supabase/config.toml`(로컬 Supabase: Keycloak 공급자, 세션 12시간·비활동 2시간), `supabase/seed.sql`(실험 조직·대응표)
- 콘솔: 로그인 화면 "회사 계정으로 로그인"(`NEXT_PUBLIC_SSO_PROVIDER` 있을 때만), `app/auth/callback/route.ts`(PKCE 세션 교환), 권한 없음·SSO 오류 안내, 로그아웃 시 Keycloak 세션도 종료(`SSO_LOGOUT_URL`), 설정 화면에 "회사 계정(AD) 연동" 표·구성원 "AD 그룹" 표시·감사 문구, DataSource `ssoGroupRoles`(Supabase·데모)
- 시험: `supabase/tests` 에 SSO 4항목, `tests/integration/05-sso.mjs`·`sso-login.mjs`(Keycloak 화면 공용 도우미·TOTP), `sso-lab-verify.mjs`(개인 PC 실제 Keycloak 확인용), `fake-supabase.mjs` 에 PKCE·Keycloak 화면 흉내 추가, `supabase-stub.sql` 에 메타데이터 열
- 문서: `docs/SSO_LAB.md`(실행 순서·확인 항목·회사 적용 시 바꿀 값·Kerberos·문제 해결), ARCHITECTURE §8·§9, DEV_GUIDE, QUALITY_REVIEW D, tests/integration/README

### 검증한 것
- 테스트용 AD: 이 작업 환경에서 같은 entrypoint 로 Samba AD DC 를 실제로 만들고 재시작까지 확인, Keycloak 이 쓰는 LDAP 조회(서비스 계정 바인드, 사용자·그룹·비활성 상태)를 ldapsearch 로 재현
- Keycloak 렐름 파일: Keycloak 26.8.0 소스의 표현 클래스·설정 키·공급자 ID 와 대조(필드 오류 0), 가져오기 때 기본 매퍼가 자동 생성되지 않는 점을 소스에서 확인하고 매퍼를 모두 명시
- Supabase Auth: 소스에서 Keycloak 공급자가 groups 를 custom_claims 로 저장(v2.176 이상)·재로그인 때 다시 쓰는 것 확인, 실제 Supabase Auth 마이그레이션 76개로 만든 auth 스키마에서 트리거·SQL 테스트 통과
- DB 테스트 26항목, 통합 테스트 전체 통과(1단계 7, 2단계 21, 3단계 43, SSO 21, 부하 2, 교착 0)
- 콘솔 tsc·eslint·next build, 로그인·설정 화면 캡처

### 특이사항
- 이 환경에서는 Docker 실행과 Keycloak·Supabase Auth 바이너리 내려받기가 막혀 있어, 실제 Keycloak 로그인은 개인 PC 에서 `node tests/integration/sso-lab-verify.mjs` 로 확인해야 함
- 회사 적용은 IT 협조 필요: 읽기 전용 서비스 계정, LDAPS, (자동 로그인 시) SPN·keytab·GPO — `docs/SSO_LAB.md` §6

## 2026-10-02 CrowdStrike·Genians 벤치마크 기능 확장 + SSO 실험 구성 켜기·끄기

### 요청과 해석
- "크라우드스트라이크, 지니언스 벤치마킹해서 판매수준으로" → **상용 제품 품질**로 해석. 회사 내부 전용(과금·고객별 화면 없음)과 수동형(PC 를 바꾸지 않음) 원칙은 유지하고, 두 제품 공통 기능 중 "보는" 기능만 추가
- "SSO 실험 구성은 켜고 끌 수 있게" → 스위치 스크립트 하나로 컨테이너·Supabase 설정·콘솔 버튼을 함께

### 바꾼 것
- SSO 스위치: `deploy/sso-lab/lab.mjs`(on/off/status/reset, `--no-docker`, `--restart-supabase`). `.env`·`apps/web/.env.local` 의 관리 구간만 고침. `supabase/config.toml` Keycloak 기본 꺼짐(`SUPABASE_AUTH_EXTERNAL_KEYCLOAK_ENABLED` 로 켬). 설정 화면에 버튼 상태 표시. 문서 `docs/SSO_LAB.md`, `deploy/sso-lab/docker-compose.yml` 머리말, `apps/web/.env.example`, DEV_GUIDE
- 에이전트(읽기 전용): `internal/collector/inventory_windows.go`(OS·하드웨어·SMBIOS 일련번호·메모리·디스크·도메인·어댑터·설치 프로그램), `posture_windows.go`(보안 설정 11개 점검, 서비스 상태는 조회 권한만), `inventory.go`+`inventory_test.go`(SMBIOS 해석·필터·변경 판단 단위 시험), `config`(inventory_interval·posture_interval·av_services), `main.go` 연결, `packaging/config.example.json`
- 데이터 계약: `contracts/ingest.schema.json`·`model/types.go`·`contract/types.go` 에 `inventory`·`posture`
- 수집 서버: 검증(점검 ID·상태, 프로그램 5000개 상한), DB 저장 함수 호출, JSON 의 NUL 제거(`stripNUL` + `main_test.go`)
- DB `supabase/migrations/20261002000008_assets_posture_ioc.sql`: 자산·설치 프로그램·이력, 보안 상태·점수·조직별 반영, Windows 수명 주기 표, 소프트웨어 정책(기본 제공 5개를 조직마다 복사), 위협 지표(7일 소급 트리거·너무 넓은 대역 거부), 탐지 규칙 EDR-IOC-001/002·EDR-SW-001·EDR-POS-001(탐지 함수 교체), 유지보수에 이력 1년 보관, 장치 타임라인에 설치 이력, 콘솔 조회 함수 7개, RLS·감사 트리거
- 콘솔: 자산·소프트웨어(`/assets`), 보안 상태(`/posture`), 위협 지표(`/iocs`) 화면, 장치 상세 "자산"·"보안 상태" 탭, 현황 "보안 위생", CSV 내보내기(`/api/export/*`), 메뉴, 규칙 화면 C2 전술, ATT&CK 목록 T1071, 감사 기록 문구·필터, `components/asset-controls.tsx`, ui 조각(점검 상태·점수·페이지), `lib/software-policy.ts`, DataSource 메서드 17개(Supabase·데모), 데모 데이터 `demo-assets.ts`
- 시험: SQL 8항목 추가(34), 종단 `02-agents.mjs` 확장, `06-assets.mjs`(33), `07-sso-switch.mjs`(11), `run.sh` 단계 추가, CI 에 Go 단위 시험
- 문서: `docs/BENCHMARK.md`(새), ARCHITECTURE §3·§4·§5·§8·§9, QUALITY_REVIEW §8, tests/integration/README

### 검증한 것
- 에이전트: Windows amd64·arm64 vet·빌드, 단위 시험, 수동형 가드레일 통과
- 서버: vet·test·build. DB: 마이그레이션 8개 새 DB 적용 + SQL 34항목 통과
- 콘솔: tsc·eslint·next build, 데모 모드 화면 캡처(밝은·어두운·모바일), 브라우저 오류 0
- 종단 시험 전체 통과: 01 7, 02 28, 03 43, 06 33, 05 21, 07 11, 부하 2, 교착 0
- 성능: 장치 2,000대×프로그램 150개에서 소프트웨어 노출 조회 4.7초 → 0.17초로 고침(이름·버전 묶음 단위 비교), 너무 넓은 금지 정책이 경보 12만 건을 만들던 문제 → 장치·정책당 1건, 실행당 500건 상한

### 특이사항
- 실제 Windows 에서 자산·보안 상태 값은 `edr-agent.exe console` 출력의 `inventory`·`posture` 로 확인 필요(이 환경은 Windows 실행 불가)
- 사내 백신(예: AhnLab V3)의 서비스 이름은 기본 목록에 없으면 `config.json` 의 `av_services` 에 추가해야 "실시간 검사"가 통과로 나온다(`sc query` 로 확인)
- Windows 수명 주기 표·기본 제공 취약 소프트웨어 목록은 마이그레이션으로 갱신해야 한다
- `.github/workflows/ci.yml` 은 이번에도 바뀜(Go 단위 시험) — PC 에 직접 저장 필요
- 일부러 넣지 않은 것(격리·차단·원격 대응·장치 제어·NAC 차단): `docs/BENCHMARK.md` §2-4

## 2026-10-02 문서 감사(보안 관리자의 PC 감사): 개인정보·키워드·오래된 문서 찾기

### 요청과 해석
- "주민등록번호 등 개인정보 문서, 특정 단어가 든 문서, 저장일 기준 오래된 문서 찾기" + "보안관리자가 PC 감사하는 용도" → 관리자 전용 감사 기능으로 구현
- 선택: PDF 포함(PDF 라이브러리 추가 승인), 실행은 정기 자동 + 콘솔 "지금 검사"
- 원칙: 에이전트는 문서를 **읽기만**(고치기·옮기기·지우기 없음), 서버에는 **위치와 건수만**(내용·개인정보 값 없음), 기본 꺼짐 + 직원 고지 확인 필수, 소유자·관리자만, 조회·내려받기까지 감사 기록

### 바꾼 것
- 에이전트: `internal/docscan/`(detect.go 검출, extract.go 형식별 글자 추출, hwp.go HWP 5.0 복합 문서 읽기, scanner.go 폴더 순회·속도 제한·배치, runner.go 일정·상태 파일, open_windows.go 공유 모드 열기·클라우드 전용 파일 건너뛰기, docscan_test.go), `transport` `GetPolicy`, `config`(policy_interval·docscan_mb_per_sec), `main.go`(15분마다 정책 확인, 백그라운드 검사, `edr-agent.exe docscan <폴더> [키워드]` 확인 명령), `packaging/config.example.json`, `go.mod`(github.com/ledongthuc/pdf)
- 데이터 계약: `doc_scan` (`contracts/ingest.schema.json`, `model/types.go`, `contract/types.go`)
- 수집 서버: `GET /v1/policy`, `doc_scan` 검증(검사 ID·종류·건수·크기), DB 함수로 저장, `main_test.go` 시험 추가
- DB `supabase/migrations/20261002000009_doc_audit.sql`: 정책(고지 확인 제약)·요청·검사·결과 테이블, RLS(관리자만), 에이전트용 함수 2개, 콘솔 함수 3개(조회·내려받기 감사 포함), 감사 트리거, 유지보수(이력 1년)
- 콘솔: `/documents`(개인정보·키워드·오래된 문서·검사 현황·설정), `components/doc-controls.tsx`, `lib/data/doc-defaults.ts`, `demo-docs.ts`, DataSource 메서드 6개(Supabase·데모), 서버 액션 2개, CSV(`/api/export/documents-*`), 메뉴, 감사 기록 문구·필터
- 시험: SQL 1묶음 추가(35), 종단 `tests/integration/08-docscan.mjs`(27), `run.sh`, README
- 문서: ARCHITECTURE §3·§7-3, BENCHMARK, `docs/DOC_AUDIT_NOTICE.md`(직원 공지 예시, 새 파일), CLAUDE.md 의 허용 의존성에 PDF 라이브러리 추가

### 검증한 것
- 에이전트: 단위 시험(검출·Office·HWPX·HWP·PDF·중단 시 최종 배치 없음·일정), Windows amd64·arm64 vet·빌드, 수동형 가드레일 통과
- 서버: vet·test·build. DB: 마이그레이션 9개 새 DB 적용 + SQL 35항목 통과
- 콘솔: tsc·eslint·next build, 데모 화면 캡처(밝은·어두운·모바일), 브라우저 오류 0
- 종단 시험 전체 통과: 01 7, 02 28, 03 43, 06 33, 08 27, 05 21, 07 11, 부하 2, 교착 0

### 특이사항
- 실제 Windows 에서 확인 필요: `edr-agent.exe docscan C:\Users\<나>\Documents 대외비` (결과를 화면에만 출력)
- `agent/go.sum` 이 없으므로 처음 빌드 전에 `scripts\build.ps1 -Tidy`(또는 agent 폴더에서 `go mod tidy`) 필요. CI 는 자동으로 함
- 한계: 이미지·스캔 PDF(글자 없는 PDF) 안의 번호는 찾지 못함(OCR 없음), CP949 로 저장된 txt 의 한글 키워드는 못 찾을 수 있음(숫자 형태 개인정보는 찾음), 암호 문서는 "암호가 걸린 문서"로만 표시
- 켜기 전에 인사·법무와 공지 문구(`docs/DOC_AUDIT_NOTICE.md`)를 확인할 것

## 2026-10-02 PC 조치 목록 메뉴 추가 (보안·문서 업데이트 필요 사항)

### 요청과 해석
- "PC 보안·문서 업데이트 필요 사항을 메뉴로" → 선택: **PC별 조치 목록** + **담당자·완료 표시** 관리
- 조치 항목은 지금 데이터에서 계산(따로 쌓지 않음) → 고쳐지면 다음 수집·검사에서 저절로 빠지고, 처리 기록이 있으면 "해결 확인됨"으로 남음(90일)

### 바꾼 것
- DB `supabase/migrations/20261002000010_remediation.sql`: 처리 기록 `remediation_tracking`(상태·담당자·메모·기한, RLS — 문서 감사 항목은 관리자만), 계산 함수 `edr_remediation_items`(점수에 넣은 보안 점검 실패, 켜 둔 소프트웨어 정책의 장치·정책별 1건, 개인정보·오래된 문서 장치별 1건), 콘솔 함수 `console_remediation`·`console_remediation_overview`, 처리 함수 `console_remediation_update`(분석가 이상, 문서 항목은 관리자, 담당자는 조직 구성원만, 최대 500건), 감사(한 건은 트리거, 여러 건은 대표 한 줄 `remediation.bulk`)
- 콘솔: 메뉴 "PC 조치 목록"(`/remediation`), `components/remediation-table.tsx`(고르기 + 상태·담당자·기한·메모 한꺼번에), `lib/remediation-labels.ts`, `lib/data/demo-remediation.ts`, DataSource 메서드 3개(Supabase·데모), 서버 액션 `updateRemediation`, CSV `/api/export/remediation`, 감사 기록 문구·필터·값 표시
- 시험: SQL 1묶음 추가(36), 종단 `tests/integration/09-remediation.mjs`(20), `run.sh`, README
- 문서: ARCHITECTURE §9-1(문서 감사·PC 조치 목록 화면), BENCHMARK

### 검증한 것
- DB: 마이그레이션 10개 새 DB 적용 + SQL 36항목 통과
- 콘솔: tsc·eslint·next build, 데모 화면 캡처(밝은·어두운·모바일), 일괄 처리 클릭 시험(안내·감사 기록), 브라우저 오류 0
- 종단 시험 전체 통과: 01 7, 02 28, 03 43, 06 33, 08 27, 09 20, 05 21, 07 11, 부하 2, 교착 0

### 특이사항
- 에이전트·수집 서버는 바뀌지 않음(조치는 사람이 함 — 에이전트는 여전히 읽기만)
- "완료 표시"는 처리했다는 기록일 뿐, 실제 해결은 다음 수집(보안 점검 1시간·프로그램 6시간)이나 문서 검사에서 확인됨
- 같은 PC 의 같은 문제는 한 줄(소프트웨어는 정책당, 문서는 종류당)로 묶음

---

## 2026-10-06 — 알림 연동 (슬랙·이메일·SIEM) + 탐지 고도화 확인

### 요청과 해석
- 업로드한 EDR 기능 목록 전체 중 **"보고·탐지·알림"** 범위만 적용(선택 B: 알림 + 탐지 고도화). 에이전트가 PC를 제어하는 자동 대응·자체 보호·원격 셸·커널 드라이버는 "에이전트는 보기만 한다" 원칙상 만들지 않음.
- 사내 메신저 연동은 슬랙 포함 요청 → 슬랙·이메일·SIEM(Syslog) 채널로 구성.
- 확인 결과 MITRE ATT&CK 매핑·IoC/VirusTotal 대조·프로세스 트리는 이미 있던 기능(0004·0008·process-tree) → 새로 만든 것은 알림 연동뿐. 알림에 기존 MITRE 정보를 함께 실음.

### 바꾼 것
- DB `supabase/migrations/20261002000011_notifications.sql`(신규): 채널 `notification_channels`(종류·대상·`secret_ref`·심각도 하한·규칙 접두사, RLS — 읽기는 구성원·관리는 소유자/관리자), 발송 큐 `notification_outbox`, 경보 INSERT 트리거 `edr_enqueue_notifications`(심각도·규칙 거르기 + MITRE payload), 발송용 `edr_lease_notifications`/`edr_mark_notification`/`edr_prune_notifications`(edr_enricher), 테스트 발송 `console_notification_test`, 전용 감사 트리거 `edr_audit_notification`(`notification.channel.*`)
- 수집 서버: `services/internal/notify`(슬랙·이메일[SMTP]·syslog·웹훅, 표준 라이브러리만, 시험용 `EDR_NOTIFY_SINK`), enricher 알림 루프 `notifierLoop`(기본 켜짐, `RUN_NOTIFIER=0` 으로 끔)
- 콘솔: 설정에 "알림 연동" 패널(`components/notification-controls.tsx` — 채널 추가·수정·삭제·테스트 발송, 관리자만), DataSource 메서드 4개(Supabase·데모), 서버 액션 3개(`saveNotificationChannel`·`deleteNotificationChannel`·`testNotificationChannel`, zod·관리자), 감사 필터·문구
- 시험: DB SQL 1묶음 추가(총 37), 종단 `tests/integration/10-notify.mjs`(15), `run.sh`(enricher 에 SINK, 8-4 단계), README
- 문서: ARCHITECTURE §4-1(알림 연동), `deploy/.env.example`(RUN_NOTIFIER·SLACK·SMTP·syslog 안내)

### 검증한 것
- 수집 서버: 스크래치 복사본에서 `go build`(enricher·ingest) 통과 — pgx 등 의존성은 로컬 체크아웃 replace 로 빌드
- DB: 마이그레이션 11개 새 DB 적용 + SQL 37항목 통과(알림: 심각도·규칙 거르기, MITRE payload, 조직 RLS, 관리자 전용, 감사)
- 콘솔: tsc·eslint·next build 통과
- 종단 시험 전체 통과: 01 7, 02 28, 03 43, 06 33, 08 27, 09 20, **10 15**, 05 21, 07 11, 부하 2, 교착 0
- 에이전트 `scripts/check-passive.sh` 통과(에이전트 코드 안 건드림)

### 특이사항
- **에이전트는 그대로** — 알림은 전부 서버(enricher)에서 내보냄. PC 제어 기능은 넣지 않음.
- 비밀값(슬랙 웹훅 URL·SMTP 비밀번호)은 DB·브라우저에 저장하지 않음. 채널에는 `.env` 키 이름만 두고 실제 값은 서버 `.env` 에서 읽음.
- 실제 "차단·롤백"은 Windows Defender(실시간 보호·제어된 폴더 액세스·공격 표면 감소)에 맡기고 이 EDR 은 보고·탐지·알림을 맡는 조합 권장.
- 운영 전 `.env` 에 채널 `secret_ref` 에 맞는 변수(예: `SLACK_WEBHOOK_SOC`)와 `SMTP_*` 를 채워야 실제 전송됨.

---

## 2026-10-06 — Wazuh 경보를 콘솔로 받기 (외부 오픈소스 EDR 연동)

### 요청과 해석
- "PC 제어·차단은 직접 만들지 말고 기존 오픈소스를 쓴다"는 방향 확인 후, 그중 **Wazuh 경보를 이 콘솔 한 화면에서 함께 보는 단방향 수집**만 구현. Wazuh·PC 를 제어하지 않음.
- 실제 차단·대응은 Windows Defender + Wazuh 에 맡기는 조합 권장(문서화).

### 바꾼 것
- DB `supabase/migrations/20261002000012_wazuh_alerts.sql`(신규): `alerts.source`('edr'|'wazuh') 컬럼, 저장 함수 `edr_ingest_wazuh_alert`(rule level→심각도, 에이전트 이름→장치 매칭, Wazuh id 중복 방지, MITRE·src_ip 를 details 에; edr_ingest 전용). 기존 경보·인시던트·알림 트리거를 그대로 탐.
- 수집 서버 `services/cmd/ingest/main.go`: `POST /v1/wazuh` 웹훅(공유 비밀 `WAZUH_WEBHOOK_SECRET` + `WAZUH_TENANT_ID`, 둘 다 있을 때만 열림, 상수시간 비교, gzip·단건/배열 수신, 최대 500건)
- 콘솔: `Alert.source`·필터, 경보 화면 출처 필터(내장 탐지·Wazuh)와 `Wazuh` 배지(목록·상세), 데모 Wazuh 경보 2건
- Wazuh 쪽 연동: `deploy/wazuh/custom-edr`·`custom-edr.py`(integrator 스크립트, 표준 라이브러리만), `deploy/wazuh/README.md`(설정 절차), `deploy/.env.example`
- 시험: DB SQL 1묶음(총 38), 종단 `tests/integration/11-wazuh.mjs`(10), `run.sh`(ingest 에 WAZUH env, 8-5 단계), README
- 문서: ARCHITECTURE §4-2(외부 EDR 경보 수집)

### 검증한 것
- DB: 마이그레이션 12개 적용 + SQL 38항목 통과(Wazuh: 심각도 매핑·호스트 매칭·중복·source·인시던트 묶음·실행 권한·구성원 RLS)
- 수집 서버: `go build`(ingest·enricher), 웹훅 수동 시험(401·단건·배열·중복)
- 콘솔: tsc·eslint·next build, 경보 화면 출처 필터·배지 캡처 확인
- 종단 시험 전체 통과: 01 7, 02 28, 03 43, 06 33, 08 27, 09 20, 10 15, **11 10**, 05 21, 07 11, 부하 2
- 에이전트 `check-passive.sh` 통과(에이전트 안 건드림)

### 특이사항
- 단방향 수집만 함. Wazuh 를 조작하거나 PC 에 개입하는 코드는 없음.
- Wazuh 경보도 알림 연동(슬랙·이메일) 조건에 걸리면 함께 발송됨.
- 운영 전 수집 서버 `.env` 에 `WAZUH_WEBHOOK_SECRET`·`WAZUH_TENANT_ID` 를 넣고, Wazuh 매니저에 integrator 스크립트·`<integration>` 블록을 설정해야 함(`deploy/wazuh/README.md`).

---

## 2026-10-06 — CI 워크플로 복구·실행

### 요청과 해석
- 저장소에 `.git` 이 없어 첫 푸시 때 `.github/workflows` 가 비어 있었음. "CI 돌려줘" → 문서·`run.sh` 기준으로 `ci.yml` 복구 후 Actions 실행.

### 바꾼 것
- `.github/workflows/ci.yml`(신규): `agent`(가드레일·단위시험·Windows amd64/arm64 빌드·vet), `server`(gofmt·vet·test·build), `console`(lint·typecheck·build), `integration`(Postgres 16 + PostgREST 12.2.8 + Playwright, `tests/integration/run.sh`, 실패 시 `integration-logs` 아티팩트)

### 검증한 것
- 로컬 `scripts/build.ps1 -Tidy` 는 이전 턴에서 통과.
- CI 1차: agent·console 통과, server gofmt 실패 → `notify.go` gofmt 후 재실행.
- CI 2차: agent·server·console 통과, integration 은 `03-console` "메모 저장" 1건 실패(나머지 단계 통과).

### 특이사항
- 워크플로 파일이 로컬에 없어서 문서(DEV_GUIDE·integration README·work-log)와 `run.sh` 요구사항으로 재작성함.
- 메모 저장 실패 원인: 테스트가 `getByText` 로 확인하는데, 아직 textarea 에 남은 글자와 바로 매칭되어 서버 액션 완료 전에 DB 를 읽음. 입력칸이 비워질 때까지 기다리도록 `03-console.mjs` 수정.
