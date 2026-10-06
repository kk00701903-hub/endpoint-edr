# Endpoint EDR — Claude 작업 규칙

이 저장소의 **개발(설계·코드 작성·수정·검증)은 Claude 가 한다.**
사용자는 Cursor 에서 **변경 확인 → 빌드 → 커밋 → 푸시만** 한다. 절차는 `docs/DEV_GUIDE.md`.

## 프로젝트 개요
- 수동형(Passive) Windows 엔드포인트 모니터링 시스템. **회사 내부 전용**(외부 판매·배포 없음).
- DB 는 조직(tenant) 단위 구조지만 기본은 회사 1개. 판매용 기능(과금, 고객별 분리 UI 등)은 만들지 않는다.
- 구성: `agent/`(Go Windows 서비스) → `services/ingest`(Go) → Supabase Postgres → Grafana(`deploy/grafana`) / Next.js 관리 콘솔(`apps/web`).
- 설계 근거는 항상 `docs/ARCHITECTURE.md` 를 먼저 읽고 따른다.

## 작업 규칙
- 작업 폴더는 사용자 PC 의 `C:\Develop\endpoint-edr`. 파일은 이 폴더에 직접 수정해 둔다.
- 요청받은 범위 밖의 파일·문장·구조는 바꾸지 않는다. 다른 곳을 고쳐야 하면 먼저 이유와 함께 물어본다.
- **git commit / push 는 하지 않는다.** 파일 수정까지만 한다(커밋·빌드·푸시는 사용자가 Cursor 에서).
- 작업이 끝나면
  1. 아래 "검증"을 실행하고 결과를 보고한다(통과 못 한 항목은 숨기지 않는다).
  2. `docs/work-log.md` 맨 아래에 날짜·변경 파일·특이사항을 한국어로 추가한다.
  3. 사용자가 그대로 쓸 수 있는 **커밋 메시지 한 줄**을 제안한다(예: `feat(agent): Sysmon 채널 수집 추가`).
- 코드 주석·문서는 한국어, 식별자는 영어.
- Windows 실제 실행은 Claude 가 할 수 없다. 에이전트는 크로스 컴파일·vet 으로 검증하고, 실기 확인이 필요한 부분은 사용자에게 확인 방법(`edr-agent.exe console` 등)을 알려준다.

## 검증 (변경한 영역만)
| 영역 | 명령 |
|---|---|
| 에이전트 | `cd agent && GOOS=windows go vet ./... && GOOS=windows go build ./cmd/edr-agent` + `bash scripts/check-passive.sh` |
| 서버 | `cd services && go vet ./... && go build ./...` |
| DB | 로컬 PostgreSQL 에 마이그레이션 전체 적용 후 `supabase/tests/rls_and_detection_test.sql` 실행 |
| Grafana | 대시보드·알림 SQL 을 `grafana_reader` 권한으로 실행해 오류 없는지 확인 |
| 콘솔 | `cd apps/web && pnpm lint && pnpm typecheck && pnpm build` + `EDR_DEMO=1` 로 띄워 바꾼 화면을 스크린샷으로 확인(밝은·어두운·모바일) |
| 종단(여러 영역에 걸친 변경, DB·ingest·콘솔 쓰기 동작) | 테스트 전용 PostgreSQL 로 `bash tests/integration/run.sh` (설명은 `tests/integration/README.md`). 같은 시험이 GitHub Actions(`.github/workflows/ci.yml`)에서 푸시·PR 마다 돈다 |

## 데이터 계약
- 에이전트↔서버 데이터 형식의 단일 기준은 `contracts/ingest.schema.json`.
- 필드를 바꾸면 반드시 함께 수정: `agent/internal/model/types.go`, `services/internal/contract/types.go`,
  `services/cmd/ingest/main.go`(저장부), `supabase/migrations/`(새 마이그레이션), 콘솔 타입(`apps/web/src/lib/data/types.ts`).

## 보안 기본값
- Supabase `service_role` 키는 서버 코드에서만. 브라우저 번들·에이전트에 절대 넣지 않는다.
- 비밀값은 `.env`(커밋 금지)로만. 예시는 `.env.example` 에 더미값.

---

## 에이전트(`agent/`) — 읽기 전용·충돌 제로
### 절대 규칙: 에이전트는 "보기만" 한다
다음은 어떤 이유로도 추가하지 않는다. 요청받으면 거절하고 대안을 제시한다.
- 프로세스 종료/일시정지, 다른 프로세스 메모리 읽기·쓰기(PROCESS_VM_READ 포함), 원격 스레드, DLL 주입, 후킹
- 파일 삭제·이동·속성 변경(단, `C:\ProgramData\EndpointEDR\` 내부의 자기 상태 파일은 예외)
- 레지스트리 쓰기 권한 요청(KEY_SET_VALUE, KEY_ALL_ACCESS 등), 방화벽/네트워크 설정 변경
- 커널 드라이버, ETW 커널 프로바이더, 감사 정책(auditpol)·이벤트 로그 설정 변경, 외부 프로그램 실행(exec.Command)

### 필수 패턴
- 프로세스 핸들: `PROCESS_QUERY_LIMITED_INFORMATION` 만.
- 파일 열기: `FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE`, 해시는 `internal/hasher` 사용(캐시·속도제한).
- 레지스트리: `QUERY_VALUE|ENUMERATE_SUB_KEYS` 만.
- 새 수집기는 `internal/collector/*_windows.go` 에 `//go:build windows` 로 작성, 차분(diff) 전송, 1회 처리량 상한을 둔다.
- 실패는 조용히 건너뛰고(보호 프로세스 접근 거부는 정상) 서비스 이벤트 로그에만 남긴다. panic 금지.
- CGO 금지(크로스 컴파일 유지). 외부 의존성은 golang.org/x/sys, github.com/ledongthuc/pdf(문서 감사 PDF 글자 추출, 2026-10 승인) 외 추가 전에 물어본다.

## DB(`supabase/`) — 마이그레이션·RLS
- 사용자가 DB 에 적용한 마이그레이션 파일은 수정하지 않는다. 변경은 항상 새 파일 `supabase/migrations/YYYYMMDDHHMMSS_설명.sql`.
- 새 테이블은 같은 마이그레이션에서 `enable row level security` + 정책을 만든다. 정책 없는 테이블 금지.
- 조직 판별은 `tenant_id in (select public.my_tenant_ids())`, 역할 판별은 `(select public.has_tenant_role(tenant_id, array[...]))`.
  `auth.uid()` 는 `(select auth.uid())` 로 감싼다(행마다 재평가 방지).
- 텔레메트리 테이블은 authenticated 에게 INSERT/UPDATE/DELETE 를 주지 않는다. 쓰기는 edr_ingest/edr_enricher 역할만.
- 대용량 테이블은 `observed_at`/`event_time` 월 파티션. 새 파티션 테이블은 `edr_ensure_partitions()` 배열에 추가.
- 새 탐지 규칙: `edr_run_detections()` 에 블록 추가, 규칙 ID `EDR-<영역>-<번호>`, `dedup_key` 필수, `docs/ARCHITECTURE.md` §4 표 갱신.
- 변경 후 `supabase/tests/rls_and_detection_test.sql` 에 테스트를 추가하고 실행한다.
- 사용자가 화면·API 로 하는 새 관리·조치 동작을 만들면 `edr_audit()` 트리거 대상에 넣어 감사 기록을 남긴다. 여러 행을 한꺼번에 바꾸는 동작은 RPC 안에서 `edr.audit_cascade` 를 켜서 대표 한 줄만 남긴다.
- 정기 작업을 추가하면 pg_cron 일정과 enricher 대체 루프(`RUN_DETECTIONS=1`) 양쪽에 넣고, 실행 시각을 `detection_state` 에 남겨 콘솔 시스템 상태에 보이게 한다.

## 관리 콘솔(`apps/web`) — Next.js
- Next.js App Router + TypeScript(strict). 데이터 조회는 서버 컴포넌트 우선, 상호작용만 클라이언트 컴포넌트.
- 데이터 접근은 반드시 `src/lib/data/source.ts` 의 `DataSource` 계약을 통한다. 메서드를 추가하면 `supabase-source.ts`(실데이터)와 `demo-source.ts`(예시 데이터) **둘 다** 구현한다.
- Supabase 는 `@supabase/ssr` 로 서버/브라우저 클라이언트를 분리(`src/lib/supabase/server.ts`, `client.ts`). 세션 갱신은 `src/proxy.ts`(Next 16 의 middleware 후속).
- 브라우저에서는 anon key + 사용자 세션만 사용 → 권한은 전적으로 RLS 가 판단. `service_role` 사용 금지.
- 쓰기 동작(경보 상태 변경, 등록키 발급)은 Server Action 또는 Route Handler 에서 zod 로 입력 검증 후 실행.
  등록키 발급은 RPC `create_enrollment_key` 호출(평문 키는 화면에 1회만 표시).
- 도메인 타입은 `src/lib/data/types.ts`(DB 컬럼과 1:1). any 금지. 스키마를 바꾸면 이 파일도 함께 고친다.
- UI: Tailwind v4 + `src/components/ui.tsx` 기본 조각(Button, Panel, SeverityTag 등) 재사용. 색은 `globals.css` 토큰만 사용(하드코딩 금지). 차트: Recharts 또는 직접 SVG. 실시간 경보: Supabase Realtime 의 `alerts` 구독.
- 심각도 색은 한 가지 붉은 계열 명도 단계(`--sev-*`)이며 항상 글자 라벨과 함께 쓴다. 문구는 한국어, 사용자 관점의 쉬운 말(예: "종결", "예외로 처리").
- 렌더 함수 안에서 `Date.now()` 를 직접 부르지 않는다(`nowMs()` 사용). 클라이언트에서 상대 시간을 그리는 요소에는 `suppressHydrationWarning`.
- 테이블·목록은 서버 측 페이지네이션(range) 필수 — 텔레메트리는 수백만 행이다.
- 화면 구조는 인시던트 중심(docs/ARCHITECTURE.md §9). 새 화면도 인시던트·엔터티·헌팅으로 이어지는 링크(피벗)를 둔다.
- 헌팅 쿼리 필드는 `src/lib/hunt/query.ts` 의 FIELDS 목록에만 추가한다(SQL 문자열 조립 금지). 추가하면 supabase-source 의 DATASET 컬럼과 demo 의 matches 동작을 함께 확인한다.
- 텔레메트리 테이블은 devices 로 PostgREST 임베드(`devices(hostname)`)를 쓰지 않는다(외래키 없음) — 장치 이름은 별도 조회.
