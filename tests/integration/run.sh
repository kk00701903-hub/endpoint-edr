#!/usr/bin/env bash
# =====================================================================
# 종단 통합 테스트: 콘솔 등록키 발급 → 에이전트 흉내 → 실제 ingest·enricher → DB 탐지·인시던트 → 콘솔 조사·권한·감사 → 회사 계정(SSO) → 동시 전송 부하
#
# 필요한 것: PostgreSQL 16(테스트 전용 클러스터, 초사용자 접속), psql, Go, Node 22, pnpm, PostgREST(12.x), Playwright Chromium
# 접속 정보: PGHOST / PGPORT / PGUSER 환경 변수 (예: PGHOST=localhost PGPORT=5432 PGUSER=postgres)
#
# ⚠ 테스트 DB(edr_it)를 지우고 다시 만들며, 클러스터의 edr_ingest·edr_enricher 역할에 LOGIN 을 켠다.
#   운영 DB·Supabase 프로젝트에는 절대 실행하지 말 것.
#
# 선택 환경 변수
#   POSTGREST_BIN     PostgREST 실행 파일 (기본: postgrest)
#   SERVICES_BIN_DIR  미리 빌드한 ingest·enricher 가 있는 폴더(없으면 services 를 빌드)
#   SKIP_CONSOLE_BUILD=1  apps/web 을 이 스크립트로 이미 빌드해 두었을 때(NEXT_PUBLIC_* 값이 빌드에 박히므로 다른 설정으로 빌드했으면 쓰지 말 것)
#   CHROMIUM_PATH     Playwright 기본 브라우저 대신 쓸 Chromium
# =====================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/tests/integration"
export EDR_IT_DB="${EDR_IT_DB:-edr_it}"
export EDR_IT_TMP="${EDR_IT_TMP:-$(mktemp -d /tmp/edr-it.XXXXXX)}"
POSTGREST_BIN="${POSTGREST_BIN:-postgrest}"
INGEST_PORT=18080 PGRST_PORT=3301 SUPA_PORT=54321 CONSOLE_PORT=3300
export EDR_IT_CONSOLE="http://localhost:$CONSOLE_PORT" EDR_IT_INGEST="http://127.0.0.1:$INGEST_PORT" EDR_IT_SUPABASE="http://localhost:$SUPA_PORT"
export JWT_SECRET="it-only-jwt-secret-with-at-least-32-characters-long"
LOG="$EDR_IT_TMP/logs"; mkdir -p "$LOG"

# 백그라운드 서버는 각자 프로세스 그룹(setsid)으로 띄워, 끝날 때 자식(next-server 등)까지 함께 정리한다
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -- "-$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
wait_http() { # url, 이름
  for _ in $(seq 1 60); do curl -fs -o /dev/null "$1" && return 0; sleep 1; done
  echo "시작 실패: $2 ($1)"; tail -20 "$LOG/$2.log" || true; exit 1
}
PSQL=(psql -X -q -v ON_ERROR_STOP=1)
# libpq 키워드 형식 DSN (유닉스 소켓·TCP 모두)
dsn() { echo "host=${PGHOST:-localhost} port=${PGPORT:-5432} user=$1 dbname=$EDR_IT_DB sslmode=disable"; }

# 이전 실행이 남아 있으면 엉뚱한 서버에 붙으므로 먼저 확인
for port in $INGEST_PORT $PGRST_PORT $SUPA_PORT $CONSOLE_PORT; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "포트 $port 를 이미 다른 프로그램이 쓰고 있습니다. 종료 후 다시 실행하세요."; exit 1; fi
done

step "1. DB 만들기 + 마이그레이션 + SQL 테스트"
"${PSQL[@]}" -d postgres -c "drop database if exists $EDR_IT_DB with (force)" -c "create database $EDR_IT_DB"
"${PSQL[@]}" -d "$EDR_IT_DB" -f "$HERE/supabase-stub.sql"
for f in "$ROOT"/supabase/migrations/*.sql; do
  "${PSQL[@]}" -d "$EDR_IT_DB" -f "$f" >/dev/null 2>"$LOG/migrate.err" || { cat "$LOG/migrate.err"; exit 1; }
done
echo "마이그레이션 $(ls "$ROOT"/supabase/migrations/*.sql | wc -l)개 적용"
"${PSQL[@]}" -d "$EDR_IT_DB" -f "$ROOT/supabase/tests/rls_and_detection_test.sql" 2>&1 | grep -E "OK|FAIL|ERROR" | sed 's/.*NOTICE:  /  /'
"${PSQL[@]}" -d postgres -c "alter role edr_ingest login" -c "alter role edr_enricher login"

step "2. 서비스 빌드·기동 (ingest, PostgREST, Supabase 흉내)"
BIN="${SERVICES_BIN_DIR:-$EDR_IT_TMP/bin}"
if [ -z "${SERVICES_BIN_DIR:-}" ]; then (cd "$ROOT/services" && { [ -f go.sum ] || go mod tidy; } && go build -o "$BIN/" ./cmd/...); fi
export WAZUH_WEBHOOK_SECRET="it-wazuh-secret"
DATABASE_URL="$(dsn edr_ingest)" LISTEN_ADDR="127.0.0.1:$INGEST_PORT" \
  WAZUH_WEBHOOK_SECRET="$WAZUH_WEBHOOK_SECRET" WAZUH_TENANT_ID="aaaaaaaa-0000-0000-0000-000000000001" \
  setsid "$BIN/ingest" >"$LOG/ingest.log" 2>&1 & PIDS+=($!)
PGRST_DB_URI="$(dsn "${PGUSER:-postgres}")" PGRST_DB_SCHEMAS=public PGRST_DB_ANON_ROLE=anon PGRST_JWT_SECRET="$JWT_SECRET" \
  PGRST_SERVER_PORT=$PGRST_PORT setsid "$POSTGREST_BIN" >"$LOG/postgrest.log" 2>&1 & PIDS+=($!)
FAKE_SUPABASE_PORT=$SUPA_PORT PGRST_PORT=$PGRST_PORT setsid node "$HERE/fake-supabase.mjs" >"$LOG/supabase.log" 2>&1 & PIDS+=($!)
wait_http "http://127.0.0.1:$INGEST_PORT/healthz" ingest
wait_http "http://127.0.0.1:$PGRST_PORT/" postgrest

# 콘솔 사용자(소유자) + 다른 조직
"${PSQL[@]}" -d "$EDR_IT_DB" <<'SQL'
insert into auth.users values ('33333333-3333-3333-3333-333333333333', 'secops@corp.example'), ('44444444-4444-4444-4444-444444444444', 'other@b.example');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', '우리회사'), ('bbbbbbbb-0000-0000-0000-000000000002', '다른법인');
insert into tenant_members (tenant_id, user_id, role) values ('aaaaaaaa-0000-0000-0000-000000000001', '33333333-3333-3333-3333-333333333333', 'owner'),
                                  ('bbbbbbbb-0000-0000-0000-000000000002', '44444444-4444-4444-4444-444444444444', 'owner');
-- 회사 계정(SSO): AD 그룹 → 역할 (supabase/seed.sql 과 같음)
insert into sso_group_roles (tenant_id, provider, idp_group, role) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'keycloak', 'EDR-Admins', 'admin'),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'keycloak', 'EDR-Analysts', 'analyst'),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'keycloak', 'EDR-Viewers', 'viewer');
SQL

step "3. 콘솔 빌드·기동 (Supabase 모드)"
ANON="$(JWT_SECRET="$JWT_SECRET" node "$HERE/fake-supabase.mjs" anon-key)"
export NEXT_PUBLIC_SUPABASE_URL="$EDR_IT_SUPABASE" NEXT_PUBLIC_SUPABASE_ANON_KEY="$ANON" EDR_DEMO=0 NEXT_PUBLIC_SSO_PROVIDER=keycloak
if [ "${SKIP_CONSOLE_BUILD:-0}" != "1" ]; then
  (cd "$ROOT/apps/web" && pnpm install --frozen-lockfile >/dev/null && pnpm build >"$LOG/console-build.log" 2>&1) || { tail -30 "$LOG/console-build.log"; exit 1; }
fi
PORT=$CONSOLE_PORT EDR_INGEST_URL="$EDR_IT_INGEST" setsid bash -c "cd '$ROOT/apps/web' && exec pnpm start" >"$LOG/console.log" 2>&1 & PIDS+=($!)
wait_http "http://localhost:$CONSOLE_PORT/login" console

FAILED=0
run() { node "$HERE/$1" || FAILED=1; }

step "4. 콘솔 로그인 · 등록키 발급"
run 01-enroll.mjs
step "5. 에이전트 3대 → 수집 서버"
run 02-agents.mjs
step "6. 탐지 실행 (enricher, pg_cron 대체 모드)"
export EDR_NOTIFY_SINK="$LOG/notify_sink.jsonl"; : >"$EDR_NOTIFY_SINK"
DATABASE_URL="$(dsn edr_enricher)" RUN_DETECTIONS=1 RUN_NOTIFIER=1 EDR_NOTIFY_SINK="$EDR_NOTIFY_SINK" setsid "$BIN/enricher" >"$LOG/enricher.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 30); do
  n=$(psql -X -At -d "$EDR_IT_DB" -c "select count(*) from detection_state where name in ('main', 'maintenance')")
  [ "$n" = "2" ] && break; sleep 1
done
psql -X -At -d "$EDR_IT_DB" -c "select '  경보 ' || count(*) || '건, 인시던트 ' || (select count(*) from incidents) || '건' from alerts"
step "7. 콘솔 화면 · 조사 · 권한 · 감사 기록"
run 03-console.mjs
step "8. 자산 · 보안 상태 · 소프트웨어 정책 · 위협 지표"
run 06-assets.mjs
step "8-2. 문서 감사 (정책 → 에이전트 → 결과 · 권한 · 감사 기록)"
run 08-docscan.mjs
step "8-3. PC 조치 목록 (계산 · 담당자·상태 · 권한 · 해결 확인)"
run 09-remediation.mjs
step "8-4. 알림 연동 (채널 설정 → 경보 → 슬랙·이메일·SIEM 발송 · 권한 · 감사)"
run 10-notify.mjs
step "8-5. Wazuh 경보 수집 (웹훅 → 경보 화면 출처 필터·배지)"
run 11-wazuh.mjs
step "9. 회사 계정(SSO) 로그인 — AD 그룹 → 역할 (Keycloak 흉내)"
run 05-sso.mjs
step "10. SSO 실험 구성 스위치 (lab.mjs on/off)"
run 07-sso-switch.mjs
step "11. 동시 전송 부하 (교착 상태 회귀 시험)"
run 04-load.mjs
DEADLOCKS=$(grep -c "deadlock detected" "$LOG/ingest.log" || true)
ERRS=$(grep -c '"level":"ERROR"' "$LOG/ingest.log" || true)
echo "  수집 서버 교착 ${DEADLOCKS}건, 오류 로그 ${ERRS}건"
[ "$DEADLOCKS" = "0" ] || FAILED=1

step "결과"
if [ "$FAILED" = "0" ]; then echo "✅ 통합 테스트 통과 (로그: $LOG)"; else echo "❌ 실패한 단계가 있습니다 (로그: $LOG)"; fi
exit $FAILED
