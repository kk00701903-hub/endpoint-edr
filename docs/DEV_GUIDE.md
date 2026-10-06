# 개발·운영 가이드 — Claude 개발 + Cursor 커밋·빌드·푸시

## 역할 분담

| 누가 | 어디서 | 하는 일 |
|---|---|---|
| **Claude** | Claude 앱 (PC 의 `C:\Develop\endpoint-edr` 폴더 연결) | 설계, 코드 작성·수정, 검증(크로스 컴파일·vet·가드레일·DB 테스트), `docs/work-log.md` 기록, 커밋 메시지 제안 |
| **사용자** | Cursor | 변경 확인(diff) → 빌드(`scripts\build.ps1`) → 커밋 → 푸시 |
| **사용자** | 서버·테스트 PC | Supabase 설정, Docker 기동, 에이전트 설치·실기 확인 (Claude 가 절차 안내) |

Claude 가 따르는 규칙은 저장소 루트의 `CLAUDE.md` 에 있다. 규칙을 바꾸고 싶으면 Claude 에게 "CLAUDE.md 에 ○○ 규칙 추가해줘"라고 하면 된다.

> Cursor 의 AI 기능(Composer/Agent, 자동 수정)으로는 코드를 고치지 않는다. Claude 가 작업 중인 파일과 엇갈리면 어느 쪽이 최신인지 꼬인다.
> Cursor 는 Git 클라이언트 + 터미널로만 쓴다.

---

## 0단계. 준비물 (모두 무료)

| 도구 | 용도 | 설치 확인 |
|---|---|---|
| Go 1.23 이상 | 에이전트·서버 빌드 | `go version` |
| Git for Windows | 커밋·푸시, 빌드 스크립트의 가드레일 검사(bash) | `git --version` |
| Cursor | 변경 확인·커밋·빌드·푸시 | — |
| Docker Desktop | 서버 실행, 로컬 Supabase | `docker version` |
| Node.js 20 LTS 이상 + pnpm | Supabase CLI, 관리 콘솔 | `node -v`, `pnpm -v` |
| Windows 테스트 VM | 에이전트 시험 (실사용 PC 말고 VM 권장) | Hyper-V / VirtualBox |

---

## 1단계. Claude 에게 작업 요청하기

1. Claude 앱에서 이 대화처럼 `C:\Develop\endpoint-edr` 폴더를 연결한 상태로 요청한다.
2. 요청은 **한 번에 한 기능**, 범위를 분명하게:
   ```
   [무엇을] 탐지 규칙 EDR-NET-002 추가 — 같은 프로세스가 10분 안에 서로 다른 공인 IP 50개 이상에 접속하면 high
   [범위]   새 마이그레이션 + 테스트 + ARCHITECTURE.md 규칙표만. 다른 파일은 건드리지 마.
   ```
3. Claude 는 작업이 끝나면 다음을 보고한다.
   - 바꾼 파일 목록
   - 검증 결과 (통과 / 미검증 항목과 이유)
   - 제안 커밋 메시지 한 줄
   - 사용자가 직접 확인해야 할 것 (예: 테스트 VM 에서 `edr-agent.exe console` 실행)
4. 작업 기록은 `docs/work-log.md` 에 자동으로 쌓인다.

---

## 2단계. Cursor 에서 할 일 — 확인 → 빌드 → 커밋 → 푸시

Claude 가 "완료"라고 보고한 뒤에 진행한다(작업 도중 커밋하지 않기).

### ① 변경 확인
Source Control 패널(`Ctrl+Shift+G`)에서 Claude 가 보고한 파일만 바뀌었는지, diff 를 훑어본다.
특히 `agent/` 에 새 Windows API 호출이 생겼으면 권한 플래그를 한 번 더 본다.

### ② 빌드
Cursor 터미널(PowerShell)에서:
```powershell
.\scripts\build.ps1          # 처음이거나 의존성이 바뀌었으면: .\scripts\build.ps1 -Tidy
```
이 스크립트가 하는 일:
1. 읽기 전용 가드레일 검사(`scripts/check-passive.sh`, Git Bash 사용) — 실패하면 중단
2. `go mod tidy` (처음 1회 또는 `-Tidy`) — `go.sum` 생성/갱신
3. 에이전트 빌드 → `agent\dist\edr-agent-amd64.exe`, `edr-agent-arm64.exe` + `go vet`
4. 서버(ingest·enricher) 컴파일 확인 + `go vet`
5. 관리 콘솔 `pnpm install` → `pnpm lint` → `pnpm build` (pnpm 이 있을 때)

`go.sum` 이 새로 생기거나 바뀌면 그 파일도 같이 커밋한다. `dist\` 의 exe 는 커밋하지 않는다(`.gitignore` 처리됨).

PowerShell 실행 정책 때문에 막히면 한 번만: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### ③ 커밋
Claude 가 제안한 커밋 메시지를 그대로 쓰거나 다듬어서 커밋한다.

### ④ 푸시
`git push` (또는 Cursor 의 Sync 버튼).

### ⑤ 자동 검증(CI) 결과 확인
푸시하면 GitHub 의 **Actions** 탭에서 `ci` 가 자동으로 돈다(약 10분).
- 에이전트: 수동형 가드레일 + Windows 빌드(amd64·arm64)
- 서버: gofmt·vet·빌드
- 콘솔: lint·타입 검사·빌드
- 종단 통합 테스트: 테스트용 PostgreSQL 에 마이그레이션 전체 적용 → SQL 테스트 → 콘솔 등록키 발급 → 에이전트 흉내 3대 전송 → 탐지·인시던트 → 콘솔 조사·권한·감사 기록 → 150대 동시 전송 부하(`tests/integration/README.md`)

빨간색(실패)이면 실패한 단계의 로그를 복사해 Claude 에게 "CI 실패, 고쳐줘"라고 보내면 된다. 통합 테스트가 실패하면 `integration-logs` 아티팩트에 서버 로그가 남는다.

### 빌드가 실패하면
터미널 출력 전체를 복사해 Claude 에게 붙여 넣고 "빌드 실패, 고쳐줘"라고 하면 된다. Claude 가 고친 뒤 ② 부터 다시.

---

## 3단계. Supabase 준비 (최초 1회)

> DB 를 Supabase Cloud 에 둘지, 사내 서버에 셀프호스팅할지 먼저 정한다 (`docs/ARCHITECTURE.md` §7-2).

### 클라우드
1. supabase.com 에서 프로젝트 생성.
2. 터미널:
   ```bash
   npx supabase login
   npx supabase link --project-ref <프로젝트ref>
   npx supabase db push            # supabase/migrations/*.sql 적용
   ```
3. `db push` 출력에 "pg_cron 을 사용할 수 없습니다" 안내가 나왔다면: 대시보드 → Database → Extensions 에서 **pg_cron** 을
   활성화한 뒤 SQL Editor 에서 아래 두 줄을 실행.
   ```sql
   select cron.schedule('edr-detections',  '* * * * *',  'select public.edr_run_detections()');
   select cron.schedule('edr-maintenance', '10 0 * * *', 'select public.edr_maintenance()');
   ```
   확인: `select jobname, schedule from cron.job;` 에 edr-detections / edr-maintenance 2개
   (0006 이전에 만든 edr-partitions / edr-retention 은 0006 적용 시 edr-maintenance 하나로 바뀐다).
   pg_cron 을 끝내 쓸 수 없으면 `deploy/.env` 에 `RUN_DETECTIONS=1` — enricher 가 탐지(1분)와 파티션·보존 작업(6시간)을 대신 실행한다.
   어느 쪽이든 콘솔 **설정 → 시스템 상태**에서 마지막 실행 시각과 파티션 남은 기간을 확인할 수 있다.
4. SQL Editor 에서 서비스용 역할 비밀번호 설정:
   ```sql
   alter role edr_ingest     with login password '긴-무작위-문자열';
   alter role edr_enricher   with login password '...';
   alter role grafana_reader with login password '...';
   ```
5. 회사 조직과 관리자 연결(대시보드 Authentication 에서 사용자 하나 만든 뒤):
   ```sql
   insert into tenants (name) values ('우리회사') returning id;
   insert into tenant_members values ('<위 id>', '<auth 사용자 id>', 'owner');
   ```

### 로컬(개발용)
```bash
npx supabase start          # Docker 로 로컬 Supabase 기동, 마이그레이션 자동 적용
psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" -f supabase/tests/rls_and_detection_test.sql
```
테스트는 트랜잭션 안에서 실행 후 롤백되므로 데이터가 남지 않는다. `OK:` 줄만 나오고 `FAIL`·`ERROR` 가 없으면 정상.

전체 구간(DB → 수집 → 탐지 → 콘솔)을 한 번에 시험하려면 `tests/integration/README.md` 의 `run.sh` 를 쓴다(테스트 전용 DB 필요, CI 에서도 같은 스크립트가 돈다).

---

## 4단계. 서버 기동 (Docker)

```bash
cd deploy
cp .env.example .env         # 값 채우기 (도메인, DB 접속, 비밀번호)
docker compose up -d --build
docker compose logs -f ingest
```
- 사내망 전용이면 `deploy/Caddyfile` 상단 주석대로 사내 인증서를 지정한다.
- 시험만 할 때는 `ingest` 에 `ports: ["8080:8080"]` 을 임시로 추가해 `http://<서버 IP>:8080` 으로 붙여도 된다(운영은 반드시 HTTPS).
- Grafana: `https://<GRAFANA_DOMAIN>` → `EDR` 폴더의 "EDR 보안 현황" 대시보드, 알림 규칙 2개가 자동 등록된다.

---

## 5단계. 에이전트 설치 (테스트 VM)

1. 등록키 발급 — 관리 콘솔 **설정 → 등록키 만들기** 가 가장 쉽다. 콘솔을 아직 안 띄웠으면 SQL Editor 에서:
   ```sql
   -- SQL Editor 는 로그인 사용자 컨텍스트가 없으므로, 한 트랜잭션 안에서 owner 사용자로 지정한 뒤 호출
   begin;
   select set_config('request.jwt.claim.sub', '<owner 사용자 id>', true);
   select public.create_enrollment_key('<tenant id>', '테스트 VM');
   commit;
   ```
   → `edr_enr_...` 평문 키는 이때 한 번만 보인다.
2. 먼저 서버 없이 점검: VM 에 `edr-agent-amd64.exe` 를 복사하고 관리자 PowerShell 에서
   `.\edr-agent-amd64.exe console > sample.json` — 1회 수집 결과만 출력하고 전송은 하지 않는다.
   CPU·메모리가 튀지 않는지, Escort 등 기존 보안 솔루션이 경고를 띄우지 않는지 같이 본다.
3. 배치:
   ```
   C:\Program Files\EndpointEDR\edr-agent.exe
   C:\ProgramData\EndpointEDR\config.json   ← agent/packaging/config.example.json 을 복사해 ingest_url, enrollment_key 입력
   ```
4. 관리자 PowerShell:
   ```powershell
   & "C:\Program Files\EndpointEDR\edr-agent.exe" install
   Start-Service EndpointEDRAgent
   ```
5. 1~2분 뒤 Grafana "에이전트 상태" 패널에 PC 가 보이면 성공. 시험: 다른 PC 에서 틀린 비밀번호로 RDP 10회 → `EDR-AUTH-001` 경보.

실기 결과(이상 동작, 오탐, `sample.json` 일부)를 Claude 에게 전달하면 그걸 기준으로 고친다.

---

## 6단계. 관리 콘솔(Next.js) 실행

콘솔 코드는 `apps/web` 에 있습니다. 화면 구성은 `docs/ARCHITECTURE.md` §9.

### 화면만 먼저 보기 (예시 데이터, Supabase 불필요)
```powershell
cd apps\web
pnpm install
$env:EDR_DEMO="1"; pnpm dev        # http://localhost:3000 — 로그인 없이 예시 데이터로 모든 화면 확인
```
예시 데이터에는 "외부에서 RDP 무차별 대입 → 로그인 성공 → 계정 생성 → 자동 실행 등록 → 악성 파일 실행 → 로그 삭제"로 이어지는
사건이 SRV-WEB-01 에 들어 있습니다. **인시던트 → "다단계 공격 의심: SRV-WEB-01 외"** 를 열면 자동 요약과 공격 그래프를 볼 수 있고,
그래프의 노드·엔터티에서 IP/해시 프로필, 헌팅 쿼리로 이어서 조사해 볼 수 있습니다.
예시 모드에서 바꾼 내용(경보 처리 등)은 서버를 다시 켜면 처음 상태로 돌아갑니다.

### 실제 데이터로 실행
1. `apps\web\.env.example` 을 `.env.local` 로 복사하고 Supabase URL·anon 키 입력 (`EDR_DEMO=0`).
2. Supabase 대시보드 Authentication 에서 보안 담당자 계정을 만들고 `tenant_members` 에 역할과 함께 추가(3단계 5번).
3. `pnpm dev` 로 확인 → 운영은 `deploy/docker-compose.yml` 의 `console` 서비스(`CONSOLE_DOMAIN`)로 띄웁니다.
4. 새 경보 실시간 알림을 쓰려면 Supabase 대시보드 Database → Replication 에서 `alerts` 가 `supabase_realtime` 에 포함됐는지 확인(마이그레이션이 자동 추가).

### 회사 계정(AD)으로 로그인 (선택)
AD 그룹으로 콘솔 역할을 정하는 SSO 는 개인 PC 에서 먼저 시험한다: **`docs/SSO_LAB.md`** (테스트용 AD + Keycloak + Supabase 로컬).
`.env.local` 에 `NEXT_PUBLIC_SSO_PROVIDER=keycloak` 이 있을 때만 로그인 화면에 "회사 계정으로 로그인" 버튼이 생긴다.
실험 구성은 기본으로 꺼져 있고, `node deploy/sso-lab/lab.mjs on | off | status` 한 줄로 컨테이너·Supabase 설정·콘솔 버튼을 함께 켜고 끈다.

### 역할별로 할 수 있는 일
| 역할 | 할 수 있는 일 |
|---|---|
| 열람자 | 모든 화면 보기 |
| 분석가 | + 경보 확인·종결·메모, 예외 만들기 |
| 관리자 | + 규칙 켜기/끄기, 예외 지우기, 등록키 발급·폐기 |
| 소유자 | + 구성원 관리 |

## 7단계. 자주 쓰는 요청 예시

**탐지 규칙 추가**
```
새 마이그레이션으로 규칙 EDR-NET-002 추가: 같은 프로세스가 10분 내 서로 다른 공인 IP 50개 이상에
outbound 연결, severity high, dedup_key 는 장치+프로세스+시(hour). 테스트와 ARCHITECTURE.md 규칙표도 갱신.
```

**콘솔 화면 개선**
```
장치 상세에 "최근 7일 로그온 기록" 탭 추가: 4624/4625 를 계정·출발지별로 묶어서 보여줘.
DataSource 계약에 메서드를 추가하고 supabase-source·demo-source 둘 다 구현, 데모 데이터로 화면 확인까지.
```

**에이전트 수집 항목 추가**
```
Sysmon 이 설치된 PC 에서만 Microsoft-Windows-Sysmon/Operational 의 EventID 1,3,11,13 을 읽도록 추가.
채널이 없으면 조용히 건너뛰기. 읽기 전용 규칙 지키고 vet·가드레일 검증까지.
```

**전송 필드 추가**
```
Process 에 signer(서명자) 필드 추가. 서명 검증 결과는 해시 캐시와 같은 키로 캐시.
데이터 계약 관련 파일 전부와 새 마이그레이션(process_events.signer)까지.
```

**오탐 줄이기**
```
EDR-PERSIST-002 경보 중 이 목록(붙여넣기)은 정상 업데이트 프로그램이다. 예외 처리 방법을 제안하고, 내가 고르면 적용해줘.
```

---

## 8단계(선택). 콘솔이 커질 때 모노레포 전환

콘솔 코드가 늘면 pnpm 워크스페이스 + Turborepo(MIT)로 묶을 수 있다. 필요해지면 Claude 에게
"pnpm+turborepo 모노레포로 전환해줘. Go 디렉터리는 옮기지 말고 apps/web 만 정리해"라고 요청한다.
```
endpoint-edr/
├─ pnpm-workspace.yaml      # packages: ["apps/*", "packages/*"]
├─ turbo.json
├─ apps/web/                # 관리 콘솔 (Next.js)
├─ packages/
│  ├─ contracts/            # ingest.schema.json → zod 스키마/TS 타입 자동 생성
│  └─ db-types/             # supabase gen types 결과
├─ agent/  services/  supabase/  deploy/   # Go·SQL 은 그대로
```
