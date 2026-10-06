# 회사 계정(SSO) 실험 — 개인 PC 에서 AD + Keycloak 로 콘솔 로그인 해 보기

회사 AD 를 건드리지 않고, 개인 PC 의 Docker 안에 **테스트용 AD(도메인 `bing.test`, NetBIOS `BING`)** 와 **Keycloak** 을 띄워
콘솔의 "회사 계정으로 로그인" 흐름을 끝까지 시험한다. 회사로 옮길 때 바꿀 값은 §6.

```
브라우저 ─ 콘솔(localhost:3000) "회사 계정으로 로그인"
        ─ Supabase 로컬 Auth(127.0.0.1:54321)
        ─ Keycloak(host.docker.internal:8080, 렐름 bing) ── LDAP 읽기 ──▶ 테스트용 AD (Samba AD DC)
        ◀ 로그인 성공(AD 그룹이 담긴 groups 클레임)
        ─ DB 트리거가 AD 그룹 → 콘솔 역할로 구성원 등록 → 콘솔 화면
```

| AD 그룹 | 콘솔 역할 | 비고 |
|---|---|---|
| `EDR-Admins` | 관리자 | 로그인할 때 OTP(인증 앱) 필수, 처음이면 등록 화면 |
| `EDR-Analysts` | 분석가 | |
| `EDR-Viewers` | 열람자 | |
| (없음) | 접근 불가 | 로그인은 되지만 "권한이 없습니다" 안내 |

## 켜고 끄기 (한 줄)
실험 구성은 **기본으로 꺼져 있다**. 켜고 끄는 것은 스위치 스크립트 하나로 한다(저장소 루트에서).

```powershell
node deploy/sso-lab/lab.mjs status       # 지금 상태
node deploy/sso-lab/lab.mjs on           # 켜기: 테스트용 AD·Keycloak 실행 + Supabase 의 Keycloak 로그인 + 콘솔 버튼
node deploy/sso-lab/lab.mjs off          # 끄기: 위 세 가지를 끔(AD·Keycloak 데이터는 남아 다시 켜면 그대로)
node deploy/sso-lab/lab.mjs reset        # 끄고 AD·Keycloak 데이터까지 지움(OTP 등록도 초기화)
```

| 켜고 끄는 것 | 어디에 반영되나 | 반영 시점 |
|---|---|---|
| 테스트용 AD·Keycloak 컨테이너 | `docker compose -f deploy/sso-lab/docker-compose.yml` up / stop | 바로 |
| Supabase 로컬의 Keycloak 로그인 | 저장소 루트 `.env` 의 `SUPABASE_AUTH_EXTERNAL_KEYCLOAK_ENABLED` (→ `supabase/config.toml`) | Supabase 로컬 재시작 후. `--restart-supabase` 를 붙이면 스크립트가 다시 시작 |
| 콘솔의 "회사 계정으로 로그인" 버튼 | `apps/web/.env.local` 의 `NEXT_PUBLIC_SSO_*`, `SSO_LOGOUT_URL` | `pnpm dev` 는 바로, 운영 빌드는 다시 빌드 |

- 두 `.env` 파일에서는 `# >>> sso-lab` ~ `# <<< sso-lab` 구간만 고치고 나머지 줄은 건드리지 않는다. 두 파일 모두 커밋되지 않는다.
- `--no-docker` 를 붙이면 컨테이너는 그대로 두고 설정만 바꾼다(예: 컨테이너는 켜 둔 채 콘솔 버튼만 끄기).
- 꺼져 있어도 이메일·비밀번호 로그인은 그대로 된다. 이미 AD 그룹으로 가입된 구성원은 남아 있다(설정 → 구성원).

아래 0~4 단계는 처음 한 번 준비하는 절차와 직접 확인할 것이다.

## 0. 준비 (한 번만)
- Docker Desktop(WSL2), Node.js 22, pnpm. 메모리 16GB 권장(Supabase 로컬 2~3GB + Keycloak 1GB + AD 0.3GB).
- PowerShell 에서 `ping host.docker.internal` 이 응답하는지 확인한다.
  응답이 없으면 관리자 권한 메모장으로 `C:\Windows\System32\drivers\etc\hosts` 맨 아래에 `127.0.0.1 host.docker.internal` 를 추가한다.
  (브라우저와 Supabase(도커 안) 가 **같은 주소**로 Keycloak 을 봐야 로그인이 이어진다)

## 1. 테스트용 AD + Keycloak 띄우기
```powershell
cd C:\Develop\endpoint-edr
node deploy/sso-lab/lab.mjs on      # 컨테이너가 준비될 때까지 기다린 뒤 설정 파일 두 개를 켠다
```
- 처음에는 AD 를 만드느라 1~2분 걸리고, 그다음 Keycloak 이 뜬다(약 30초). 진행 상황: `docker compose -f deploy/sso-lab/docker-compose.yml logs -f ad`
- 테스트 사용자(비밀번호 모두 `Passw0rd!Lab`):

  | 아이디 | 이름 | AD 그룹 | 기대 결과 |
  |---|---|---|---|
  | `kim.admin` | 김관리 | EDR-Admins | 관리자, OTP 필요 |
  | `lee.analyst` | 이분석 | EDR-Analysts | 분석가 |
  | `park.viewer` | 박열람 | EDR-Viewers | 열람자 |
  | `choi.none` | 최무권한 | 없음 | 권한 없음 안내 |
  | `jung.locked` | 정잠김 | EDR-Analysts, **비활성** | Keycloak 에서 차단 |

- Keycloak 관리 화면: http://host.docker.internal:8080/admin → `lab-admin` / `Lab!Admin2026`
  → 왼쪽 위에서 렐름 **bing** 선택 → *User federation* → `bing-ad` → **Test connection**, **Test authentication** 이 모두 성공이면 AD 연결 정상.

## 2. Supabase 로컬 띄우기
1단계의 `on` 이 저장소 루트 `.env`(커밋되지 않음)에 Keycloak 로그인 켜기와 비밀값(`edr-console-lab-secret`)을 이미 넣어 두었다.
```powershell
npx supabase@latest start
```
- `supabase/migrations` 전체와 `supabase/seed.sql`(실험 조직 + AD 그룹 대응표)이 자동으로 들어간다.
- 출력되는 **API URL**(`http://127.0.0.1:54321`)과 **anon key** 를 다음 단계에서 쓴다.
- Supabase CLI 가 오래됐으면 최신으로(로그인한 사용자의 AD 그룹 정보 저장은 Supabase Auth v2.176 이상에서 동작).

## 3. 콘솔 띄우기
`apps\web\.env.local` (커밋되지 않음)에 Supabase 주소와 키를 넣는다. SSO 버튼 줄(`NEXT_PUBLIC_SSO_*`, `SSO_LOGOUT_URL`)은 `lab.mjs on` 이 넣고 `off` 가 뺀다.
```
NEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:54321
NEXT_PUBLIC_SUPABASE_ANON_KEY=<2단계 출력의 anon key>
EDR_DEMO=0
```
```powershell
cd apps\web
pnpm install
pnpm dev
```
http://localhost:3000 → **회사 계정으로 로그인** → Keycloak 화면에서 `lee.analyst` / `Passw0rd!Lab`.

## 4. 직접 확인할 것
1. `kim.admin` → 처음이면 OTP 등록 화면(휴대폰 인증 앱으로 QR 스캔) → 콘솔 왼쪽 아래에 **관리자**
2. **설정** → *회사 계정(AD) 연동* 표, 구성원 목록의 **AD 그룹** 표시, 감사 기록의 **AD 그룹으로 가입**
3. `choi.none` → "권한이 없습니다" 안내 → **다른 계정으로 로그인** 으로 Keycloak 세션까지 로그아웃
4. `jung.locked` → Keycloak 에 "계정이 비활성화되었습니다"
5. AD 에서 그룹을 바꾸고 다시 로그인하면 역할이 바뀌는지:
   ```powershell
   docker exec edr-lab-ad samba-tool group removemembers EDR-Analysts lee.analyst   # 분석가에서 빼기
   docker exec edr-lab-ad samba-tool group addmembers EDR-Viewers lee.analyst       # 열람자로 넣기
   docker exec edr-lab-ad samba-tool user disable park.viewer                       # 계정 잠그기
   ```
   → 해당 사용자로 다시 로그인(이미 로그인돼 있으면 로그아웃 후). 감사 기록에 **AD 그룹으로 역할 변경 / 접근 제거** 가 남는다.

### 자동 확인 스크립트
위 1·3·4 와 역할을 브라우저로 자동 확인한다(관리자 OTP 도 자동 입력).
```powershell
cd tests\integration
npm ci
npx playwright install chromium
node sso-lab-verify.mjs          # "통과 9, 실패 0" 이면 정상. 화면을 보려면 $env:HEADED="1"
```

## 5. 정리
```powershell
node deploy/sso-lab/lab.mjs off      # SSO 실험 끄기(AD·Keycloak 데이터 유지)
node deploy/sso-lab/lab.mjs reset    # 데이터까지 지우고 처음부터(OTP 등록도 초기화)
npx supabase stop                    # Supabase 로컬까지 끄려면
```

## 6. 회사 AD(bing.co.kr)로 옮길 때
실험실 설정 중 **그대로 쓰면 안 되는 것**과 바꿀 값:

| 항목 | 실험실 | 회사 |
|---|---|---|
| AD | Samba 컨테이너 `ldap://ad:389` | 회사 DC `ldaps://<DC 주소>:636` (단순 바인드는 반드시 LDAPS) |
| 서비스 계정 | `CN=svc-keycloak,CN=Users,DC=bing,DC=test` | IT 팀이 만든 읽기 전용 계정(예: `BING\svc-edr-ldap`)의 DN |
| 사용자 검색 위치 | `DC=bing,DC=test` | `DC=bing,DC=co,DC=kr` 또는 직원 OU |
| 권한 그룹 위치 | `OU=EDR,DC=bing,DC=test` | IT 팀이 만든 그룹 OU |
| Keycloak 주소 | `http://host.docker.internal:8080` | `https://sso.bing.co.kr` (사내 인증서), `LAB_SSL_REQUIRED=external` |
| Keycloak DB | 개발 모드(H2 파일) | `start` 모드 + PostgreSQL |
| 비밀값 | 고정 실험용 | 모두 새로 만들어 `.env` 로만 |
| 사용자 캐시 | `NO_CACHE`(그룹 변경 즉시 반영) | 그대로 또는 5분 정도의 `MAX_LIFESPAN` |

이 값들은 `deploy/sso-lab/keycloak/bing-realm.json` 의 `${LAB_...}` 자리에 환경 변수로 넣으면 된다.

**Windows 자동 로그인(Kerberos)** — 실험실에서는 꺼 둠(개인 PC 는 도메인 가입이 아니라 시험 불가). 회사에서 켜려면:
1. IT 팀: 서비스 계정에 SPN 등록 `setspn -S HTTP/sso.bing.co.kr BING\svc-edr-ldap`, keytab 발급(`ktpass`)
2. Keycloak: `bing-ad` 에서 *Allow Kerberos authentication* 켜고 Kerberos realm `BING.CO.KR`, principal `HTTP/sso.bing.co.kr@BING.CO.KR`, keytab 경로 지정 → `edr-browser` 흐름의 *Kerberos* 를 **ALTERNATIVE** 로
3. GPO: `https://sso.bing.co.kr` 를 로컬 인트라넷 영역에, Edge·Chrome 의 `AuthServerAllowlist` 에 추가
→ 도메인 PC 에서는 비밀번호 창 없이 바로 콘솔로 들어가고, 그 밖에서는 지금처럼 아이디·비밀번호 화면이 뜬다.

**Supabase 클라우드를 쓸 때** — 로그인 중 Supabase 서버가 Keycloak 에 직접 접속하므로 Keycloak 이 인터넷에서 보여야 한다.
사내 인증 서버를 밖에 여는 것이 되므로, 회사 적용은 Supabase 를 사내 서버에 설치하는 쪽을 권장한다(`docs/ARCHITECTURE.md` §7-2).

## 문제가 생기면
| 증상 | 확인 |
|---|---|
| 버튼을 눌렀는데 `host.docker.internal` 접속 불가 | §0 hosts 파일, `docker ps` 로 `edr-lab-keycloak` 실행 중인지 |
| Keycloak 에 "Invalid parameter: redirect_uri" | Supabase API URL 이 `127.0.0.1:54321` 또는 `localhost:54321` 인지(렐름 json 의 redirectUris) |
| 로그인 화면에 회사 계정 버튼이 없음 | `node deploy/sso-lab/lab.mjs status` — 콘솔 버튼이 꺼짐이면 `on`. 운영 빌드면 다시 빌드 |
| 버튼을 누르면 "Unsupported provider" | Supabase 쪽이 꺼져 있음 → `lab.mjs on --restart-supabase` (`.env` 를 바꾼 뒤 Supabase 를 다시 시작해야 반영) |
| 로그인 후 콘솔 대신 "회사 계정 로그인이 완료되지 않았습니다" | `npx supabase status` 로 Auth 가 떠 있는지, `.env` 의 비밀값이 `edr-console-lab-secret` 인지 |
| 로그인은 되는데 모두 "권한이 없습니다" | Supabase CLI 를 최신으로(그룹 정보 저장), `supabase/seed.sql` 이 들어갔는지(설정 → 회사 계정(AD) 연동 표) |
| Keycloak 사용자 목록이 비어 있음 | 정상 — 처음 로그인할 때 AD 에서 읽어 온다. *User federation → Sync all users* 로 미리 가져올 수도 있음 |
| AD 컨테이너가 계속 재시작 | `docker compose ... logs ad` — 처음 만들 때 오류면 `down -v` 후 다시 `up` |
