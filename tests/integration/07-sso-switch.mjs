// 7단계: SSO 실험 구성 스위치(deploy/sso-lab/lab.mjs) — 임시 폴더에 저장소 흉내를 만들고 docker 대신 기록용 가짜 명령으로 시험한다.
//   on  → 컨테이너 실행 후 .env(Supabase Keycloak 켜기)·apps/web/.env.local(콘솔 버튼) 구간을 넣는다. 다른 줄·CRLF·사용자 비밀값은 그대로
//   off → 구간을 빼거나 끄고 컨테이너를 멈춘다(데이터 유지) / reset → down -v / docker 실패 시 설정 파일을 바꾸지 않는다
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { done, expect } from "./lib.mjs";

const LAB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../deploy/sso-lab/lab.mjs");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "edr-lab-"));
fs.mkdirSync(path.join(root, "apps/web"), { recursive: true });
fs.writeFileSync(path.join(root, "apps/web/.env.local"), "NEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:54321\r\nNEXT_PUBLIC_SSO_PROVIDER=keycloak\r\nEDR_DEMO=0\r\n");
fs.writeFileSync(path.join(root, ".env"), "SUPABASE_AUTH_EXTERNAL_KEYCLOAK_SECRET=my-own-secret\nOTHER=1\n");
// 가짜 docker: 받은 인자를 기록하고, up/stop 에 따라 ps 결과를 바꾼다. FAIL_UP=1 이면 up 실패
const fake = path.join(root, "fake-docker.mjs");
fs.writeFileSync(fake, `#!/usr/bin/env node
import fs from "node:fs";
const dir = ${JSON.stringify(root)}, a = process.argv.slice(2).join(" ");
fs.appendFileSync(dir + "/docker.log", a + "\\n");
if (a.includes(" up ") && process.env.FAIL_UP) { console.error("daemon not running"); process.exit(1); }
if (a.includes(" up ")) fs.writeFileSync(dir + "/up", "");
if (a.includes(" stop") || a.includes(" down")) fs.rmSync(dir + "/up", { force: true });
if (a.includes("ps --all") && fs.existsSync(dir + "/up")) console.log("ad\\trunning\\thealthy\\nkeycloak\\trunning\\t");
`);
fs.chmodSync(fake, 0o755);
const env = { ...process.env, EDR_LAB_ROOT: root, EDR_LAB_DOCKER: fake };
const lab = (...args) => spawnSync(process.execPath, [LAB, ...args], { env, encoding: "utf8" });
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");
const dockerLog = () => (fs.existsSync(path.join(root, "docker.log")) ? read("docker.log") : "");

try {
  let r = lab("status");
  expect("status: 일부만 켜짐 감지", r.status === 0 && r.stdout.includes("일부만 켜짐"), r.stdout.split("\n").at(-2));

  r = spawnSync(process.execPath, [LAB, "on"], { env: { ...env, FAIL_UP: "1" }, encoding: "utf8" });
  expect("on: docker 실패 시 설정 파일 그대로", r.status === 1 && !read(".env").includes(">>> sso-lab") && r.stderr.includes("Docker Desktop"));

  r = lab("on");
  const web = read("apps/web/.env.local"), dot = read(".env");
  expect("on: 컨테이너 실행(--wait)", dockerLog().includes("compose -f " + path.join(root, "deploy/sso-lab/docker-compose.yml") + " up -d --build --wait"));
  expect("on: Supabase Keycloak 켜기 + 사용자 비밀값 유지", dot.includes("SUPABASE_AUTH_EXTERNAL_KEYCLOAK_ENABLED=true") && dot.includes("SUPABASE_AUTH_EXTERNAL_KEYCLOAK_SECRET=my-own-secret") && dot.includes("OTHER=1") && dot.split("KEYCLOAK_SECRET").length === 2);
  expect("on: 콘솔 버튼 구간(CRLF 유지, 중복 없음)", web.includes("NEXT_PUBLIC_SSO_PROVIDER=keycloak\r\n") && web.split("NEXT_PUBLIC_SSO_PROVIDER").length === 2 && web.includes("SSO_LOGOUT_URL=") && web.includes("EDR_DEMO=0\r\n"));
  expect("on: 상태 켜짐", r.stdout.includes("→ 켜짐"));
  lab("on", "--no-docker");
  expect("on 두 번: 구간 하나", read(".env").split(">>> sso-lab").length === 2 && read("apps/web/.env.local").split(">>> sso-lab").length === 2);

  r = lab("off");
  expect("off: 콘솔 버튼 빼고 Supabase 끄고 컨테이너 멈춤", !read("apps/web/.env.local").includes("NEXT_PUBLIC_SSO") && read("apps/web/.env.local").includes("NEXT_PUBLIC_SUPABASE_URL")
    && read(".env").includes("SUPABASE_AUTH_EXTERNAL_KEYCLOAK_ENABLED=false") && dockerLog().trim().split("\n").some((l) => l.endsWith(" stop")) && r.stdout.includes("→ 꺼짐"));
  r = lab("reset");
  expect("reset: 데이터까지 삭제(down -v)", dockerLog().includes(" down -v") && r.status === 0);
  expect("알 수 없는 명령 → 사용법(종료 코드 2)", lab("xyz").status === 2);
} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
} finally {
  // config.toml 기본값은 꺼짐(켜기는 .env 의 환경 변수로)
  const cfg = fs.readFileSync(path.resolve(path.dirname(LAB), "../../supabase/config.toml"), "utf8");
  expect("supabase/config.toml: Keycloak 기본 꺼짐", /\[auth\.external\.keycloak\]\s*\nenabled = false/.test(cfg));
  fs.rmSync(root, { recursive: true, force: true });
  done("07 SSO 실험 구성 스위치");
}
