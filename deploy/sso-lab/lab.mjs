#!/usr/bin/env node
// 회사 계정(SSO) 실험 구성 스위치 — 개인 PC 에서 한 줄로 켜고 끈다.
//
//   node deploy/sso-lab/lab.mjs status     지금 상태 보기
//   node deploy/sso-lab/lab.mjs on         테스트용 AD·Keycloak 실행 + Supabase 로컬의 Keycloak 로그인 켜기 + 콘솔 버튼 켜기
//   node deploy/sso-lab/lab.mjs off        위 세 가지를 끈다(AD·Keycloak 데이터는 남김 → 다시 켜면 그대로)
//   node deploy/sso-lab/lab.mjs reset      끄고 AD·Keycloak 데이터까지 지운다(처음부터 다시, OTP 등록도 초기화)
//
// 옵션
//   --no-docker          AD·Keycloak 컨테이너는 건드리지 않고 설정 파일만 바꾼다
//   --restart-supabase   Supabase 로컬을 다시 시작해 바로 반영한다(npx supabase stop → start)
//
// 바꾸는 파일 (둘 다 커밋되지 않는 파일. 이 스크립트가 관리하는 구간만 고치고 나머지 줄은 그대로 둔다)
//   .env                 SUPABASE_AUTH_EXTERNAL_KEYCLOAK_ENABLED / _SECRET  → supabase/config.toml 의 [auth.external.keycloak] 를 켜고 끈다
//   apps/web/.env.local  NEXT_PUBLIC_SSO_PROVIDER / _LABEL / SSO_LOGOUT_URL → 콘솔 로그인 화면의 "회사 계정으로 로그인" 버튼
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = process.env.EDR_LAB_ROOT ? path.resolve(process.env.EDR_LAB_ROOT) : path.resolve(HERE, "../..");
const COMPOSE = path.join(ROOT, "deploy/sso-lab/docker-compose.yml");
const DOCKER = process.env.EDR_LAB_DOCKER || "docker";
const ROOT_ENV = path.join(ROOT, ".env");
const WEB_ENV = path.join(ROOT, "apps/web/.env.local");

const BEGIN = "# >>> sso-lab (node deploy/sso-lab/lab.mjs 가 관리하는 구간 — 켜고 끄기는 이 스크립트로)";
const END = "# <<< sso-lab";
const DEFAULT_SECRET = "edr-console-lab-secret";
const LOGOUT_URL = "http://host.docker.internal:8080/realms/bing/protocol/openid-connect/logout?client_id=edr-console&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Flogin";

const ROOT_KEYS = ["SUPABASE_AUTH_EXTERNAL_KEYCLOAK_ENABLED", "SUPABASE_AUTH_EXTERNAL_KEYCLOAK_SECRET"];
const WEB_KEYS = ["NEXT_PUBLIC_SSO_PROVIDER", "NEXT_PUBLIC_SSO_LABEL", "SSO_LOGOUT_URL"];

// ---------------- .env 파일 다루기 ----------------

/** 파일을 읽어 { eol, lines } 로. 없으면 빈 파일 */
function readEnv(file) {
  if (!fs.existsSync(file)) return { eol: process.platform === "win32" ? "\r\n" : "\n", lines: [], exists: false };
  const text = fs.readFileSync(file, "utf8");
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.split(/\r?\n/);
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  return { eol, lines, exists: true };
}

const keyOf = (line) => {
  const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
  return m ? m[1] : null;
};
const valueOf = (line) => line.slice(line.indexOf("=") + 1).trim().replace(/^(['"])(.*)\1$/, "$2");

/** 관리 구간을 뺀 나머지 줄 + 관리 구간 밖에 직접 적어 둔 같은 키(예전 안내대로 손으로 넣은 줄)의 값 */
function split(lines, keys) {
  const rest = [];
  const found = {};
  let inside = false;
  for (const l of lines) {
    if (l.startsWith("# >>> sso-lab")) { inside = true; continue; }
    if (l.startsWith(END)) { inside = false; continue; }
    const k = keyOf(l);
    if (k && keys.includes(k)) { if (!inside || !(k in found)) found[k] = valueOf(l); continue; }
    if (!inside) rest.push(l);
  }
  while (rest.length && rest[rest.length - 1].trim() === "") rest.pop();
  return { rest, found };
}

function writeEnv(file, keys, block) {
  const { eol, lines } = readEnv(file);
  const { rest } = split(lines, keys);
  const out = [...rest];
  if (block.length) {
    if (out.length) out.push("");
    out.push(BEGIN, ...block, END);
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, out.length ? out.join(eol) + eol : "");
}

function current() {
  const r = split(readEnv(ROOT_ENV).lines, ROOT_KEYS).found;
  const webFile = readEnv(WEB_ENV);
  const w = split(webFile.lines, WEB_KEYS).found;
  return {
    supabase: String(r.SUPABASE_AUTH_EXTERNAL_KEYCLOAK_ENABLED ?? "").toLowerCase() === "true",
    secret: r.SUPABASE_AUTH_EXTERNAL_KEYCLOAK_SECRET,
    console: !!w.NEXT_PUBLIC_SSO_PROVIDER,
    label: w.NEXT_PUBLIC_SSO_LABEL,
    webEnvExists: webFile.exists,
    webHasSupabaseUrl: webFile.lines.some((l) => keyOf(l) === "NEXT_PUBLIC_SUPABASE_URL"),
  };
}

function setFiles(on) {
  const cur = current();
  // 사용자가 비밀값을 바꿔 두었으면 그 값을 유지한다(Keycloak 쪽 LAB_CONSOLE_CLIENT_SECRET 과 같아야 함)
  const secret = cur.secret || DEFAULT_SECRET;
  writeEnv(ROOT_ENV, ROOT_KEYS, [
    `SUPABASE_AUTH_EXTERNAL_KEYCLOAK_ENABLED=${on ? "true" : "false"}`,
    `SUPABASE_AUTH_EXTERNAL_KEYCLOAK_SECRET=${secret}`,
  ]);
  writeEnv(WEB_ENV, WEB_KEYS, on ? [
    "NEXT_PUBLIC_SSO_PROVIDER=keycloak",
    `NEXT_PUBLIC_SSO_LABEL=${cur.label || "회사 계정으로 로그인"}`,
    `SSO_LOGOUT_URL=${LOGOUT_URL}`,
  ] : []);
}

// ---------------- 외부 명령 ----------------

function run(cmd, args, { quiet = false } = {}) {
  const r = spawnSync(cmd, args, {
    cwd: ROOT,
    stdio: quiet ? "pipe" : "inherit",
    encoding: "utf8",
    shell: process.platform === "win32" && cmd === "npx", // npx 는 Windows 에서 npx.cmd
  });
  if (r.error) return { ok: false, out: "", err: r.error.code === "ENOENT" ? `${cmd} 를 찾을 수 없습니다` : String(r.error) };
  return { ok: r.status === 0, out: r.stdout ?? "", err: r.stderr ?? "" };
}

function docker(args, opts) {
  return run(DOCKER, ["compose", "-f", COMPOSE, ...args], opts);
}

function dockerState() {
  const r = docker(["ps", "--all", "--format", "{{.Service}}\t{{.State}}\t{{.Health}}"], { quiet: true });
  if (!r.ok) return { ok: false, text: r.err.trim().split("\n")[0] || "docker 상태를 읽지 못했습니다" };
  const rows = r.out.trim().split("\n").filter(Boolean).map((l) => l.split("\t"));
  if (!rows.length) return { ok: true, running: false, text: "컨테이너 없음" };
  const running = rows.length >= 2 && rows.every(([, s]) => s === "running");
  return { ok: true, running, text: rows.map(([svc, s, h]) => `${svc} ${s}${h ? `(${h})` : ""}`).join(", ") };
}

// ---------------- 명령 ----------------

const ON = "켜짐", OFF = "꺼짐";
const args = process.argv.slice(2);
const cmd = args.find((a) => !a.startsWith("--")) ?? "status";
const noDocker = args.includes("--no-docker");
const restartSupabase = args.includes("--restart-supabase");

function printStatus() {
  const c = current();
  const d = noDocker ? null : dockerState();
  console.log("회사 계정(SSO) 실험 구성");
  console.log(`  콘솔 로그인 버튼       ${c.console ? ON : OFF}   (apps/web/.env.local)`);
  console.log(`  Supabase Keycloak 로그인 ${c.supabase ? ON : OFF}   (.env → supabase/config.toml)`);
  if (d) console.log(`  테스트용 AD·Keycloak   ${d.ok ? (d.running ? ON : OFF) : "알 수 없음"}   (${d.text})`);
  const all = [c.console, c.supabase, ...(d && d.ok ? [d.running] : [])];
  const summary = all.every(Boolean) ? "켜짐" : all.some(Boolean) ? "일부만 켜짐 — `on` 또는 `off` 를 다시 실행하세요" : "꺼짐";
  console.log(`  → ${summary}`);
  return c;
}

function nextSteps(on) {
  const c = current();
  console.log("");
  if (on && (!c.webEnvExists || !c.webHasSupabaseUrl)) {
    console.log("! apps/web/.env.local 에 NEXT_PUBLIC_SUPABASE_URL·NEXT_PUBLIC_SUPABASE_ANON_KEY 가 없습니다. docs/SSO_LAB.md 3단계를 보고 넣으세요.");
  }
  if (!restartSupabase) {
    console.log(`- Supabase 로컬이 켜져 있으면 다시 시작해야 반영됩니다: npx supabase stop && npx supabase start`);
    console.log(`  (또는 이 명령에 --restart-supabase 를 붙여 실행)`);
  }
  console.log(`- 콘솔(pnpm dev)은 .env.local 변경을 스스로 다시 읽습니다. 운영 빌드(pnpm build)는 다시 빌드해야 버튼이 ${on ? "나타납니다" : "사라집니다"}.`);
  if (on) console.log("- 확인: http://localhost:3000 → '회사 계정으로 로그인' → lee.analyst / Passw0rd!Lab   (자동 확인: cd tests/integration && node sso-lab-verify.mjs)");
}

function restart() {
  if (!restartSupabase) return true;
  console.log("\nSupabase 로컬을 다시 시작합니다(데이터는 유지)...");
  run("npx", ["supabase", "stop"]);
  return run("npx", ["supabase", "start"]).ok;
}

let exit = 0;
switch (cmd) {
  case "status":
    printStatus();
    break;
  case "on": {
    if (!noDocker) {
      console.log("테스트용 AD·Keycloak 을 띄웁니다(처음에는 AD 를 만드느라 1~2분)...");
      const r = docker(["up", "-d", "--build", "--wait"]);
      if (!r.ok) {
        console.error(`\n컨테이너를 띄우지 못했습니다${r.err ? `: ${r.err}` : ""}. Docker Desktop 이 켜져 있는지 확인하세요. 설정 파일은 바꾸지 않았습니다.`);
        exit = 1;
        break;
      }
    }
    setFiles(true);
    if (!restart()) exit = 1;
    console.log("");
    printStatus();
    nextSteps(true);
    break;
  }
  case "off":
  case "reset": {
    setFiles(false);
    if (!noDocker) {
      const r = cmd === "reset" ? docker(["down", "-v"]) : docker(["stop"]);
      if (!r.ok) { console.error(`\n컨테이너를 멈추지 못했습니다${r.err ? `: ${r.err}` : ""}`); exit = 1; }
    }
    if (!restart()) exit = 1;
    console.log("");
    printStatus();
    nextSteps(false);
    if (cmd === "reset") console.log("- AD·Keycloak 데이터를 지웠습니다. 다음 `on` 때 처음부터 다시 만듭니다.");
    break;
  }
  default:
    console.log("사용법: node deploy/sso-lab/lab.mjs [status|on|off|reset] [--no-docker] [--restart-supabase]");
    exit = 2;
}
process.exitCode = exit;
