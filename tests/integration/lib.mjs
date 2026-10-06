// 통합 테스트 공용 도구 — 주소·DB 접속은 run.sh 가 넘겨주는 환경 변수를 따른다.
import { execFileSync } from "node:child_process";
import { chromium } from "playwright";

export const CONSOLE = process.env.EDR_IT_CONSOLE ?? "http://localhost:3300";
export const INGEST = process.env.EDR_IT_INGEST ?? "http://127.0.0.1:18080";
export const SUPABASE = process.env.EDR_IT_SUPABASE ?? "http://localhost:54321";
export const DB = process.env.EDR_IT_DB ?? "edr_it";
export const STATE_DIR = process.env.EDR_IT_TMP ?? "/tmp/edr-it";
export const TENANT_A = "aaaaaaaa-0000-0000-0000-000000000001";
export const TENANT_B = "bbbbbbbb-0000-0000-0000-000000000002";
export const USER_EMAIL = "secops@corp.example";
export const USER_ID = "33333333-3333-3333-3333-333333333333";
export const PASSWORD = "correct-horse";

/** psql 로 한 값(또는 여러 줄)을 읽는다. 접속 정보는 PGHOST/PGPORT/PGUSER 환경 변수. */
export function sql(query, user) {
  const args = ["-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", DB, "-c", query];
  if (user) args.unshift("-U", user);
  return execFileSync("psql", args, { encoding: "utf8" }).trim();
}

let pass = 0, fail = 0;
const failures = [];
export function expect(name, ok, extra = "") {
  if (ok) pass++; else { fail++; failures.push(name); }
  console.log(ok ? "  PASS" : "  FAIL", name, extra === "" ? "" : `→ ${extra}`);
}
/** 단계 끝: 실패가 있으면 종료 코드 1 */
export function done(stage) {
  console.log(`\n[${stage}] 통과 ${pass}, 실패 ${fail}${fail ? ` (${failures.join(", ")})` : ""}`);
  process.exitCode = fail ? 1 : 0;
}

export async function browser() {
  return chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined });
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
