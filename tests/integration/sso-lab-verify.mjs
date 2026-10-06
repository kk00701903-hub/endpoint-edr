// 개인 PC SSO 실험실 확인 스크립트 — 실제 테스트용 AD + Keycloak + Supabase 로컬 + 콘솔로 로그인 흐름을 확인한다.
// 사용: (docs/SSO_LAB.md 5단계까지 띄운 뒤)  cd tests/integration && npm ci && npx playwright install chromium
//       node sso-lab-verify.mjs            (콘솔 주소가 다르면 CONSOLE_URL=http://localhost:3000)
// 관리자(kim.admin)의 OTP 비밀값은 처음 등록할 때 이 PC 의 임시 폴더에 저장해 두고 다음 실행 때 쓴다.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { chromium } from "playwright";
import { ssoLogin } from "./sso-login.mjs";

const CONSOLE = process.env.CONSOLE_URL ?? "http://localhost:3000";
const PW = process.env.LAB_USER_PASSWORD ?? "Passw0rd!Lab";
const OTP_FILE = path.join(os.tmpdir(), "edr-sso-lab-otp.json");
const otp = fs.existsSync(OTP_FILE) ? JSON.parse(fs.readFileSync(OTP_FILE, "utf8")) : {};
let pass = 0, fail = 0;
const check = (name, ok, extra = "") => { ok ? pass++ : fail++; console.log(ok ? "  통과" : "  실패", name, extra ? `→ ${extra}` : ""); };

const b = await chromium.launch({ headless: process.env.HEADED !== "1" });
async function as(fn) {
  const ctx = await b.newContext({ viewport: { width: 1280, height: 860 }, locale: "ko-KR" });
  const page = await ctx.newPage();
  try { await fn(page); } catch (e) { check("오류 없이 진행", false, String(e).split("\n")[0]); } finally { await ctx.close(); }
}
const roleLabel = async (p) => (await p.locator("aside").first().innerText().catch(() => "")).replace(/\s+/g, " ");

console.log(`콘솔 ${CONSOLE} 로 회사 계정 로그인을 확인합니다\n`);
await as(async (p) => {
  const r = await ssoLogin(p, CONSOLE, "kim.admin", PW, otp);
  fs.writeFileSync(OTP_FILE, JSON.stringify(otp));
  check(`kim.admin(EDR-Admins) 로그인 + OTP ${r.otp === "setup" ? "등록" : "입력"}`, r.ok && !!r.otp, r.ok ? "" : `${r.url} ${r.message ?? ""}`);
  check("kim.admin → 관리자", (await roleLabel(p)).includes("관리자"));
});
for (const [u, label] of [["lee.analyst", "분석가"], ["park.viewer", "열람자"]]) {
  await as(async (p) => {
    const r = await ssoLogin(p, CONSOLE, u, PW, otp);
    check(`${u} 로그인(OTP 없음)`, r.ok && !r.otp, r.ok ? "" : `${r.url} ${r.message ?? ""}`);
    check(`${u} → ${label}`, (await roleLabel(p)).includes(label));
  });
}
await as(async (p) => {
  const r = await ssoLogin(p, CONSOLE, "choi.none", PW, otp);
  await p.waitForTimeout(800);
  check("choi.none(그룹 없음) → 권한 없음 안내", r.ok && p.url().includes("reason=no-access"), p.url());
});
await as(async (p) => {
  const r = await ssoLogin(p, CONSOLE, "jung.locked", PW, otp);
  check("jung.locked(비활성 계정) → Keycloak 에서 차단", !r.ok && /비활성|disabled/i.test(r.message ?? ""), r.message);
});
await as(async (p) => {
  const r = await ssoLogin(p, CONSOLE, "lee.analyst", "wrong-password", otp);
  check("틀린 비밀번호 → 차단", !r.ok, r.message);
});
await b.close();
console.log(`\n통과 ${pass}, 실패 ${fail}${fail ? " — docs/SSO_LAB.md 의 '문제가 생기면'을 확인하세요" : ""}`);
process.exitCode = fail ? 1 : 0;
