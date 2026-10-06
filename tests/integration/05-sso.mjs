// 5단계: 회사 계정(SSO) 로그인 — 콘솔 버튼 → (Keycloak 흉내) → Supabase PKCE → DB 트리거가 AD 그룹으로 역할 결정
// 실제 Keycloak·테스트용 AD 로 같은 흐름을 확인하는 스크립트는 sso-lab-verify.mjs (docs/SSO_LAB.md).
import { CONSOLE, SUPABASE, browser, done, expect, sql } from "./lib.mjs";
import { ssoLogin } from "./sso-login.mjs";

const PW = process.env.LAB_USER_PASSWORD ?? "Passw0rd!Lab";
const otp = {};
const b = await browser();
const roleOf = (u) => sql(`select coalesce((select m.role || '/' || m.managed_by from tenant_members m join auth.users x on x.id = m.user_id where x.email = '${u}@bing.test'), '-')`);
async function as(user, fn) {
  const ctx = await b.newContext({ viewport: { width: 1280, height: 860 }, locale: "ko-KR", timezoneId: "Asia/Seoul" });
  const page = await ctx.newPage();
  const errs = [];
  page.on("pageerror", (e) => errs.push(String(e).slice(0, 160)));
  try { await fn(page); } finally { await ctx.close(); }
  return errs;
}

try {
  // 관리자: 처음 로그인 → OTP 등록 → 콘솔
  await as("kim.admin", async (p) => {
    await p.goto(CONSOLE + "/login", { waitUntil: "load" });
    expect("로그인 화면에 회사 계정 버튼", (await p.getByRole("button", { name: /회사 계정으로 로그인/ }).count()) === 1);
    const r = await ssoLogin(p, CONSOLE, "kim.admin", PW, otp);
    expect("관리자 SSO 로그인 + OTP 등록", r.ok && r.otp === "setup", `${r.url} ${r.message ?? ""}`);
    expect("AD 그룹 → 관리자", roleOf("kim.admin") === "admin/sso", roleOf("kim.admin"));
    const t = (await p.locator("body").innerText()).replace(/\s+/g, " ");
    expect("콘솔 화면에 관리자 표시", t.includes("kim.admin@bing.test") && t.includes("관리자"));
    await p.goto(CONSOLE + "/settings", { waitUntil: "load" });
    const s = (await p.locator("main").innerText()).replace(/\s+/g, " ");
    expect("설정: AD 연동 표·자동 가입 표시", s.includes("회사 계정(AD) 연동") && s.includes("EDR-Admins") && s.includes("AD 그룹 관리자"));
    expect("감사 기록: AD 그룹으로 가입", s.includes("AD 그룹으로 가입"));
  });
  // 관리자 두 번째 로그인: OTP 입력
  await as("kim.admin", async (p) => {
    const r = await ssoLogin(p, CONSOLE, "kim.admin", PW, otp);
    expect("관리자 재로그인 + OTP 입력", r.ok && r.otp === "used", `${r.url} ${r.message ?? ""}`);
  });
  // 분석가·열람자: OTP 없이
  for (const [u, role, label] of [["lee.analyst", "analyst/sso", "분석가"], ["park.viewer", "viewer/sso", "열람자"]]) {
    await as(u, async (p) => {
      const r = await ssoLogin(p, CONSOLE, u, PW, otp);
      expect(`${label} SSO 로그인(OTP 없음)`, r.ok && !r.otp, `${r.url} ${r.message ?? ""}`);
      expect(`AD 그룹 → ${label}`, roleOf(u) === role, roleOf(u));
    });
  }
  // 그룹 없는 계정: 로그인은 되지만 권한 없음 안내
  await as("choi.none", async (p) => {
    const r = await ssoLogin(p, CONSOLE, "choi.none", PW, otp);
    await p.waitForTimeout(800);
    const t = (await p.locator("body").innerText()).replace(/\s+/g, " ");
    expect("그룹 없는 계정 → 권한 없음 안내", r.ok && p.url().includes("reason=no-access") && t.includes("권한이 없습니다"), p.url());
    expect("그룹 없는 계정은 구성원 아님", roleOf("choi.none") === "-");
    await p.getByRole("button", { name: "다른 계정으로 로그인" }).click();
    await p.waitForURL((u) => u.pathname === "/login" && !u.search.includes("no-access"), { timeout: 10000 }).catch(() => {});
    expect("다른 계정으로 로그인 → 로그아웃", !p.url().includes("no-access"), p.url());
  });
  // 잠긴(비활성) AD 계정: Keycloak 에서 막힘
  await as("jung.locked", async (p) => {
    const r = await ssoLogin(p, CONSOLE, "jung.locked", PW, otp);
    expect("잠긴 AD 계정 차단", !r.ok && /비활성화|disabled/i.test(r.message ?? ""), r.message);
    expect("잠긴 계정은 구성원 아님", roleOf("jung.locked") === "-");
  });
  // 틀린 비밀번호
  await as("lee.analyst", async (p) => {
    const r = await ssoLogin(p, CONSOLE, "lee.analyst", "wrong-password", otp);
    expect("틀린 AD 비밀번호 차단", !r.ok && /잘못된|Invalid/i.test(r.message ?? ""), r.message);
  });
  // AD 그룹에서 빠지면 다음 로그인부터 접근 제거
  await fetch(`${SUPABASE}/fake-kc/groups`, { method: "POST", body: JSON.stringify({ username: "lee.analyst", groups: [] }) });
  await as("lee.analyst", async (p) => {
    await ssoLogin(p, CONSOLE, "lee.analyst", PW, otp);
    await p.waitForTimeout(800);
    expect("AD 그룹에서 빠짐 → 접근 제거", p.url().includes("reason=no-access") && roleOf("lee.analyst") === "-", p.url());
  });
  // 그룹 바뀜 → 역할 바뀜
  await fetch(`${SUPABASE}/fake-kc/groups`, { method: "POST", body: JSON.stringify({ username: "park.viewer", groups: ["EDR-Analysts"] }) });
  await as("park.viewer", async (p) => {
    await ssoLogin(p, CONSOLE, "park.viewer", PW, otp);
    expect("AD 그룹 변경 → 역할 변경(열람자→분석가)", roleOf("park.viewer") === "analyst/sso", roleOf("park.viewer"));
  });
  const acts = sql("select string_agg(action, ',' order by id) from audit_log where actor_email = 'AD 그룹 동기화'");
  expect("감사 기록: 가입·제거·역할 변경", ["member.sso_add", "member.sso_remove", "member.sso_role"].every((a) => acts.includes(a)), acts);
  expect("수동 소유자는 그대로", sql("select role || '/' || managed_by from tenant_members where user_id = '33333333-3333-3333-3333-333333333333'") === "owner/manual");
} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
} finally {
  await b.close();
  done("05 회사 계정(SSO)");
}
