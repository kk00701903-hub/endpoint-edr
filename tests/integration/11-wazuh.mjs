// 11단계: Wazuh 경보 수집 — 웹훅(POST /v1/wazuh)으로 받은 경보가 콘솔 경보 화면에 source=wazuh 로 뜨는지
import { CONSOLE, INGEST, PASSWORD, TENANT_A, USER_EMAIL, browser, done, expect, sql } from "./lib.mjs";

const SECRET = process.env.WAZUH_WEBHOOK_SECRET ?? "it-wazuh-secret";
async function post(secret, body) {
  const r = await fetch(INGEST + "/v1/wazuh", {
    method: "POST",
    headers: { Authorization: "Bearer " + secret, "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => null) };
}

const b = await browser();
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, locale: "ko-KR", timezoneId: "Asia/Seoul" });
const p = await ctx.newPage();
const errs = [];
p.on("pageerror", (e) => errs.push(String(e).slice(0, 160)));

try {
  // ---- 1) 잘못된 비밀 → 401 ----
  expect("잘못된 비밀 → 401", (await post("wrong", { id: "x", rule: { id: "1", level: 9, description: "nope" } })).status === 401);

  // ---- 2) 경보 1건 수신 (level 10 → high, 호스트 매칭) ----
  const dev = sql(`select hostname from devices where tenant_id='${TENANT_A}' order by hostname limit 1`);
  const r1 = await post(SECRET, {
    id: "it-9001", timestamp: new Date().toISOString(),
    rule: { id: "5710", level: 10, description: "sshd: 존재하지 않는 사용자 로그인 시도", mitre: { tactic: ["Credential Access"], id: ["T1110"] } },
    agent: { name: dev, ip: "203.0.113.7" }, location: "/var/log/auth.log", full_log: "Failed password for invalid user admin",
  });
  expect("경보 수신(stored=1)", r1.status === 200 && r1.json?.stored === 1, JSON.stringify(r1.json));
  expect("DB: source=wazuh·high·호스트 매칭", sql(`select source||':'||severity||':'||(device_id is not null)::text from alerts where dedup_key='wazuh:it-9001'`) === `wazuh:high:true`);

  // ---- 3) 같은 id 재전송 → 중복 저장 안 됨 ----
  const r2 = await post(SECRET, { id: "it-9001", rule: { id: "5710", level: 10, description: "dup" } });
  expect("중복 id → stored=0", r2.json?.stored === 0);
  expect("DB: 한 건만", sql(`select count(*) from alerts where dedup_key='wazuh:it-9001'`) === "1");

  // ---- 4) 배열로 여러 건 + level 13 → critical ----
  const r3 = await post(SECRET, [
    { id: "it-9002", rule: { id: "100100", level: 13, description: "무결성 검사: 체크섬 변경" }, agent: { name: "NO-SUCH-PC" } },
    { id: "it-9003", rule: { id: "5503", level: 5, description: "낮은 수준 이벤트" }, agent: { name: dev } },
  ]);
  expect("배열 2건 수신", r3.json?.received === 2 && r3.json?.stored === 2);
  expect("DB: level 13 → critical", sql(`select severity from alerts where dedup_key='wazuh:it-9002'`) === "critical");

  // ---- 5) 콘솔 경보 화면: 출처=Wazuh 필터로 보임 + 배지 ----
  await p.goto(CONSOLE + "/alerts?status=all&source=wazuh", { waitUntil: "load" });
  if (p.url().includes("/login")) {
    await p.getByLabel("이메일").fill(USER_EMAIL);
    await p.getByLabel("비밀번호").fill(PASSWORD);
    await p.getByRole("button", { name: "로그인", exact: true }).click();
    await p.waitForURL((u) => u.pathname === "/alerts", { timeout: 20000 });
    await p.goto(CONSOLE + "/alerts?status=all&source=wazuh", { waitUntil: "load" });
  }
  await p.waitForTimeout(600);
  const t = (await p.locator("main").innerText()).replace(/\s+/g, " ");
  expect("경보 화면에 Wazuh 경보·배지", /WAZUH-5710[\s\S]*Wazuh/.test(t) || (t.includes("WAZUH-5710") && t.includes("Wazuh")), t.slice(0, 200));
  expect("내장 탐지 경보는 안 섞임", !t.includes("EDR-AUTH") && !t.includes("EDR-MAL"));

  expect("브라우저 오류 없음", errs.length === 0, errs.join(" | "));
} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
} finally {
  await b.close();
  done("11 Wazuh 경보 수집");
}
