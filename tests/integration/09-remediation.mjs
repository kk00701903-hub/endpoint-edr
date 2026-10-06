// 9단계: PC 조치 목록 — 앞 단계 데이터(보안 점검 실패·금지 프로그램·개인정보 문서)로 목록 계산, 담당자·상태, 권한, 해결 확인, 감사 기록
//   (06 단계: SRV-WEB-01 실시간 검사 꺼짐·AnyDesk 금지 정책 / 08 단계: DEV-WS-010 개인정보 문서)
import fs from "node:fs";
import zlib from "node:zlib";
import { CONSOLE, INGEST, PASSWORD, STATE_DIR, USER_EMAIL, USER_ID, browser, done, expect, sql } from "./lib.mjs";

const devs = JSON.parse(fs.readFileSync(`${STATE_DIR}/devices.json`, "utf8"));
const b = await browser();
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, locale: "ko-KR", timezoneId: "Asia/Seoul" });
const p = await ctx.newPage();
const errs = [];
p.on("pageerror", (e) => errs.push(String(e).slice(0, 160)));

async function go(path) {
  await p.goto(CONSOLE + path, { waitUntil: "load" });
  await p.waitForTimeout(500);
  return (await p.locator("main").innerText()).replace(/\s+/g, " ");
}
async function send(name, env) {
  const r = await fetch(INGEST + "/v1/ingest", {
    method: "POST", headers: { Authorization: "Bearer " + devs[name].device_token, "Content-Encoding": "gzip", "Content-Type": "application/json" },
    body: zlib.gzipSync(Buffer.from(JSON.stringify({ agent_version: "0.3.0", hostname: name, sent_at: new Date().toISOString(), snapshot: false, ...env }))),
  });
  return r.status;
}
const toast = async (re) => (await p.locator("[data-sonner-toast]").filter({ hasText: re }).first().waitFor({ timeout: 10000 }).then(() => true).catch(() => false));
const setRole = (role) => sql(`update tenant_members set role = '${role}' where user_id = '${USER_ID}'`);
const row = (re) => p.locator("tbody tr").filter({ hasText: re }).first();
async function applyTo(re, { status, assigneeLabel }) {
  await row(re).locator("input[type=checkbox]").check();
  const bar = p.getByRole("region", { name: "고른 항목 처리" });
  if (status) await bar.getByLabel("상태").selectOption({ label: status });
  if (assigneeLabel) await bar.getByLabel("담당자").selectOption({ label: assigneeLabel });
  await bar.getByRole("button", { name: "적용" }).click();
}

try {
  await p.goto(CONSOLE + "/remediation", { waitUntil: "load" });
  if (p.url().includes("/login")) {
    await p.getByLabel("이메일").fill(USER_EMAIL);
    await p.getByLabel("비밀번호").fill(PASSWORD);
    await p.getByRole("button", { name: "로그인", exact: true }).click();
    await p.waitForURL((u) => u.pathname === "/remediation", { timeout: 20000 });
  }

  // ---- 1) 목록 계산 ----
  let t = (await p.locator("main").innerText()).replace(/\s+/g, " ");
  expect("목록: 보안 점검 실패(실시간 검사)", /SRV-WEB-01[\s\S]*악성코드 실시간 검사/.test(t), t.slice(0, 300));
  expect("목록: 금지 프로그램", t.includes("금지 프로그램 삭제: AnyDesk"));
  expect("목록: 개인정보 문서 정리(관리자)", /DEV-WS-010[\s\S]*개인정보 문서 정리 1개/.test(t));
  const items = Number(sql("select count(*) from public.edr_remediation_items('aaaaaaaa-0000-0000-0000-000000000001', true)"));
  expect("요약 수 = DB 계산", new RegExp(`조치 필요\\s*${items}`).test(t), `${items} / ${t.slice(0, 200)}`);

  // ---- 2) 담당자·상태 ----
  await applyTo(/악성코드 실시간 검사/, { status: "진행 중", assigneeLabel: USER_EMAIL });
  expect("한 건 처리(안내)", await toast(/1건을 진행 중으로 바꿨습니다/));
  expect("DB: 처리 기록", sql("select status || ':' || (assignee = updated_by)::text || ':' || title from remediation_tracking where kind = 'posture' and item_key = 'av_realtime'") === "in_progress:true:악성코드 실시간 검사");
  await go("/remediation");
  await row(/금지 프로그램 삭제: AnyDesk/).locator("input[type=checkbox]").check();
  await row(/개인정보 문서 정리/).locator("input[type=checkbox]").check();
  const bar = p.getByRole("region", { name: "고른 항목 처리" });
  await bar.getByLabel("기한").fill("2030-01-31");
  await bar.getByRole("button", { name: "적용" }).click();
  expect("여러 건 처리(기한)", await toast(/2건을 저장했습니다/));
  expect("DB: 기한 2건", sql("select count(*) from remediation_tracking where due_date = '2030-01-31'") === "2");
  t = await go("/remediation?mine=1");
  expect("내 담당 거르기", t.includes("악성코드 실시간 검사") && !t.includes("AnyDesk"));

  // ---- 3) 권한 ----
  setRole("analyst");
  t = await go("/remediation");
  expect("분석가: 문서 정리 항목 안 보임", !t.includes("개인정보 문서 정리") && t.includes("AnyDesk") && t.includes("소유자·관리자에게만"));
  await applyTo(/금지 프로그램 삭제: AnyDesk/, { status: "완료 표시" });
  expect("분석가: 보안·프로그램 항목 처리", await toast(/1건을 완료로 표시했습니다/));
  setRole("viewer");
  await go("/remediation");
  expect("열람자: 고르기 없음", (await p.locator("tbody input[type=checkbox]").count()) === 0);
  setRole("owner");
  t = await go("/remediation?view=done");
  expect("완료 표시 = 아직 남아 있으면 확인 대기", t.includes("AnyDesk") && t.includes("확인 대기"));

  // ---- 4) 고치면 저절로 빠짐 → 해결 확인됨 ----
  expect("SRV-WEB-01 실시간 검사 켜짐 전송", (await send("SRV-WEB-01", { posture: [{ id: "av_realtime", status: "pass", detail: "Microsoft Defender 실시간 보호 켜짐" }] })) === 202);
  t = await go("/remediation");
  expect("고친 항목은 목록에서 빠짐", !t.includes("악성코드 실시간 검사"));
  t = await go("/remediation?view=resolved");
  expect("해결 확인됨 보기", /SRV-WEB-01[\s\S]*악성코드 실시간 검사[\s\S]*해결 확인됨/.test(t), t.slice(0, 300));

  // ---- 5) CSV · 감사 기록 ----
  const csv = await p.request.get(CONSOLE + "/api/export/remediation?view=all");
  const csvText = await csv.text();
  expect("CSV 내려받기", csv.status() === 200 && csvText.startsWith("﻿장치,종류,할 일") && csvText.includes("해결 확인됨") && csvText.includes("AnyDesk"), csv.status());
  expect("감사 기록(한 건·여러 건)", sql("select string_agg(action, ',' order by id) from audit_log where action like 'remediation.%'") === "remediation.status,remediation.bulk,remediation.status",
    sql("select string_agg(action, ',' order by id) from audit_log where action like 'remediation.%'"));
  t = await go("/settings?audit=remediation");
  expect("감사 기록 화면", t.includes("조치 상태 변경") && t.includes("조치 항목 일괄 처리"));

  expect("브라우저 오류 없음", errs.length === 0, errs.join(" | "));
} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
} finally {
  setRole("owner");
  await b.close();
  done("09 PC 조치 목록");
}
