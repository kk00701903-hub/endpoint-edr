// 8단계: 문서 감사(보안 관리자의 PC 감사) — 콘솔 정책 → 에이전트 정책 받기 → 결과 저장 → 화면·내려받기·권한·감사 기록
//   1) 기본 꺼짐: 에이전트는 꺼진 정책을 받는다
//   2) 켜기: 직원 고지 확인 없이는 저장 버튼이 막힘 → 확인 후 저장, 에이전트가 새 정책(키워드)을 받음
//   3) "지금 검사" 요청 → 정책에 요청 번호 → 결과 배치(중간·마지막) 저장, 요청 완료, 잘못된 배치 거부
//   4) 결과 화면(개인정보·키워드·오래된 문서·검사 현황), CSV(내려받기 감사 기록)
//   5) 분석가는 볼 수 없음, 감사 기록 화면
import fs from "node:fs";
import zlib from "node:zlib";
import { CONSOLE, INGEST, PASSWORD, STATE_DIR, USER_EMAIL, USER_ID, browser, done, expect, sql } from "./lib.mjs";

const devs = JSON.parse(fs.readFileSync(`${STATE_DIR}/devices.json`, "utf8"));
const dev = devs["DEV-WS-010"];
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
async function policy() {
  const r = await fetch(INGEST + "/v1/policy", { headers: { Authorization: "Bearer " + dev.device_token } });
  return { status: r.status, body: r.status === 200 ? (await r.json()).doc_scan : null };
}
async function send(docScan) {
  const r = await fetch(INGEST + "/v1/ingest", {
    method: "POST", headers: { Authorization: "Bearer " + dev.device_token, "Content-Encoding": "gzip", "Content-Type": "application/json" },
    body: zlib.gzipSync(Buffer.from(JSON.stringify({ agent_version: "0.3.0", hostname: "DEV-WS-010", sent_at: new Date().toISOString(), snapshot: false, doc_scan: docScan }))),
  });
  return r.status;
}
const toast = async (re) => (await p.locator("[data-sonner-toast]").filter({ hasText: re }).first().waitFor({ timeout: 10000 }).then(() => true).catch(() => false));
const setRole = (role) => sql(`update tenant_members set role = '${role}' where user_id = '${USER_ID}'`);

try {
  await p.goto(CONSOLE + "/documents", { waitUntil: "load" });
  if (p.url().includes("/login")) {
    await p.getByLabel("이메일").fill(USER_EMAIL);
    await p.getByLabel("비밀번호").fill(PASSWORD);
    await p.getByRole("button", { name: "로그인", exact: true }).click();
    await p.waitForURL((u) => u.pathname === "/documents", { timeout: 20000 });
  }

  // ---- 1) 기본 꺼짐 ----
  let t = (await p.locator("main").innerText()).replace(/\s+/g, " ");
  expect("문서 감사: 기본 꺼짐 안내", t.includes("문서 감사가 꺼져 있습니다"));
  let pol = await policy();
  expect("에이전트 정책: 꺼짐", pol.status === 200 && pol.body?.enabled === false, JSON.stringify(pol));

  // ---- 2) 켜기 (직원 고지 확인 필요) ----
  await go("/documents?tab=policy");
  await p.getByRole("switch", { name: /문서 감사 꺼짐/ }).click();
  const save = p.getByRole("button", { name: "정책 저장" });
  expect("고지 확인 전에는 저장 막힘", await save.isDisabled());
  await p.getByLabel(/^키워드/).fill("대외비\n영업비밀");
  await p.getByLabel(/직원에게 PC 문서 점검 사실/).check();
  await save.click();
  expect("문서 감사 켜기(안내)", await toast(/문서 감사를 켰습니다/));
  expect("DB: 켜짐 + 고지 확인 기록", sql(`select enabled and notice_confirmed_at is not null and notice_confirmed_by = '${USER_ID}' from doc_scan_policies`) === "t");
  pol = await policy();
  expect("에이전트 정책: 켜짐·키워드·기본 폴더", pol.body?.enabled === true && pol.body.keywords.join(",") === "대외비,영업비밀"
    && pol.body.folders.includes("Documents") && pol.body.request_id == null && pol.body.version?.length === 32, JSON.stringify(pol.body));

  // ---- 3) 지금 검사 → 결과 ----
  await go("/documents?tab=devices");
  await p.getByRole("row", { name: /DEV-WS-010/ }).getByRole("button", { name: "지금 검사" }).click();
  expect("지금 검사 요청(안내)", await toast(/1대에 검사를 요청했습니다/));
  pol = await policy();
  const reqId = pol.body?.request_id;
  expect("에이전트 정책: 요청 번호 전달", Number.isInteger(reqId) && reqId > 0, JSON.stringify(pol.body));
  expect("요청: 에이전트가 받은 시각 기록", sql(`select picked_at is not null from doc_scan_requests where id = ${reqId}`) === "t");

  const head = { scan_id: "a1b2c3d4e5f60718", trigger: "request", request_id: reqId, started_at: new Date().toISOString() };
  const old = new Date(Date.now() - 5 * 365 * 86400_000).toISOString();
  expect("결과 1(중간 배치)", (await send({ ...head, final: false, files_scanned: 120, files_skipped: 2, errors: 0, findings: [
    { path: "C:\\Users\\kim\\Documents\\고객명단.xlsx", size: 52000, modified_at: new Date().toISOString(), pii: { rrn: 3, phone: 2 } },
    { path: "C:\\Users\\kim\\Desktop\\사업계획_대외비.pptx", size: 900000, modified_at: new Date().toISOString(), keywords: { 대외비: 4 } },
  ] })) === 202);
  expect("결과 2(마지막 배치)", (await send({ ...head, final: true, finished_at: new Date().toISOString(), files_scanned: 30, files_skipped: 0, errors: 1, findings: [
    { path: "C:\\Users\\kim\\Documents\\백업\\2019_거래처.xls", size: 12000, modified_at: old, stale: true, unreadable: "암호가 걸린 문서" },
  ] })) === 202);
  expect("잘못된 배치 거부(허용되지 않은 검출 종류)", (await send({ ...head, scan_id: "ffff0000", final: true, findings: [
    { path: "C:\\x.txt", size: 1, modified_at: new Date().toISOString(), pii: { rrn_value: 1 } }] })) === 400);
  expect("잘못된 배치 거부(검사 ID 형식)", (await send({ ...head, scan_id: "../../x", final: false })) === 400);
  expect("저장: 결과 3건, 검사 합계, 요청 완료",
    sql("select count(*) from doc_findings") === "3"
    && sql("select files_scanned || '/' || files_skipped || '/' || errors || '/' || status from doc_scans") === "150/2/1/done"
    && sql(`select completed_at is not null from doc_scan_requests where id = ${reqId}`) === "t",
    sql("select string_agg(path, ',') from doc_findings"));
  expect("저장: 내용·값 없이 건수만", sql("select pii::text from doc_findings where path like '%고객명단%'") === '{"rrn": 3, "phone": 2}');
  pol = await policy();
  expect("완료된 요청은 다시 주지 않음", pol.body?.request_id == null);

  // ---- 4) 결과 화면 · CSV ----
  t = await go("/documents");
  expect("개인정보 탭: 파일·장치·종류별 건수", t.includes("고객명단.xlsx") && t.includes("DEV-WS-010") && /주민등록번호\s*3건/.test(t) && /휴대전화번호\s*2건/.test(t), t.slice(0, 400));
  t = await go("/documents?tab=keyword");
  expect("키워드 탭", t.includes("사업계획_대외비.pptx") && /대외비\s*4회/.test(t));
  t = await go("/documents?tab=stale");
  expect("오래된 문서 탭(읽지 못한 이유)", t.includes("2019_거래처.xls") && t.includes("암호가 걸린 문서") && t.includes("5년 전"));
  t = await go("/documents?tab=devices");
  expect("검사 현황 탭", /DEV-WS-010[\s\S]*150/.test(t));
  const csv = await p.request.get(CONSOLE + "/api/export/documents-pii");
  const csvText = await csv.text();
  expect("CSV 내려받기", csv.status() === 200 && csvText.startsWith("﻿장치,파일 경로") && csvText.includes("주민등록번호 3"), csv.status());
  expect("감사 기록: 켬·요청·조회·내려받기",
    ["doc_scan.enable", "doc_scan.request", "doc_scan.view", "doc_scan.export"].every((a) => sql(`select count(*) > 0 from audit_log where action = '${a}' and actor_id = '${USER_ID}'`) === "t"),
    sql("select string_agg(action, ',' order by id) from audit_log where action like 'doc_scan.%'"));
  expect("감사 기록에 개인정보 값 없음", sql("select count(*) from audit_log where changes::text ~ '\\d{6}-\\d{7}'") === "0");

  // ---- 5) 권한 · 감사 기록 화면 ----
  setRole("analyst");
  t = await go("/documents");
  expect("분석가: 결과를 볼 수 없음", t.includes("소유자·관리자만 볼 수 있습니다") && !t.includes("고객명단"));
  expect("분석가: CSV 거부", (await p.request.get(CONSOLE + "/api/export/documents-pii")).status() === 403);
  setRole("owner");
  t = await go("/settings?audit=doc_scan");
  expect("감사 기록 화면: 문서 감사 동작 이름", t.includes("문서 감사 켬") && t.includes("문서 검사 요청") && t.includes("문서 감사 결과 내려받기"), t.slice(0, 300));

  expect("브라우저 오류 없음", errs.length === 0, errs.join(" | "));
} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
} finally {
  setRole("owner");
  await b.close();
  done("08 문서 감사");
}
