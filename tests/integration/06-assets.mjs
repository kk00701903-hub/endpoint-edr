// 6단계: 자산 · 보안 상태 · 소프트웨어 정책 · 위협 지표(IOC) — 수집된 데이터로 콘솔 화면과 탐지를 끝까지 확인한다.
//   (02 단계가 SRV-WEB-01·DEV-WS-010 의 자산 정보·보안 상태 기준선을 보냈다)
//   1) 자산·보안 상태 화면, CSV 내려받기
//   2) 금지 소프트웨어 정책(콘솔) → EDR-SW-001
//   3) 보안 기능 꺼짐(실시간 검사 통과 → 실패) → EDR-POS-001, 처음부터 실패는 경보 없음
//   4) 위협 지표 등록(콘솔) → 최근 7일 소급 경보 EDR-IOC-001(해시)·002(IP), 잘못된 값 안내
//   5) 설치 프로그램 변화 → 설치·업데이트 이력, 점검 항목 점수 제외 → 감사 기록
import fs from "node:fs";
import zlib from "node:zlib";
import { CONSOLE, INGEST, PASSWORD, STATE_DIR, USER_EMAIL, browser, done, expect, sql } from "./lib.mjs";

const MAL = "e3".repeat(32);
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
async function send(token, env) {
  const r = await fetch(INGEST + "/v1/ingest", {
    method: "POST", headers: { Authorization: "Bearer " + token, "Content-Encoding": "gzip", "Content-Type": "application/json" },
    body: zlib.gzipSync(Buffer.from(JSON.stringify({ agent_version: "0.3.0", hostname: env.hostname, sent_at: new Date().toISOString(), snapshot: false, ...env }))),
  });
  return r.status;
}
const detect = () => sql("select public.edr_run_detections()", "edr_enricher");
/** 탐지 결과 확인: enricher 도 1분마다 같은 함수를 돌리므로(동시 실행은 잠금으로 건너뜀) 기대값이 나올 때까지 잠시 기다린다 */
async function settle(query, want, ms = 75_000) {
  let got = "";
  for (const t0 = Date.now(); Date.now() - t0 < ms; await new Promise((r) => setTimeout(r, 1500))) {
    detect();
    got = sql(query);
    if (got === want) break;
  }
  return got;
}
const toast = async (re) => (await p.locator("[data-sonner-toast]").filter({ hasText: re }).first().waitFor({ timeout: 10000 }).then(() => true).catch(() => false));

try {
  // 로그인(03 단계 끝에서 로그아웃했으므로 다시)
  await p.goto(CONSOLE + "/assets", { waitUntil: "load" });
  await p.getByLabel("이메일").fill(USER_EMAIL);
  await p.getByLabel("비밀번호").fill(PASSWORD);
  await p.getByRole("button", { name: "로그인", exact: true }).click();
  await p.waitForURL((u) => u.pathname === "/assets", { timeout: 20000 });

  // ---- 1) 자산 화면 ----
  let t = (await p.locator("main").innerText()).replace(/\s+/g, " ");
  expect("자산: 장치·일련번호·지원 종료 표시", t.includes("SRV-WEB-01") && t.includes("SRV7Q2K3") && t.includes("PF3ABC12") && /지원 종료/.test(t));
  expect("자산: 요약(지원 종료 1대·디스크 부족 1대)", /지원 종료 Windows\s*1/.test(t) && /디스크 10GB 미만\s*1/.test(t), t.slice(0, 200));
  t = await go("/assets?tab=devices&filter=unsupported");
  expect("자산: 지원 종료 거르기", t.includes("DEV-WS-010") && !t.includes("SRV-WEB-01"));
  t = await go("/assets?tab=devices&q=PF3ABC");
  expect("자산: 일련번호 검색", t.includes("DEV-WS-010") && !t.includes("SRV-WEB-01"));
  t = await go("/assets?tab=software&name=" + encodeURIComponent("7-Zip 24.09 (x64)"));
  expect("소프트웨어: 이름별 목록 + 설치 장치", t.includes("AnyDesk") && t.includes("설치된 장치 1대") && t.includes("SRV-WEB-01"));
  t = await go("/assets?tab=exposure");
  expect("취약 소프트웨어: 기본 제공 정책으로 WinRAR·7-Zip 노출", /WinRAR[\s\S]*1대에 설치됨/.test(t) && /7-Zip[\s\S]*1대에 설치됨/.test(t) && t.includes("CVE-2023-38831"), t.slice(0, 300));

  const csv = await p.request.get(CONSOLE + "/api/export/assets");
  const csvText = await csv.text();
  expect("CSV 내려받기(BOM·한글 머리글·행)", csv.status() === 200 && csvText.startsWith("﻿장치,Windows") && csvText.includes("SRV7Q2K3"), csv.status());

  // ---- 2) 금지 소프트웨어 정책 ----
  await p.getByRole("button", { name: "정책 추가" }).click();
  await p.getByPlaceholder(/AnyDesk/).fill("anydesk");
  await p.getByRole("dialog").getByLabel("심각도").selectOption("high");
  await p.getByPlaceholder(/원격 제어 도구/).fill("승인되지 않은 원격 제어 도구");
  await p.getByRole("dialog").getByRole("button", { name: "만들기" }).click();
  expect("금지 정책 만들기(안내)", await toast(/금지 정책을 만들었습니다/));
  let got = await settle("select string_agg(d.hostname || ':' || a.severity, ',') from alerts a join devices d on d.id = a.device_id where a.rule_id = 'EDR-SW-001'", "SRV-WEB-01:high");
  expect("EDR-SW-001: 이미 설치된 PC 경보(심각도는 정책 따름)", got === "SRV-WEB-01:high", got);
  detect();
  expect("EDR-SW-001: 다시 돌려도 중복 없음", sql("select count(*) from alerts where rule_id = 'EDR-SW-001'") === "1");

  // ---- 3) 보안 기능 꺼짐 ----
  expect("SRV-WEB-01 실시간 검사 꺼짐 + 평문 자격 증명 켜짐 전송", (await send(devs["SRV-WEB-01"].device_token, { hostname: "SRV-WEB-01", posture: [
    { id: "av_realtime", status: "fail", detail: "Microsoft Defender 실시간 보호 꺼짐(또는 수동 모드), 실행 중인 다른 백신 없음" },
    { id: "firewall", status: "pass" }, { id: "wdigest", status: "fail", detail: "WDigest 평문 자격 증명 저장 켜짐(UseLogonCredential=1)" }, { id: "smb1", status: "fail" },
  ] })) === 202);
  got = await settle("select string_agg(details->>'check_id', ',' order by details->>'check_id') from alerts where rule_id = 'EDR-POS-001'", "av_realtime,wdigest");
  expect("EDR-POS-001: 통과→실패 2건(실시간 검사·WDigest), 처음부터 실패(SMBv1)는 없음", got === "av_realtime,wdigest", got);
  t = await go("/posture");
  expect("보안 상태: 점수·분포·낮은 장치", /전체 보안 점수/.test(t) && t.includes("SRV-WEB-01") && t.includes("악성코드 실시간 검사"));
  t = await go("/posture?check=av_realtime&status=fail");
  expect("보안 상태: 항목별 실패 장치 + 고치는 방법", t.includes("SRV-WEB-01") && t.includes("고치는 방법") && t.includes("실시간 보호 꺼짐"));
  t = await go(`/devices/${devs["SRV-WEB-01"].device_id}?tab=posture`);
  expect("장치 상세: 보안 상태 탭", t.includes("보안 점수") && t.includes("평문 자격 증명 저장 안 함") && t.includes("고치는 방법"));
  // 점검 항목 점수 제외(관리자) → 감사 기록
  await go("/posture");
  await p.getByRole("switch", { name: /SMBv1 꺼짐 점수 반영 끄기/ }).click();
  expect("점검 항목 점수 제외", await toast(/점수에서 뺐습니다/));
  expect("점검 항목 변경 감사 기록", sql("select count(*) from audit_log where action = 'posture_policy.disable' and target_id = 'smb1'") === "1");

  // ---- 4) 위협 지표 ----
  await go("/iocs");
  await p.getByPlaceholder(/한 줄에 하나씩/).fill("10.0.0.0/8");
  await p.getByRole("button", { name: /^등록$/ }).click();
  const bad = p.getByRole("alert").filter({ hasText: /너무 넓은 대역/ });
  expect("위협 지표: 너무 넓은 대역 안내", await bad.first().waitFor({ timeout: 8000 }).then(() => true).catch(() => false));
  await p.getByPlaceholder(/한 줄에 하나씩/).fill(`${MAL.toUpperCase()}\n45.9.148[.]3\n203.0.113.0/24`);
  await p.getByPlaceholder(/피싱 메일/).fill("침해 사고 분석에서 나온 지표");
  await p.getByRole("button", { name: /3개 등록/ }).click();
  expect("위협 지표 3개 등록 + 소급 결과 안내", await toast(/3개 등록.*최근 7일 기록에서 2건 발견/));
  expect("EDR-IOC-001(해시)·002(IP) 소급 경보",
    sql("select string_agg(rule_id, ',' order by rule_id) from alerts where rule_id like 'EDR-IOC-%'") === "EDR-IOC-001,EDR-IOC-002");
  expect("IOC 경보가 기존 인시던트에 묶임(같은 해시·IP)", sql("select count(distinct incident_id) from alerts where rule_id like 'EDR-IOC-%' and incident_id is not null") === "1");
  t = await go("/iocs?view=hit");
  expect("위협 지표: 발견된 지표 목록", t.includes("45.9.148.3") && t.includes(MAL) && !t.includes("203.0.113.0/24"));
  t = await go("/iocs?view=all");
  await p.getByRole("switch", { name: /지표 203\.0\.113\.0\/24 끄기/ }).click();
  expect("위협 지표 끄기", await toast(/지표를 껐습니다/));
  expect("위협 지표 감사 기록", sql("select string_agg(action, ',' order by id) from audit_log where target_type = 'ioc'") === "ioc.create,ioc.create,ioc.create,ioc.update");

  // ---- 5) 설치 프로그램 변화 → 이력 ----
  expect("DEV-WS-010 프로그램 변화 전송", (await send(devs["DEV-WS-010"].device_token, { hostname: "DEV-WS-010", inventory: {
    collected_at: new Date().toISOString(), os: { name: "Windows 11 Pro", edition: "Professional", display_version: "25H2", build: 26200, install_type: "Client" },
    hardware: { manufacturer: "LENOVO", model: "21AHCTO1WW", serial: "PF3ABC12" }, domain_joined: true, software: [{ name: "Google Chrome", version: "130.0.6723.92", publisher: "Google LLC" }, { name: "7-Zip 23.01 (x64)", version: "23.01", publisher: "Igor Pavlov" }, { name: "Notepad++", version: "8.7" }],
  } })) === 202);
  expect("설치·업데이트 이력", sql("select string_agg(change || ':' || name, ',' order by change, name) from software_changes") === "installed:Notepad++,updated:Google Chrome");
  expect("OS 업그레이드 → 지원 종료 해소", sql(`select status from device_posture where device_id = '${devs["DEV-WS-010"].device_id}' and check_id = 'os_supported'`) === "pass");
  t = await go("/assets?tab=changes");
  expect("설치 이력 화면", t.includes("Notepad++") && /130\.0\.6723\.70 → 130\.0\.6723\.92/.test(t));
  t = await go(`/devices/${devs["DEV-WS-010"].device_id}?tab=asset`);
  expect("장치 상세: 자산 탭(취약 표시·이력)", t.includes("PF3ABC12") && t.includes("정책에 걸린 프로그램") && t.includes("7-Zip 23.01") && t.includes("Notepad++"));
  t = await go(`/devices/${devs["DEV-WS-010"].device_id}`);
  expect("장치 타임라인에 설치 이력", t.includes("설치: Notepad++"));
  t = await go("/");
  expect("현황: 보안 위생(점수·취약·금지)", t.includes("보안 위생") && /금지 소프트웨어가 있는 PC\s*1/.test(t));
  t = await go("/settings");
  expect("감사 기록 화면: 새 동작 이름", t.includes("위협 지표 등록") && t.includes("소프트웨어 정책 추가") && t.includes("보안 점검 항목 점수 제외"));

  expect("브라우저 오류 없음", errs.length === 0, errs.join(" | "));
} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
} finally {
  await b.close();
  done("06 자산·보안 상태·위협 지표");
}
