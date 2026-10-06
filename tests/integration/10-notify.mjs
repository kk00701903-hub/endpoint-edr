// 10단계: 알림 연동 — 콘솔에서 채널 설정 → 경보 발생 → enricher 가 슬랙·이메일·SIEM(여기선 SINK 파일)으로 발송, 권한·감사 기록
//   enricher 는 run.sh 가 EDR_NOTIFY_SINK 로 띄워 둠(실제 전송 대신 파일에 한 줄씩 기록).
import fs from "node:fs";
import { CONSOLE, PASSWORD, STATE_DIR, TENANT_A, USER_EMAIL, USER_ID, browser, done, expect, sleep, sql } from "./lib.mjs";

const SINK = process.env.EDR_NOTIFY_SINK;
const b = await browser();
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, locale: "ko-KR", timezoneId: "Asia/Seoul" });
const p = await ctx.newPage();
const errs = [];
p.on("pageerror", (e) => errs.push(String(e).slice(0, 160)));
const setRole = (role) => sql(`update tenant_members set role = '${role}' where user_id = '${USER_ID}'`);
const toast = async (re) => p.locator("[data-sonner-toast]").filter({ hasText: re }).first().waitFor({ timeout: 10000 }).then(() => true).catch(() => false);
const sinkLines = () => (SINK && fs.existsSync(SINK) ? fs.readFileSync(SINK, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
async function waitSink(pred, ms = 15000) {
  for (let t = 0; t < ms; t += 500) { if (sinkLines().some(pred)) return true; await sleep(500); }
  return false;
}

try {
  await p.goto(CONSOLE + "/settings", { waitUntil: "load" });
  if (p.url().includes("/login")) {
    await p.getByLabel("이메일").fill(USER_EMAIL);
    await p.getByLabel("비밀번호").fill(PASSWORD);
    await p.getByRole("button", { name: "로그인", exact: true }).click();
    await p.waitForURL((u) => u.pathname === "/settings", { timeout: 20000 });
  }

  // ---- 1) 채널 추가(슬랙, 높음 이상) ----
  await p.getByRole("button", { name: "채널 추가" }).click();
  const dlg = p.getByRole("dialog");
  await dlg.getByLabel("채널 이름").fill("통합시험 슬랙");
  await dlg.getByLabel("채널 종류").selectOption("slack");
  await dlg.getByLabel("보내는 기준").selectOption("high");
  await dlg.getByLabel("비밀값 키 이름").fill("SLACK_WEBHOOK_SOC");
  await dlg.getByRole("button", { name: "추가" }).click();
  expect("채널 추가(안내)", await toast(/알림 채널을 추가했습니다/));
  expect("DB: 채널 저장", sql(`select kind || ':' || min_severity || ':' || enabled from notification_channels where tenant_id='${TENANT_A}' and name='통합시험 슬랙'`) === "slack:high:true");
  expect("화면에 채널 표시", (await p.locator("main").innerText()).includes("통합시험 슬랙"));

  // ---- 2) 경보 발생 → 조건에 맞으면 적재 → enricher 가 SINK 로 발송 ----
  const chId = sql(`select id from notification_channels where tenant_id='${TENANT_A}' and name='통합시험 슬랙'`);
  const dev = sql(`select id from devices where tenant_id='${TENANT_A}' limit 1`);
  // 높음 경보 → 적재·발송
  sql(`insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key) values ('${TENANT_A}','${dev}','EDR-AUTH-001','high','통합시험 경보','{}','it-notify-high')`);
  expect("높음 경보 발송(SINK 도착)", await waitSink((x) => String(x.channel_id) === chId && x.msg.title === "통합시험 경보"));
  expect("발송 메시지에 MITRE 전술", sinkLines().some((x) => x.msg.title === "통합시험 경보" && x.msg.tactic === "Credential Access"));
  expect("DB: 발송 완료 표시", sql(`select status from notification_outbox where channel_id=${chId} and payload->>'title'='통합시험 경보'`) === "sent");
  // 낮은 심각도 경보 → 적재 안 됨
  sql(`insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key) values ('${TENANT_A}','${dev}','EDR-NET-001','low','낮은 경보','{}','it-notify-low')`);
  await sleep(1000);
  expect("낮은 경보는 적재 안 됨", sql(`select count(*) from notification_outbox where channel_id=${chId} and payload->>'title'='낮은 경보'`) === "0");

  // ---- 3) 테스트 발송 버튼 ----
  await p.getByRole("button", { name: "통합시험 슬랙 테스트 알림" }).click();
  expect("테스트 발송(안내)", await toast(/테스트 알림을 대기열에 넣었습니다/));
  expect("테스트 알림 SINK 도착", await waitSink((x) => String(x.channel_id) === chId && x.msg.test === true));

  // ---- 4) 권한: 분석가는 알림 패널이 안 보임 ----
  setRole("analyst");
  await p.goto(CONSOLE + "/settings", { waitUntil: "load" });
  await p.waitForTimeout(400);
  expect("분석가에겐 알림 연동 패널 없음", !(await p.locator("main").innerText()).includes("알림 연동"));
  setRole("owner");

  // ---- 5) 수정·삭제 → 감사 기록 ----
  await p.goto(CONSOLE + "/settings", { waitUntil: "load" });
  await p.getByRole("button", { name: "통합시험 슬랙 수정" }).click();
  const dlg2 = p.getByRole("dialog");
  await dlg2.getByLabel("보내는 기준").selectOption("critical");
  await dlg2.getByRole("button", { name: "저장" }).click();
  expect("채널 수정(안내)", await toast(/알림 채널을 바꿨습니다/));
  expect("DB: 심각도 바뀜", sql(`select min_severity from notification_channels where id=${chId}`) === "critical");

  const audit = sql(`select string_agg(action, ',' order by id) from audit_log where action like 'notification.%'`);
  expect("감사 기록(추가·수정)", audit === "notification.channel.create,notification.channel.update", audit);

  const t = await p.goto(CONSOLE + "/settings?audit=notification").then(() => p.locator("main").innerText());
  expect("감사 기록 화면(알림 연동 거르기)", t.includes("알림 채널 추가") && t.includes("알림 채널 변경"));

  expect("브라우저 오류 없음", errs.length === 0, errs.join(" | "));
} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
} finally {
  setRole("owner");
  await b.close();
  done("10 알림 연동");
}
