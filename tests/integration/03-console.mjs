// 3단계: 실제로 수집·탐지된 데이터로 콘솔 화면·조사 흐름·권한·조직 격리·감사 기록을 확인한다.
import { CONSOLE, STATE_DIR, SUPABASE, TENANT_A, TENANT_B, USER_ID, browser, done, expect, sql } from "./lib.mjs";

const MAL = "e3".repeat(32);
const b = await browser();
const ctx = await b.newContext({ storageState: `${STATE_DIR}/state.json`, viewport: { width: 1440, height: 900 }, locale: "ko-KR", timezoneId: "Asia/Seoul" });
const p = await ctx.newPage();
const errs = [];
p.on("pageerror", (e) => errs.push(String(e).slice(0, 160)));
const timings = [];
async function go(path) {
  const t0 = Date.now();
  const r = await p.goto(CONSOLE + path, { waitUntil: "load" });
  timings.push([path.slice(0, 70), Date.now() - t0, r?.status()]);
  await p.waitForTimeout(400);
  return (await p.locator("main").innerText()).replace(/\s+/g, " ");
}
const setRole = (role) => sql(`update tenant_members set role = '${role}' where user_id = '${USER_ID}'`);

try {
  // 다른 조직 데이터(B사) — A사 사용자에게 절대 보이면 안 됨
  sql(`insert into devices (id, tenant_id, hostname, token_hash) values ('d0000000-0000-0000-0000-0000000000bb', '${TENANT_B}', 'B-SECRET-PC', '\\x0b') on conflict do nothing`);
  sql(`insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time) values ('${TENANT_B}', 'd0000000-0000-0000-0000-0000000000bb', 'Security', 1, 1102, now()) on conflict do nothing`);
  sql("select public.edr_run_detections()", "edr_enricher");

  // 평판 결과 도착(enricher 가 VirusTotal 응답을 저장하는 것과 같은 UPDATE) → 악성 실행 경보가 즉시 생기고 같은 인시던트에 붙어야 함
  sql(`update file_hashes set verdict = 'malicious', vt_malicious = 54, vt_total = 72, checked_at = now() where sha256 = '${MAL}'`, "edr_enricher");
  expect("악성 판정 → 즉시 경보(EDR-MAL-001)", sql("select count(*) from alerts where rule_id = 'EDR-MAL-001'") === "1");

  const inc = sql(`select id from incidents where tenant_id = '${TENANT_A}' and 'EDR-MAL-001' = any (rule_ids)`);
  const incB = sql(`select id from incidents where tenant_id = '${TENANT_B}'`);
  const alertCount = Number(sql(`select alert_count from incidents where id = ${inc}`));
  const devCount = Number(sql(`select cardinality(device_ids) from incidents where id = ${inc}`));
  const srv = sql("select id from devices where hostname = 'SRV-WEB-01'");
  expect("탐지: 늦게 도착한 무차별 대입도 탐지(EDR-AUTH-001 2대)", sql("select count(distinct device_id) from alerts where rule_id = 'EDR-AUTH-001'") === "2");
  expect("탐지: 공격 경보가 인시던트 하나로 묶임(공유 IP 로 2대)", devCount === 2 && alertCount >= 9, `장치 ${devCount}, 경보 ${alertCount}`);

  // 현황
  let t = await go("/");
  expect("현황: 긴급 인시던트", /처리할 인시던트 \d+건, 그중 긴급 \d+건/.test(t), t.slice(0, 50));
  expect("현황: 다른 조직 데이터 없음", !/B-SECRET|감사 로그가 삭제/.test(t));

  // 인시던트
  t = await go("/incidents");
  expect("인시던트 목록", t.includes("다단계 공격 의심"));
  expect("다른 조직 인시던트 안 보임", !t.includes("감사 로그가 삭제"));
  t = await go(`/incidents/${incB}`);
  expect("다른 조직 인시던트 URL 직접 접근 차단", /찾는 항목이 없습니다/.test(t));
  t = await go(`/incidents/${inc}`);
  expect("자동 요약 헤드라인", t.includes(`장치 ${devCount}대에서`) && t.includes(`경보 ${alertCount}건`));
  expect("요약: 공격 흐름", /무차별 대입/.test(t) && /평판 악성 파일 실행\(upd\.exe/.test(t));
  expect("권고: 공격 IP 차단", t.includes("185.220.101.12 차단"));
  const graph = await p.locator("svg[role=img][aria-label^='공격 그래프']").getAttribute("aria-label").catch(() => "");
  expect("공격 그래프", /노드 \d+개/.test(graph ?? ""), graph);
  await p.getByRole("button", { name: /^프로세스 upd\.exe/ }).first().click();
  expect("그래프 노드 상세", (await p.locator("aside[aria-label='노드 상세']").innerText()).includes("C:\\ProgramData\\upd.exe"));
  t = await go(`/incidents/${inc}?tab=evidence`);
  expect("증거: 외부 IP", t.includes("185.220.101.12"));

  // 엔터티 · ATT&CK
  t = await go("/entities/ip/185.220.101.12");
  expect("IP 프로필: 장치 2대", t.includes("SRV-WEB-01") && t.includes("DEV-WS-010"));
  t = await go("/entities/hash/" + MAL);
  expect("해시 프로필: 악성 54/72", /악성/.test(t) && /54/.test(t));
  t = await go("/attack");
  expect("ATT&CK 매트릭스 적중", /T1110/.test(t));

  // 헌팅
  const hunt = async (q) => {
    const s = await go(`/hunt?q=${encodeURIComponent(q)}&h=168`);
    const m = s.match(/(프로세스|네트워크 연결|보안 이벤트|자동 실행) ([\d,]+)건/);
    return { n: m ? Number(m[2].replace(/,/g, "")) : s.includes("조건에 맞는 기록이 없습니다") ? 0 : null, s };
  };
  let r = await hunt('process.cmdline ~ "-enc"');
  expect("헌팅: 인코딩 PowerShell", r.n >= 2, r.n);
  r = await hunt("event.id = 4625 and event.src_ip = 185.220.101.12");
  expect("헌팅: 로그온 실패 27건", r.n === 27, r.n);
  r = await hunt("device.hostname = SRV-WEB-01 and process.name = upd.exe");
  expect("헌팅: 장치 + 프로세스", r.n >= 1, r.n);
  r = await hunt("185.220.101.12");
  expect("헌팅: 값만 입력", r.n >= 1, r.n);
  r = await hunt("device.hostname = B-SECRET-PC and event.id = 1102");
  expect("헌팅: 다른 조직 0건", r.n === 0, r.n ?? r.s.slice(0, 160));
  r = await hunt("process.nmae = x");
  expect("헌팅: 문법 오류 안내", r.s.includes("알 수 없는 필드"));

  // 장치
  t = await go("/devices");
  expect("장치 목록(다른 조직 제외)", t.includes("SRV-WEB-01") && !t.includes("B-SECRET"));
  t = await go(`/devices/${srv}`);
  expect("장치 상세: 프로세스 트리·자원", t.includes("upd.exe") && /38(\.2)?\s?MB/.test(t));

  // 시스템 상태
  t = await go("/settings");
  expect("시스템 상태: 탐지·파티션 정상", /시스템 상태/.test(t) && /탐지 실행 정상/.test(t) && /저장 공간\(월 파티션\) 정상/.test(t), (t.match(/시스템 상태 [^.]{0,30}/) || [""])[0]);

  // 조사 흐름(쓰기)
  await go(`/hunt?q=${encodeURIComponent('process.cmdline ~ "-enc"')}`);
  await p.getByRole("button", { name: "저장" }).click();
  await p.getByPlaceholder(/서버 인코딩/).fill("인코딩 PowerShell");
  await p.getByRole("dialog").getByRole("button", { name: "저장" }).click();
  await p.waitForTimeout(1500);
  expect("쿼리 저장", sql("select count(*) from saved_queries") === "1");
  await go(`/incidents/${inc}`);
  await p.getByRole("button", { name: /조사 시작/ }).click();
  await p.waitForTimeout(1500);
  expect("조사 시작", sql(`select status from incidents where id = ${inc}`) === "acknowledged");
  await p.getByLabel("처리 메모").fill("공격자 IP 방화벽 차단 요청함");
  await p.getByRole("button", { name: "메모 남기기" }).click();
  // 저장 성공 시 입력칸이 비워짐. getByText 만 쓰면 textarea 내용과 바로 매칭되어 레이스가 난다.
  await p.waitForFunction(() => {
    const el = document.querySelector('textarea[aria-label="처리 메모"]');
    return el instanceof HTMLTextAreaElement && el.value === "";
  }, null, { timeout: 8000 });
  await p.locator("ol li", { hasText: "공격자 IP 방화벽 차단 요청함" }).waitFor({ timeout: 5000 });
  expect("메모 저장", sql("select count(*) from incident_comments") === "1");
  await p.getByRole("button", { name: "인시던트 종결" }).click();
  await p.waitForTimeout(1500);
  expect("종결 → 묶인 경보 모두 종결", sql(`select count(*) from alerts where incident_id = ${inc} and status <> 'closed'`) === "0");
  await go("/rules");
  const before = await p.getByRole("switch").first().getAttribute("aria-checked");
  await p.getByRole("switch").first().click(); await p.waitForTimeout(1500);
  expect("탐지 규칙 끄기", (await p.getByRole("switch").first().getAttribute("aria-checked")) !== before);
  await p.getByRole("switch").first().click(); await p.waitForTimeout(1500);

  // 감사 기록
  const actions = sql("select string_agg(action, ',' order by id) from audit_log");
  // 인시던트 조사 시작·종결에 딸린 경보 변경은 인시던트 한 줄로만 남아야 함
  expect("감사 기록(DB)", ["enrollment_key.create", "incident.update", "incident.close", "rule.disable", "rule.enable"].every((a) => actions.includes(a)) && !actions.includes("alert."), actions);
  t = await go("/settings");
  expect("감사 기록 화면", t.includes("인시던트 종결") && t.includes("탐지 규칙 끔") && t.includes("등록키 발급"));

  // 뷰어 권한 + API 직접 호출
  setRole("viewer");
  t = await go(`/incidents/${inc}`);
  expect("뷰어: 조치 버튼 없음", (await p.getByRole("button", { name: /인시던트 종결|조사 시작|다시 열기/ }).count()) === 0);
  t = await go("/settings");
  expect("뷰어: 등록키·감사 기록 숨김", (await p.getByRole("button", { name: "등록키 만들기" }).count()) === 0 && !t.includes("고치거나 지울 수 없습니다"));
  const tok = await (await fetch(`${SUPABASE}/auth/v1/token?grant_type=password`, { method: "POST", body: JSON.stringify({ email: "secops@corp.example", password: process.env.EDR_IT_PASSWORD ?? "correct-horse" }) })).json();
  const H = { Authorization: "Bearer " + tok.access_token, apikey: "x", "Content-Type": "application/json", Prefer: "return=representation" };
  let res = await fetch(`${SUPABASE}/rest/v1/alerts?incident_id=eq.${inc}`, { method: "PATCH", headers: H, body: JSON.stringify({ status: "open" }) });
  expect("뷰어: API 로 경보 수정 거부", res.status >= 400 || (await res.json()).length === 0, res.status);
  res = await fetch(`${SUPABASE}/rest/v1/rpc/create_enrollment_key`, { method: "POST", headers: H, body: JSON.stringify({ p_tenant: TENANT_A, p_label: "x", p_max_uses: 1, p_days: 1 }) });
  expect("뷰어: API 로 등록키 발급 거부", res.status >= 400, res.status);
  res = await fetch(`${SUPABASE}/rest/v1/audit_log?select=id`, { headers: H });
  expect("뷰어: API 로 감사 기록 조회 0건", (await res.json()).length === 0);
  res = await fetch(`${SUPABASE}/rest/v1/audit_log`, { method: "DELETE", headers: H });
  expect("감사 기록 삭제 불가", res.status >= 400 || sql("select count(*) from audit_log") !== "0", res.status);
  res = await fetch(`${SUPABASE}/rest/v1/devices?select=hostname`, { headers: H });
  expect("API 로도 다른 조직 장치 안 보임", !(await res.json()).some((d) => d.hostname === "B-SECRET-PC"));
  res = await fetch(`${SUPABASE}/rest/v1/process_events`, { method: "POST", headers: H, body: JSON.stringify({ tenant_id: TENANT_A, device_id: srv, observed_at: new Date().toISOString(), pid: 1, name: "fake" }) });
  expect("사용자 계정으로 텔레메트리 위조 거부", res.status >= 400, res.status);
  setRole("owner");

  // 로그아웃
  await go("/");
  await p.getByRole("button", { name: /로그아웃/ }).click();
  await p.waitForTimeout(1500);
  await p.goto(CONSOLE + "/incidents", { waitUntil: "load" });
  expect("로그아웃 후 보호", p.url().includes("/login"));
  expect("브라우저 오류 없음", errs.length === 0, errs.join(" | "));
} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
  setRole("owner");
} finally {
  await b.close();
  const slow = timings.filter(([, ms]) => ms > 2000);
  console.log(`\n  화면 응답: ${timings.length}회, 최대 ${Math.max(...timings.map(([, ms]) => ms))}ms${slow.length ? `, 2초 초과 ${slow.map(([u]) => u).join(", ")}` : ""}`);
  done("03 콘솔");
}
