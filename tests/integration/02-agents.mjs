// 2단계: 에이전트 3대를 흉내 내 실제 수집 서버(ingest)로 등록·전송하고, 수집 서버의 방어 동작을 확인한다.
// 데이터 형식은 contracts/ingest.schema.json 그대로. 공격 시나리오:
//   SRV-WEB-01 : 외부 IP 의 RDP 무차별 대입 → 성공 → 계정 생성·관리자 그룹 추가 → 서비스·자동 실행 등록 → 악성 파일 실행 → 외부 통신
//   DEV-WS-010 : 같은 공격 IP 의 무차별 대입(40분 전 일인데 이제야 도착 = 스풀 재전송)
//   DEV-LT-020 : 정상 PC
import fs from "node:fs";
import zlib from "node:zlib";
import { INGEST, STATE_DIR, done, expect, sql } from "./lib.mjs";

const key = fs.readFileSync(`${STATE_DIR}/enroll-key.txt`, "utf8").trim();
const now = Date.now();
const iso = (msAgo) => new Date(now - msAgo).toISOString();
const MAL = "e3".repeat(32);
const CLEAN = "1a".repeat(32);
const ATTACKER = "185.220.101.12";

async function enroll(hostname) {
  const r = await fetch(INGEST + "/v1/enroll", { method: "POST", body: JSON.stringify({ enrollment_key: key, hostname, os_version: "Windows Server 2022", agent_version: "0.3.0" }) });
  return { status: r.status, body: r.status === 200 ? await r.json() : await r.text() };
}
async function send(token, env, { gzip = true, raw } = {}) {
  const json = raw ?? Buffer.from(JSON.stringify(env));
  const body = gzip ? zlib.gzipSync(json) : json;
  try {
    const r = await fetch(INGEST + "/v1/ingest", { method: "POST", headers: { Authorization: "Bearer " + token, ...(gzip ? { "Content-Encoding": "gzip" } : {}), "Content-Type": "application/json" }, body });
    return r.status;
  } catch {
    return "reset"; // 서버가 큰 본문을 끊은 경우
  }
}
const base = (hostname, extra) => ({ agent_version: "0.3.0", hostname, sent_at: new Date().toISOString(), snapshot: true,
  health: { uptime_sec: 3600, cpu_percent: 0.4, working_set_mb: 38.2, goroutines: 14, spool_files: 0, spool_bytes: 0, scan_ms: { process: 42, network: 8, autoruns: 120 } }, ...extra });
const fails = (n, msAgo, user, rec0, logonType = 10) => Array.from({ length: n }, (_, i) => ({ channel: "Security", provider: "Microsoft-Windows-Security-Auditing", event_id: 4625, record_id: rec0 + i,
  event_time: iso(msAgo - i * 4000), target_user: user, logon_type: logonType, src_ip: ATTACKER, src_port: "51000", status: "0xc000006d", sub_status: "0xc000006a" }));

try {
  // --- 등록 ---
  const bad = await fetch(INGEST + "/v1/enroll", { method: "POST", body: JSON.stringify({ enrollment_key: "edr_enr_wrong", hostname: "X" }) });
  expect("잘못된 등록키 거부(403)", bad.status === 403, bad.status);
  const devs = {};
  for (const h of ["SRV-WEB-01", "DEV-WS-010", "DEV-LT-020"]) {
    const r = await enroll(h);
    expect(`${h} 등록`, r.status === 200 && String(r.body.device_token).startsWith("edr_dev_"), r.status);
    devs[h] = r.body;
  }
  fs.writeFileSync(`${STATE_DIR}/devices.json`, JSON.stringify(devs));

  // --- SRV-WEB-01 공격 흐름 ---
  const web = base("SRV-WEB-01", {
    processes: [
      { pid: 4, ppid: 0, name: "System", create_time: iso(864e5), observed_at: iso(0) },
      { pid: 700, ppid: 4, name: "services.exe", path: "C:\\Windows\\System32\\services.exe", user: "NT AUTHORITY\\SYSTEM", sha256: CLEAN, create_time: iso(864e5), observed_at: iso(0) },
      { pid: 5120, ppid: 700, name: "cmd.exe", path: "C:\\Windows\\System32\\cmd.exe", command_line: "cmd.exe /c powershell -nop -w hidden -enc SQBFAFgA", user: "SRV-WEB-01\\administrator", create_time: iso(9e5), observed_at: iso(0) },
      { pid: 5188, ppid: 5120, name: "powershell.exe", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", command_line: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", user: "SRV-WEB-01\\administrator", create_time: iso(8.9e5), observed_at: iso(0) },
      { pid: 6044, ppid: 5188, name: "upd.exe", path: "C:\\ProgramData\\upd.exe", command_line: "C:\\ProgramData\\upd.exe -k netsvc", user: "SRV-WEB-01\\administrator", sha256: MAL, create_time: iso(8e5), observed_at: iso(0) },
      { pid: 6100, ppid: 700, name: "badhash.exe", path: "C:\\x.exe", sha256: "not-a-hash", create_time: iso(7e5), observed_at: iso(0) },
    ],
    connections: [
      { proto: "tcp4", direction: "inbound", local_ip: "10.10.1.5", local_port: 3389, remote_ip: ATTACKER, remote_port: 51544, state: "ESTABLISHED", pid: 1100, process_name: "svchost.exe", is_external: true, observed_at: iso(0) },
      { proto: "tcp4", direction: "outbound", local_ip: "10.10.1.5", local_port: 50211, remote_ip: "45.9.148.3", remote_port: 443, state: "ESTABLISHED", pid: 6044, process_name: "upd.exe", is_external: true, observed_at: iso(0) },
      { proto: "tcp4", direction: "listen", local_ip: "0.0.0.0", local_port: 443, state: "LISTEN", pid: 2200, process_name: "w3wp.exe", is_external: false, observed_at: iso(0) },
    ],
    security_events: [
      ...fails(15, 12e5, "administrator", 1000),
      { channel: "Security", provider: "Microsoft-Windows-Security-Auditing", event_id: 4624, record_id: 1100, event_time: iso(10e5), target_user: "administrator", logon_type: 10, src_ip: ATTACKER },
      { channel: "Security", provider: "Microsoft-Windows-Security-Auditing", event_id: 4720, record_id: 1101, event_time: iso(9.5e5), target_user: "svc_backup", data: { SubjectUserName: "administrator" } },
      { channel: "Security", provider: "Microsoft-Windows-Security-Auditing", event_id: 4732, record_id: 1102, event_time: iso(9.4e5), target_user: "svc_backup", data: { TargetUserName: "Administrators" } },
      { channel: "System", provider: "Service Control Manager", event_id: 7045, record_id: 77, event_time: iso(8.5e5), data: { ServiceName: "NetSvcUpd", ImagePath: "C:\\ProgramData\\upd.exe" } },
    ],
    autoruns: [
      { change: "baseline", location: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", entry_name: "SecurityHealth", command: "%windir%\\system32\\SecurityHealthSystray.exe", observed_at: iso(864e5) },
      { change: "added", location: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", entry_name: "Updater", command: "C:\\ProgramData\\upd.exe -k netsvc", image_path: "C:\\ProgramData\\upd.exe", sha256: MAL, observed_at: iso(8.2e5) },
    ],
  });
  expect("SRV-WEB-01 전송(202)", (await send(devs["SRV-WEB-01"].device_token, web)) === 202);
  expect("같은 배치 재전송 수락(202)", (await send(devs["SRV-WEB-01"].device_token, web)) === 202);

  // --- DEV-WS-010: 40분 전 무차별 대입이 이제야 도착 ---
  expect("DEV-WS-010 늦은 전송", (await send(devs["DEV-WS-010"].device_token, base("DEV-WS-010", {
    processes: [{ pid: 900, ppid: 4, name: "explorer.exe", path: "C:\\Windows\\explorer.exe", user: "CORP\\kim", sha256: CLEAN, create_time: iso(3e6), observed_at: iso(0) }],
    security_events: fails(12, 24e5, "kim", 500, 3),
  }))) === 202);

  // --- DEV-LT-020: 정상 PC, 비압축 전송 ---
  expect("DEV-LT-020 비압축 전송", (await send(devs["DEV-LT-020"].device_token, base("DEV-LT-020", {
    processes: [{ pid: 1200, ppid: 4, name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", user: "CORP\\lee", sha256: CLEAN, create_time: iso(2e6), observed_at: iso(0) }],
  }), { gzip: false })) === 202);

  // --- 저장 결과 ---
  expect("보안 이벤트 재전송 중복 제거", sql("select count(*) from security_events where event_id = 4625") === "27", sql("select count(*) from security_events where event_id = 4625"));
  expect("잘못된 해시는 버림", sql("select count(*) from process_events where name = 'badhash.exe' and sha256 is not null") === "0");
  expect("에이전트 자원 사용량 저장", sql("select count(*) from devices where health is not null") === "3");
  expect("해시 평판 대기열 등록", sql(`select verdict from file_hashes where sha256 = '${MAL}'`) === "pending");

  // --- 자산 정보 · 보안 상태 (기준선: 경보는 만들지 않음) ---
  const inventory = (os, software, extra = {}) => ({ collected_at: iso(0), os, hardware: { manufacturer: "Dell Inc.", model: "PowerEdge R650", serial: "SRV7Q2K3", bios_version: "1.9.2", cpu: "Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz", cores: 32, memory_mb: 65536, disk_total_gb: 558.9, disk_free_gb: 7.5 }, domain: "CORP", domain_joined: true, last_user: "CORP\\svc.admin", adapters: [{ name: "Ethernet0", mac: "00:50:56:AA:BB:CC", ips: ["10.10.1.5"] }], software, ...extra });
  expect("SRV-WEB-01 자산 정보 전송", (await send(devs["SRV-WEB-01"].device_token, base("SRV-WEB-01", {
    inventory: inventory({ name: "Windows Server 2022 Standard", edition: "ServerStandard", display_version: "21H2", build: 20348, ubr: 2655, install_type: "Server", installed_at: "0001-01-01T00:00:00Z", arch: "amd64" }, [
      { name: "AnyDesk", version: "8.1.0", publisher: "AnyDesk Software GmbH", scope: "user" },
      { name: "WinRAR 6.11 (64-bit)", version: "6.11.0", publisher: "win.rar GmbH", install_date: "20240105", scope: "machine", arch: "x64" },
      { name: "7-Zip 24.09 (x64)", version: "24.09", publisher: "Igor Pavlov", scope: "machine", arch: "x64" },
      { name: "Bad\u0000Name Tool", version: "1.0\u0000", publisher: "X" },
    ]),
    posture: [{ id: "av_realtime", status: "pass", detail: "Microsoft Defender 실시간 감시 동작" }, { id: "firewall", status: "pass" }, { id: "wdigest", status: "pass", detail: "꺼짐" }, { id: "smb1", status: "fail", detail: "SMBv1 켜짐: 서버(SMB1=1)" }],
  }))) === 202);
  expect("DEV-WS-010 자산 정보 전송", (await send(devs["DEV-WS-010"].device_token, base("DEV-WS-010", {
    inventory: { ...inventory({ name: "Windows 11 Pro", edition: "Professional", display_version: "23H2", build: 22631, ubr: 4602, install_type: "Client" }, [
      { name: "Google Chrome", version: "130.0.6723.70", publisher: "Google LLC" }, { name: "7-Zip 23.01 (x64)", version: "23.01", publisher: "Igor Pavlov" },
    ]), hardware: { manufacturer: "LENOVO", model: "21AHCTO1WW", serial: "PF3ABC12", memory_mb: 16384, disk_total_gb: 476.3, disk_free_gb: 120.2 } },
    posture: [{ id: "av_realtime", status: "pass" }, { id: "firewall", status: "pass" }, { id: "uac", status: "pass" }],
  }))) === 202);
  expect("자산 정보 저장(OS 수명 주기·NUL 제거·Go 의 빈 시각 무시)",
    sql("select string_agg(os_label || '/' || coalesce(os_installed_at::text, '-') || '/' || software_count, ',' order by os_label) from device_inventory") === "Windows 11 23H2/-/2,Windows Server 2022/-/4"
    && sql("select count(*) from device_software where name = 'BadName Tool' and version = '1.0'") === "1",
    sql("select string_agg(os_label || '/' || coalesce(os_installed_at::text, '-') || '/' || software_count, ',') from device_inventory"));
  expect("보안 상태 저장 + 지원 종료 판단(서버)", sql("select string_agg(dp.check_id || ':' || dp.status, ',' order by dp.check_id) from device_posture dp join devices d on d.id = dp.device_id where d.hostname = 'DEV-WS-010'") === "av_realtime:pass,firewall:pass,os_supported:fail,uac:pass");
  expect("첫 자산 정보는 이력 없음(기준선)", sql("select count(*) from software_changes") === "0");
  expect("잘못된 점검 결과 거부(400)", (await send(devs["DEV-WS-010"].device_token, base("DEV-WS-010", { posture: [{ id: "av_realtime", status: "ok" }] }))) === 400);
  expect("설치 프로그램 5000개 초과 거부(413)", (await send(devs["DEV-WS-010"].device_token, base("DEV-WS-010", {
    inventory: inventory({ name: "x", build: 1 }, Array.from({ length: 5001 }, (_, i) => ({ name: `p${i}` }))) }))) === 413);

  // --- 수집 서버 방어 ---
  const lt = devs["DEV-LT-020"].device_token;
  expect("토큰 없음 거부(401)", (await send("nope", base("X", {}))) === 401);
  expect("위조 토큰 거부(401)", (await send("edr_dev_" + "0".repeat(64), base("X", {}))) === 401);
  expect("깨진 JSON 거부(400)", (await send(lt, null, { raw: Buffer.from("{not json") })) === 400);
  const badGzip = await fetch(INGEST + "/v1/ingest", { method: "POST", headers: { Authorization: "Bearer " + lt, "Content-Encoding": "gzip" }, body: "plain" });
  expect("잘못된 gzip 거부(400)", badGzip.status === 400);
  const st = await send(lt, null, { gzip: false, raw: Buffer.alloc(6 << 20, "a") });
  expect("5MB 초과 거부", st === 400 || st === 413 || st === "reset", st);
  const bomb = zlib.gzipSync(Buffer.concat([Buffer.from('{"hostname":"'), Buffer.alloc(60 << 20, "a"), Buffer.from('"}')]));
  const bombStatus = await fetch(INGEST + "/v1/ingest", { method: "POST", headers: { Authorization: "Bearer " + lt, "Content-Encoding": "gzip" }, body: bomb })
    .then((r) => r.status).catch(() => "reset");
  expect(`압축 폭탄(${(bomb.length / 1024).toFixed(0)}KB→60MB) 거부`, bombStatus === 400, bombStatus);
  expect("배치 2만 행 초과 거부(413)", (await send(lt, base("DEV-LT-020", { process_exits: Array.from({ length: 20001 }, (_, i) => ({ pid: i, observed_at: iso(0) })) }))) === 413);
  const skew = await send(lt, { agent_version: "0.3.0", hostname: "DEV-LT-020", sent_at: iso(0), snapshot: false,
    security_events: [{ channel: "Security", provider: "x", event_id: 4624, record_id: 777001, event_time: "2025-01-01T00:00:00Z", target_user: "lee", logon_type: 2 }] });
  expect("시계가 틀린 PC 의 시각은 서버 시각으로 보정", skew === 202 && sql("select count(*) from security_events where record_id = 777001 and event_time > now() - interval '1 hour'") === "1");
  const codes = [];
  for (let i = 0; i < 32; i++) codes.push(await send(lt, base("DEV-LT-020", {})));
  expect("장치당 분당 요청 제한(429)", codes.includes(429), `${codes.indexOf(429) + 1}번째부터`);

} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
} finally {
  done("02 에이전트 → 수집 서버");
}
