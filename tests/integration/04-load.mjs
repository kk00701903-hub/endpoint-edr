// 4단계: 동시 전송 부하 — PC 여러 대가 같은 프로그램(같은 해시)을 동시에 보내도 교착 상태·오류가 없어야 한다.
// (2026-10-02 발견: 해시 기록 잠금 순서가 엇갈려 300대 동시 전송 시 수집이 멈춤 → 수정 후 회귀 시험으로 유지)
import zlib from "node:zlib";
import { INGEST, TENANT_A, done, expect, sql } from "./lib.mjs";

const N = Number(process.env.EDR_IT_LOAD_DEVICES ?? 150), ROUNDS = Number(process.env.EDR_IT_LOAD_ROUNDS ?? 3), CONC = Number(process.env.EDR_IT_LOAD_CONC ?? 48);
const tok = (i) => "edr_dev_" + i.toString(16).padStart(64, "0");

// 부하용 장치는 DB 에 직접 만든다(등록 API 는 IP 당 분당 30회 제한)
sql(`insert into devices (tenant_id, hostname, token_hash, os_version, agent_version)
     select '${TENANT_A}', format('LOAD-PC-%s', lpad(g::text, 4, '0')), extensions.digest('edr_dev_' || lpad(to_hex(g), 64, '0'), 'sha256'), 'Windows 11 23H2', '0.3.0'
     from generate_series(1, ${N}) g on conflict do nothing`);

function batch(i, round) {
  const t = new Date().toISOString();
  return { agent_version: "0.3.0", hostname: `LOAD-PC-${String(i).padStart(4, "0")}`, sent_at: t, snapshot: round === 0,
    processes: Array.from({ length: round === 0 ? 150 : 20 }, (_, k) => ({ pid: 1000 + round * 200 + k, ppid: 4, name: ["chrome.exe", "svchost.exe", "Teams.exe", "outlook.exe", "explorer.exe"][k % 5],
      path: "C:\\Program Files\\App\\app.exe", command_line: `app.exe --id=${k}`, user: `CORP\\u${i}`, sha256: (k % 40).toString(16).padStart(2, "0").repeat(32), create_time: t, observed_at: t })),
    connections: Array.from({ length: 40 }, (_, k) => ({ proto: "tcp4", direction: "outbound", local_ip: "10.1.0." + (i % 250), local_port: 50000 + k, remote_ip: `20.${k}.${i % 200}.${round}`, remote_port: 443, state: "ESTABLISHED", pid: 1000 + k, process_name: "chrome.exe", is_external: true, observed_at: t })),
    security_events: Array.from({ length: 15 }, (_, k) => ({ channel: "Security", provider: "Microsoft-Windows-Security-Auditing", event_id: k % 3 ? 4624 : 4634, record_id: round * 1000 + k + 1, event_time: t, target_user: `u${i}`, logon_type: 3, src_ip: "10.1.0.10" })),
    health: { uptime_sec: 1000, cpu_percent: 0.5, working_set_mb: 35, goroutines: 14, spool_files: 0, spool_bytes: 0, scan_ms: { process: 40 } } };
}

const jobs = [];
for (let r = 0; r < ROUNDS; r++) for (let i = 1; i <= N; i++) jobs.push([i, r]);
const lat = [], codes = {};
let rows = 0;
const t0 = performance.now();
await Promise.all(Array.from({ length: CONC }, async () => {
  while (jobs.length) {
    const [i, r] = jobs.shift();
    const env = batch(i, r);
    rows += env.processes.length + env.connections.length + env.security_events.length;
    const s = performance.now();
    let st;
    try {
      st = (await fetch(INGEST + "/v1/ingest", { method: "POST", headers: { Authorization: "Bearer " + tok(i), "Content-Encoding": "gzip" }, body: zlib.gzipSync(JSON.stringify(env)), signal: AbortSignal.timeout(60000) })).status;
    } catch { st = "neterr"; }
    lat.push(performance.now() - s);
    codes[st] = (codes[st] ?? 0) + 1;
  }
}));
const sec = (performance.now() - t0) / 1000;
lat.sort((a, b) => a - b);
const q = (x) => Math.round(lat[Math.floor(lat.length * x)]);
console.log(`  PC ${N}대 × ${ROUNDS}회 = ${lat.length}요청, ${sec.toFixed(1)}초, 초당 ${(lat.length / sec).toFixed(0)}요청·${(rows / sec).toFixed(0)}행, p50 ${q(0.5)}ms p95 ${q(0.95)}ms, 응답 ${JSON.stringify(codes)}`);
expect("모든 배치 수락(202)", codes[202] === lat.length, JSON.stringify(codes));
expect("p95 응답 3초 이내", q(0.95) < 3000, `${q(0.95)}ms`);
done("04 동시 전송 부하");
