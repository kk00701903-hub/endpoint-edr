import "server-only";
import { PAGE_SIZE, type DataSource } from "./source";
import { matches } from "../hunt/query";
import * as A from "./demo-assets";
import * as D from "./demo-docs";
import * as R from "./demo-remediation";
import type {
  Alert, AlertComment, AutorunRow, ConnectionRow, Device, DetectionRule, EnrollmentKey, EntityProfile, Incident, Member,
  Overview, ProcessRow, SavedQuery, Severity, Suppression, TimelineItem, TrendPoint, Viewer,
  AuditEntry, SsoGroupRole, SystemStatus, NotificationChannel,
} from "./types";

// ---------------------------------------------------------------------------
// 데모 모드: Supabase 없이 화면을 확인하기 위한 "그럴듯한" 사내 환경 예시 데이터.
// 매번 같은 결과가 나오도록 고정 시드 난수를 쓴다. 변경(경보 처리 등)은 서버 메모리에만 남는다.
// ---------------------------------------------------------------------------

function rng(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const hashStr = (s: string) => [...s].reduce((h, c) => (Math.imul(h, 31) + c.charCodeAt(0)) | 0, 7);
const pick = <T,>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;
const hex = (r: () => number, n: number) => Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join("");
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
const MIN = 60_000, HOUR = 3_600_000, DAY = 86_400_000;

const TENANT = "00000000-0000-4000-8000-00000000demo";
const ME = "00000000-0000-4000-8000-0000000000me";

const RULES: DetectionRule[] = [
  { rule_id: "EDR-AUTH-001", title: "로그온 무차별 대입", description: "같은 PC·같은 출발지에서 10분 내 로그온 실패(4625) 10회 이상", severity: "high", mitre_tactic: "Credential Access", mitre_technique: "T1110", technique_name: "Brute Force", data_source: "보안 이벤트", enabled: true },
  { rule_id: "EDR-AUTH-002", title: "무차별 대입 후 로그온 성공", description: "실패 5회 이상 직후 같은 출발지에서 네트워크/RDP 로그온 성공", severity: "critical", mitre_tactic: "Credential Access", mitre_technique: "T1110", technique_name: "Brute Force", data_source: "보안 이벤트", enabled: true },
  { rule_id: "EDR-AUTH-003", title: "외부 IP 원격 데스크톱 로그온", description: "공인 IP 에서 RDP(LogonType 10) 로그온 성공", severity: "high", mitre_tactic: "Initial Access", mitre_technique: "T1133", technique_name: "External Remote Services", data_source: "보안 이벤트", enabled: true },
  { rule_id: "EDR-LOG-001", title: "이벤트 로그 삭제", description: "보안(1102) 또는 시스템(104) 로그 삭제 — 흔적 지우기", severity: "high", mitre_tactic: "Defense Evasion", mitre_technique: "T1070.001", technique_name: "Clear Windows Event Logs", data_source: "보안 이벤트", enabled: true },
  { rule_id: "EDR-PERSIST-001", title: "새 서비스 설치", description: "서비스 설치 이벤트(7045)", severity: "medium", mitre_tactic: "Persistence", mitre_technique: "T1543.003", technique_name: "Windows Service", data_source: "보안 이벤트", enabled: true },
  { rule_id: "EDR-PERSIST-002", title: "자동 실행 항목 추가·변경", description: "Run 키·시작프로그램·서비스·예약작업 등 기준선 대비 추가/변경 (사용자·임시 경로면 high)", severity: "medium", mitre_tactic: "Persistence", mitre_technique: "T1547.001", technique_name: "Registry Run Keys / Startup Folder", data_source: "자동 실행", enabled: true },
  { rule_id: "EDR-PERSIST-003", title: "예약 작업 생성·변경", description: "예약 작업 생성(4698)/변경(4702)", severity: "medium", mitre_tactic: "Persistence", mitre_technique: "T1053.005", technique_name: "Scheduled Task", data_source: "보안 이벤트", enabled: true },
  { rule_id: "EDR-ACCT-001", title: "로컬 계정 생성", description: "계정 생성(4720)", severity: "medium", mitre_tactic: "Persistence", mitre_technique: "T1136.001", technique_name: "Create Account: Local Account", data_source: "보안 이벤트", enabled: true },
  { rule_id: "EDR-ACCT-002", title: "보안 그룹 구성원 추가", description: "보안/로컬/유니버설 그룹 구성원 추가(4728/4732/4756)", severity: "high", mitre_tactic: "Persistence", mitre_technique: "T1098", technique_name: "Account Manipulation", data_source: "보안 이벤트", enabled: true },
  { rule_id: "EDR-NET-001", title: "외부에서 RDP 연결", description: "공인 IP 로부터 3389 인바운드 연결 수립", severity: "high", mitre_tactic: "Lateral Movement", mitre_technique: "T1021.001", technique_name: "Remote Desktop Protocol", data_source: "네트워크", enabled: true },
  { rule_id: "EDR-MAL-001", title: "평판 악성 파일 실행", description: "해시 평판이 악성/의심인 파일을 최근 7일 내 실행", severity: "critical", mitre_tactic: "Execution", mitre_technique: "T1204.002", technique_name: "User Execution: Malicious File", data_source: "프로세스 + 해시 평판", enabled: true },
  { rule_id: "EDR-IOC-001", title: "위협 지표(해시) 일치", description: "등록한 위협 지표(SHA-256)와 같은 파일이 실행되거나 자동 실행 항목으로 등록됨. 지표를 등록하면 최근 7일을 소급해 찾음", severity: "high", mitre_tactic: "Execution", mitre_technique: "T1204.002", technique_name: "User Execution: Malicious File", data_source: "프로세스 + 자동 실행 + 위협 지표", enabled: true },
  { rule_id: "EDR-IOC-002", title: "위협 지표(IP) 통신", description: "등록한 위협 지표 IP·대역과 통신하거나 그 주소에서 로그온 시도. 지표를 등록하면 최근 7일을 소급해 찾음", severity: "high", mitre_tactic: "Command and Control", mitre_technique: "T1071", technique_name: "Application Layer Protocol", data_source: "네트워크 + 보안 이벤트 + 위협 지표", enabled: true },
  { rule_id: "EDR-SW-001", title: "허용되지 않은 소프트웨어 설치", description: "관리자가 금지한 소프트웨어(예: 승인되지 않은 원격 제어 도구)가 설치되어 있음. 정책을 새로 만들면 이미 설치된 PC 도 찾음", severity: "medium", mitre_tactic: "Command and Control", mitre_technique: "T1219", technique_name: "Remote Access Software", data_source: "자산(설치 프로그램)", enabled: true },
  { rule_id: "EDR-POS-001", title: "보안 기능 꺼짐", description: "실시간 악성코드 검사·Windows 방화벽이 꺼지거나 평문 자격 증명 저장(WDigest)이 켜짐 — 통과에서 실패로 바뀐 순간", severity: "high", mitre_tactic: "Defense Evasion", mitre_technique: "T1562.001", technique_name: "Impair Defenses: Disable or Modify Tools", data_source: "보안 상태 점검", enabled: true },
];

// ---------- 장치 ----------
const DEPTS = [["MGT", "LT"], ["FIN", "LT"], ["FIN", "PC"], ["DEV", "WS"], ["DEV", "LT"], ["SAL", "LT"], ["DSN", "WS"], ["HR", "PC"]] as const;
const OS = ["Windows 10.0.22631", "Windows 10.0.22631", "Windows 10.0.26100", "Windows 10.0.19045"];

function makeDevices(): Device[] {
  const r = rng(42);
  const out: Device[] = [];
  for (let i = 0; i < 58; i++) {
    const [d, t] = DEPTS[i % DEPTS.length]!;
    out.push(device(r, `${d}-${t}-${String(10 + i * 3).padStart(3, "0")}`, pick(r, OS), i));
  }
  ["SRV-FILE-01", "SRV-DC-01", "SRV-DC-02", "SRV-ERP-01", "SRV-WEB-01", "SRV-BACKUP-01"].forEach((h, j) =>
    out.push(device(r, h, "Windows 10.0.20348", 58 + j)));
  return out;
}
function device(r: () => number, hostname: string, os: string, i: number): Device {
  const lastSeen = i === 7 || i === 33 ? 4 * HOUR + r() * HOUR : i === 21 ? 3.2 * DAY : i === 49 ? 50 * MIN : r() * 90_000;
  const cpu = hostname === "SRV-FILE-01" ? 2.4 : Math.round((0.08 + r() * 0.9) * 100) / 100;
  return {
    id: `d0000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
    hostname, os_version: os, agent_version: i % 11 === 0 ? "0.1.0" : "0.2.0", status: "active",
    tags: hostname.startsWith("SRV") ? ["서버"] : [hostname.split("-")[0]!],
    last_ip: hostname.startsWith("SRV") ? `10.10.0.${10 + i}` : `10.20.${Math.floor(i / 20)}.${30 + (i % 200)}`,
    enrolled_at: iso(40 * DAY + r() * 10 * DAY), last_seen_at: iso(lastSeen),
    health: {
      uptime_sec: Math.floor(r() * 9 * 86400), cpu_percent: cpu,
      working_set_mb: Math.round((26 + r() * 30 + (hostname.startsWith("SRV") ? 18 : 0)) * 10) / 10,
      goroutines: 9 + Math.floor(r() * 4), spool_files: i === 49 ? 6 : 0, spool_bytes: i === 49 ? 412_000 : 0,
      scan_ms: { process: Math.floor(18 + r() * 60), network: Math.floor(2 + r() * 8), eventlog: Math.floor(3 + r() * 30), autoruns: Math.floor(120 + r() * 400) },
      last_errors: i === 49 ? ["10:12:04 network scan: GetExtendedTcpTable failed: 87"] : [],
    },
    health_at: iso(lastSeen + r() * 4 * MIN),
  };
}

// ---------- 경보 ----------
type Seed = { rule: string; sev: Severity; title: (h: string, r: () => number) => string; details: (r: () => number) => Record<string, unknown>; weight: number };
const ATTACK_IPS = ["203.0.113.47", "198.51.100.23", "185.220.101.12", "194.26.29.110"];
const SEEDS: Seed[] = [
  { rule: "EDR-AUTH-001", sev: "high", weight: 14, title: (_h, r) => `로그온 무차별 대입 의심 (${pick(r, ATTACK_IPS)})`,
    details: (r) => ({ src_ip: pick(r, ATTACK_IPS), failures: 10 + Math.floor(r() * 140), users: ["administrator", "admin"], logon_types: [10], window_minutes: 10 }) },
  { rule: "EDR-PERSIST-002", sev: "medium", weight: 22, title: (_h, r) => `자동 실행 항목 추가: ${pick(r, ["OneDrive", "Zoom", "GoogleUpdateTaskMachineUA", "AdobeAAMUpdater", "TeamsMachineInstaller", "updater"])}`,
    details: (r) => ({ location: pick(r, ["HKU\\S-1-5-21-…\\Run", "ScheduledTask", "HKLM\\…\\Run"]), entry: "OneDrive", command: "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background", change: "added" }) },
  { rule: "EDR-PERSIST-001", sev: "medium", weight: 10, title: (_h, r) => `새 서비스 설치: ${pick(r, ["GoogleUpdater", "MozillaMaintenance", "edgeupdate", "PSEXESVC", "AnyDesk"])}`,
    details: () => ({ event_id: 7045 }) },
  { rule: "EDR-PERSIST-003", sev: "medium", weight: 9, title: (_h, r) => `예약 작업 생성: ${pick(r, ["\\Microsoft\\Office\\Office Feature Updates", "\\OneDrive Reporting Task", "\\SystemUpdate"])}`,
    details: () => ({ event_id: 4698 }) },
  { rule: "EDR-ACCT-002", sev: "high", weight: 3, title: () => "로컬 그룹에 구성원 추가: Administrators", details: () => ({ event_id: 4732 }) },
  { rule: "EDR-AUTH-003", sev: "high", weight: 2, title: (_h, r) => `외부 IP 에서 원격 데스크톱 로그온: administrator ← ${pick(r, ATTACK_IPS)}`,
    details: (r) => ({ src_ip: pick(r, ATTACK_IPS), user: "administrator" }) },
  { rule: "EDR-NET-001", sev: "high", weight: 2, title: (_h, r) => `외부에서 RDP 포트로 연결됨: ${pick(r, ATTACK_IPS)}`, details: (r) => ({ remote_ip: pick(r, ATTACK_IPS), remote_port: 50000 + Math.floor(r() * 9999), process: "svchost.exe" }) },
  { rule: "EDR-ACCT-001", sev: "medium", weight: 2, title: () => "로컬 계정 생성: support$", details: () => ({ event_id: 4720 }) },
  { rule: "EDR-LOG-001", sev: "high", weight: 1, title: () => "보안 감사 로그가 삭제됨", details: () => ({ event_id: 1102 }) },
  { rule: "EDR-MAL-001", sev: "critical", weight: 1, title: () => "평판 악성 파일 실행: invoice_0923.exe",
    details: () => ({ sha256: "9f2c4e7a1b0d3c5e8f6a4b2c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e", path: "C:\\Users\\kim.js\\Downloads\\invoice_0923.exe", vt_malicious: 47, vt_total: 72 }) },
];

function makeAlerts(devices: Device[]): Alert[] {
  const r = rng(7);
  const total = SEEDS.reduce((s, x) => s + x.weight, 0);
  const out: Alert[] = [];
  for (let i = 0; i < 168; i++) {
    let w = r() * total;
    const seed = SEEDS.find((s) => (w -= s.weight) < 0) ?? SEEDS[0]!;
    const dev = seed.rule.startsWith("EDR-AUTH") || seed.rule === "EDR-NET-001"
      ? pick(r, devices.filter((d) => d.hostname.startsWith("SRV") || d.hostname.startsWith("DEV")))
      : pick(r, devices);
    // 최근일수록 촘촘하게
    const age = Math.pow(r(), 1.8) * 14 * DAY;
    const createdAgo = age;
    const status = createdAgo < 30 * HOUR ? (r() < 0.75 ? "open" : "acknowledged") : r() < 0.08 ? "acknowledged" : "closed";
    const sev = seed.rule === "EDR-PERSIST-002" && r() < 0.18 ? "high" : seed.sev;
    out.push({
      id: 1000 + i, device_id: dev.id, hostname: dev.hostname, rule_id: seed.rule, severity: sev,
      title: seed.title(dev.hostname, r), details: seed.details(r), status,
      resolution: status === "closed" ? pick(r, ["benign", "benign", "false_positive", "true_positive"] as const) : null,
      assigned_to: status === "acknowledged" ? ME : null, created_at: iso(createdAgo), updated_at: iso(Math.max(0, createdAgo - 40 * MIN)),
    });
  }
  // 오늘의 주요 사건 하나: 무차별 대입 → 성공 → 악성 실행 (SRV-WEB-01)
  const web = devices.find((d) => d.hostname === "SRV-WEB-01")!;
  const story: [string, Severity, string, number, Record<string, unknown>][] = [
    ["EDR-AUTH-001", "high", "로그온 무차별 대입 의심 (45.155.205.99)", 3.1 * HOUR, { src_ip: "45.155.205.99", failures: 214, users: ["administrator", "admin", "test"], logon_types: [10], window_minutes: 10 }],
    ["EDR-AUTH-002", "critical", "무차별 대입 후 로그온 성공: administrator ← 45.155.205.99", 2.7 * HOUR, { src_ip: "45.155.205.99", user: "administrator", logon_type: 10, failures_before: 214 }],
    ["EDR-ACCT-001", "medium", "로컬 계정 생성: support$", 2.5 * HOUR, { event_id: 4720 }],
    ["EDR-PERSIST-002", "high", "자동 실행 항목 추가: WinSvcHelper", 2.4 * HOUR, { location: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", entry: "WinSvcHelper", command: "C:\\ProgramData\\svch\\svchelper.exe -k", image_path: "C:\\ProgramData\\svch\\svchelper.exe", change: "added" }],
    ["EDR-MAL-001", "critical", "평판 악성 파일 실행: svchelper.exe", 2.2 * HOUR, { sha256: "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b", path: "C:\\ProgramData\\svch\\svchelper.exe", vt_malicious: 52, vt_total: 71 }],
    ["EDR-LOG-001", "high", "보안 감사 로그가 삭제됨", 2.0 * HOUR, { event_id: 1102 }],
    ["EDR-POS-001", "high", "보안 기능 꺼짐: 평문 자격 증명 저장 안 함", 2.3 * HOUR, { check_id: "wdigest", check: "평문 자격 증명 저장 안 함", detail: "WDigest 평문 자격 증명 저장 켜짐(UseLogonCredential=1)", previous: "pass" }],
    ["EDR-IOC-002", "high", "위협 지표(IP)에서 로그온 시도: 45.155.205.99", 2.1 * HOUR, { ioc_id: 1, ioc_type: "ip", ioc_value: "45.155.205.99", ioc_description: "SRV-WEB-01 무차별 대입 출발지(사내 분석)", src_ip: "45.155.205.99", user: "administrator", source: "logon" }],
  ];
  story.forEach(([rule, sev, title, ago, details], j) => out.push({
    id: 2000 + j, device_id: web.id, hostname: web.hostname, rule_id: rule, severity: sev, title, details,
    status: "open", resolution: null, assigned_to: null, created_at: iso(ago), updated_at: iso(ago),
  }));
  // 금지 소프트웨어(AnyDesk) 설치 — 3일 전, 영업팀 노트북
  const sal = devices.find((d) => d.hostname === "SAL-LT-025");
  if (sal) out.push({ id: 2100, device_id: sal.id, hostname: sal.hostname, rule_id: "EDR-SW-001", severity: "high", title: "허용되지 않은 소프트웨어 설치: AnyDesk",
    details: { software: "AnyDesk", version: "8.1.0", publisher: "AnyDesk Software GmbH", policy_id: 6, policy: "AnyDesk", reason: "승인되지 않은 원격 제어 도구 — 사내 원격 지원은 승인된 도구만" },
    status: "acknowledged", resolution: null, assigned_to: ME, created_at: iso(3 * DAY - 20 * MIN), updated_at: iso(2 * DAY) });
  // Wazuh(외부 오픈소스 EDR)에서 받은 경보 — 같은 화면에서 함께 봄
  if (sal) out.push({ id: 2200, device_id: sal.id, hostname: sal.hostname, rule_id: "WAZUH-5710", severity: "high", source: "wazuh",
    title: "[Wazuh] sshd: 존재하지 않는 사용자로 로그인 시도 — SAL-LT-025",
    details: { wazuh: true, wazuh_rule_id: "5710", level: 10, agent: "SAL-LT-025", src_ip: "203.0.113.44", location: "/var/log/auth.log", mitre_technique: ["T1110"], full_log: "Failed password for invalid user admin from 203.0.113.44" },
    status: "open", resolution: null, assigned_to: null, created_at: iso(5 * HOUR), updated_at: iso(5 * HOUR) });
  out.push({ id: 2201, device_id: web.id, hostname: web.hostname, rule_id: "WAZUH-100100", severity: "critical", source: "wazuh",
    title: "[Wazuh] 무결성 검사: 시스템 파일 체크섬 변경 — " + web.hostname,
    details: { wazuh: true, wazuh_rule_id: "100100", level: 13, agent: web.hostname, location: "syscheck", full_log: "File '/etc/pam.d/sshd' checksum changed" },
    status: "open", resolution: null, assigned_to: null, created_at: iso(6 * HOUR), updated_at: iso(6 * HOUR) });
  return out.sort((a, b) => b.created_at.localeCompare(a.created_at));
}

// ---------- 프로세스 (장치별로 결정적 생성) ----------
function makeProcesses(dev: Device): ProcessRow[] {
  const r = rng(hashStr(dev.id));
  let pid = 4;
  const rows: ProcessRow[] = [];
  const boot = Date.now() - (dev.health?.uptime_sec ?? 86400) * 1000;
  const add = (name: string, ppid: number | null, path: string | null, cmd: string | null, user: string | null, startAfter = 0): number => {
    pid += 4 * (1 + Math.floor(r() * 60));
    rows.push({ pid, ppid, create_time: new Date(boot + startAfter).toISOString(), name, path, command_line: cmd, username: user,
      sha256: path ? hex(r, 64) : null, verdict: path ? "clean" : null, first_seen_at: new Date(boot + startAfter).toISOString() });
    return pid;
  };
  const SYS = "NT AUTHORITY\\SYSTEM", user = `CORP\\${pick(r, ["kim.js", "lee.hy", "park.sm", "choi.dw", "jung.ek"])}`;
  rows.push({ pid: 4, ppid: 0, create_time: new Date(boot).toISOString(), name: "System", path: null, command_line: null, username: null, sha256: null, verdict: null, first_seen_at: new Date(boot).toISOString() });
  const smss = add("smss.exe", 4, "C:\\Windows\\System32\\smss.exe", "\\SystemRoot\\System32\\smss.exe", SYS, 2000);
  add("csrss.exe", smss, null, null, null, 3000);
  const wininit = add("wininit.exe", smss, "C:\\Windows\\System32\\wininit.exe", "wininit.exe", SYS, 3500);
  const services = add("services.exe", wininit, null, null, null, 3700);
  add("lsass.exe", wininit, null, null, null, 3800);
  for (const k of ["DcomLaunch", "RPCSS", "LocalServiceNetworkRestricted", "netsvcs", "NetworkService", "LocalSystemNetworkRestricted", "utcsvc"])
    add("svchost.exe", services, "C:\\Windows\\System32\\svchost.exe", `C:\\Windows\\system32\\svchost.exe -k ${k} -p`, SYS, 5000 + r() * 4000);
  add("spoolsv.exe", services, "C:\\Windows\\System32\\spoolsv.exe", "C:\\Windows\\System32\\spoolsv.exe", SYS, 9000);
  add("MsMpEng.exe", services, "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25080.5-0\\MsMpEng.exe", null, SYS, 9500);
  add("SecAgentSvc.exe", services, "C:\\Program Files\\CorpSecurity\\SecAgentSvc.exe", "\"C:\\Program Files\\CorpSecurity\\SecAgentSvc.exe\" -service", SYS, 10000);
  add("edr-agent.exe", services, "C:\\Program Files\\EndpointEDR\\edr-agent.exe", "\"C:\\Program Files\\EndpointEDR\\edr-agent.exe\"", SYS, 70_000);
  if (dev.hostname.startsWith("SRV")) {
    add("sqlservr.exe", services, "C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe", "sqlservr.exe -sMSSQLSERVER", "NT SERVICE\\MSSQLSERVER", 12000);
    add("w3wp.exe", services, "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap \"DefaultAppPool\"", "IIS APPPOOL\\DefaultAppPool", 15000);
    if (dev.hostname === "SRV-WEB-01") {
      const ex = Date.now() - 2.2 * HOUR - boot;
      const cmd = add("cmd.exe", services, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c C:\\ProgramData\\svch\\svchelper.exe -k", SYS, ex);
      const mal = add("svchelper.exe", cmd, "C:\\ProgramData\\svch\\svchelper.exe", "C:\\ProgramData\\svch\\svchelper.exe -k", SYS, ex + 900);
      const m = rows.find((x) => x.pid === mal)!;
      m.sha256 = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";
      m.verdict = "malicious";
      add("powershell.exe", mal, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", SYS, ex + 2000);
    }
  } else {
    const winlogon = add("winlogon.exe", smss, "C:\\Windows\\System32\\winlogon.exe", "winlogon.exe", SYS, 4000);
    add("dwm.exe", winlogon, "C:\\Windows\\System32\\dwm.exe", "\"dwm.exe\"", "Window Manager\\DWM-1", 4500);
    const explorer = add("explorer.exe", null, "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", user, 40_000);
    const chrome = add("chrome.exe", explorer, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", user, 60_000);
    for (const t of ["gpu-process", "utility", "renderer", "renderer", "renderer"])
      add("chrome.exe", chrome, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", `"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=${t}`, user, 61_000);
    add("ms-teams.exe", explorer, "C:\\Program Files\\WindowsApps\\MSTeams_25198.1112.3855.2511_x64__8wekyb3d8bbwe\\ms-teams.exe", "ms-teams.exe", user, 65_000);
    add("OUTLOOK.EXE", explorer, "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "\"OUTLOOK.EXE\"", user, 70_000);
    if (dev.hostname.startsWith("DEV")) {
      const code = add("Code.exe", explorer, `C:\\Users\\${user.split("\\")[1]}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe`, "Code.exe", user, 90_000);
      add("node.exe", code, "C:\\Program Files\\nodejs\\node.exe", "node.exe ./node_modules/.bin/next dev", user, 95_000);
    }
    add("OneDrive.exe", explorer, "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background", user, 50_000);
  }
  return rows;
}

function makeConnections(dev: Device, procs: ProcessRow[]): ConnectionRow[] {
  const r = rng(hashStr(dev.id) + 1);
  const name = (n: string) => procs.find((p) => p.name === n);
  const rows: ConnectionRow[] = [];
  const push = (proto: string, direction: string, lport: number, rip: string | null, rport: number | null, state: string, proc: string, ext: boolean, ago = r() * 50 * MIN) => {
    const p = name(proc);
    rows.push({ observed_at: iso(ago), proto, direction, local_ip: direction === "listen" ? "0.0.0.0" : dev.last_ip, local_port: lport,
      remote_ip: rip, remote_port: rport, state, pid: p?.pid ?? null, process_name: proc, is_external: ext });
  };
  push("tcp4", "listen", 135, null, null, "LISTEN", "svchost.exe", false);
  push("tcp4", "listen", 445, null, null, "LISTEN", "System", false);
  push("tcp4", "outbound", 50000 + Math.floor(r() * 9999), "10.10.0.68", 443, "ESTABLISHED", "edr-agent.exe", false);
  push("tcp4", "outbound", 50000 + Math.floor(r() * 9999), "10.10.0.20", 8443, "ESTABLISHED", "SecAgentSvc.exe", false);
  if (dev.hostname.startsWith("SRV")) {
    push("tcp4", "listen", 3389, null, null, "LISTEN", "svchost.exe", false);
    push("tcp4", "listen", 1433, null, null, "LISTEN", "sqlservr.exe", false);
    if (dev.hostname === "SRV-WEB-01") {
      push("tcp4", "listen", 443, null, null, "LISTEN", "System", false);
      push("tcp4", "inbound", 3389, "45.155.205.99", 51882, "ESTABLISHED", "svchost.exe", true, 2.7 * HOUR);
      push("tcp4", "outbound", 49822, "91.92.249.17", 8080, "ESTABLISHED", "svchelper.exe", true, 2.1 * HOUR);
      push("tcp4", "outbound", 49840, "91.92.249.17", 8080, "ESTABLISHED", "powershell.exe", true, 2.0 * HOUR);
    }
  } else {
    for (const ip of ["142.250.206.238", "142.250.76.142", "172.217.161.234"]) push("tcp4", "outbound", 50000 + Math.floor(r() * 9999), ip, 443, "ESTABLISHED", "chrome.exe", true);
    push("tcp4", "outbound", 50000 + Math.floor(r() * 9999), "52.112.120.204", 443, "ESTABLISHED", "ms-teams.exe", true);
    push("tcp4", "outbound", 50000 + Math.floor(r() * 9999), "52.97.183.162", 443, "ESTABLISHED", "OUTLOOK.EXE", true);
    push("tcp6", "outbound", 50000 + Math.floor(r() * 9999), "2603:1036:304:2858::2", 443, "ESTABLISHED", "OneDrive.exe", true);
    push("udp4", "bound", 5353, null, null, "BOUND", "chrome.exe", false);
  }
  return rows.sort((a, b) => b.observed_at.localeCompare(a.observed_at));
}

function makeAutoruns(dev: Device): AutorunRow[] {
  const base = (loc: string, name: string, cmd: string, ago = 40 * DAY): AutorunRow => ({
    location: loc, entry_name: name, command: cmd, image_path: cmd.replace(/^"([^"]+)".*$/, "$1").replace(/ -.*$/, ""), sha256: null,
    first_seen_at: iso(ago), last_seen_at: iso(4 * MIN), removed_at: null,
  });
  const rows = [
    base("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SecurityHealth", "%windir%\\system32\\SecurityHealthSystray.exe"),
    base("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "CorpSecurityTray", "\"C:\\Program Files\\CorpSecurity\\SecTray.exe\""),
    base("Service", "EndpointEDRAgent", "\"C:\\Program Files\\EndpointEDR\\edr-agent.exe\""),
    base("Service", "SecAgentSvc", "\"C:\\Program Files\\CorpSecurity\\SecAgentSvc.exe\" -service"),
    base("Service", "WinDefend", "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25080.5-0\\MsMpEng.exe\""),
    base("ScheduledTask", "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "%windir%\\system32\\defrag.exe -c -h -o -$"),
    base("ScheduledTask", "\\GoogleUpdateTaskMachineUA", "\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\" /ua /installsource scheduler", 12 * DAY),
  ];
  if (!dev.hostname.startsWith("SRV")) rows.push(base("HKU\\S-1-5-21-…\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "OneDrive", "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background", 9 * DAY));
  if (dev.hostname === "SRV-WEB-01") rows.push(base("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "WinSvcHelper", "C:\\ProgramData\\svch\\svchelper.exe -k", 2.4 * HOUR));
  return rows;
}


// ---------- 보안 이벤트 (헌팅·엔터티용, 장치별 결정적 생성) ----------
interface EventRow { event_time: string; device_id: string; event_id: number; target_user: string | null; logon_type: number | null; src_ip: string | null; channel: string }
function makeEvents(dev: Device): EventRow[] {
  const r = rng(hashStr(dev.id) + 7);
  const out: EventRow[] = [];
  const ev = (ago: number, id: number, user: string | null, lt: number | null, ip: string | null) =>
    out.push({ event_time: iso(ago), device_id: dev.id, event_id: id, target_user: user, logon_type: lt, src_ip: ip, channel: "Security" });
  if (dev.hostname === "SRV-WEB-01") {
    for (let i = 0; i < 40; i++) ev(3.1 * HOUR - i * 40_000, 4625, pick(r, ["administrator", "admin", "test"]), 10, "45.155.205.99");
    ev(2.7 * HOUR, 4624, "administrator", 10, "45.155.205.99");
    ev(2.5 * HOUR, 4720, "support$", null, null);
    ev(2.0 * HOUR, 1102, null, null, null);
  }
  if (dev.hostname.startsWith("SRV") || dev.hostname.startsWith("DEV")) {
    const n = Math.floor(r() * 12);
    for (let i = 0; i < n; i++) ev(r() * 5 * DAY, 4625, pick(r, ["administrator", "admin", "sa", "backup"]), 10, pick(r, ATTACK_IPS));
  }
  for (let i = 0; i < 4; i++) ev(r() * 3 * DAY, 4624, `corp\\${pick(r, ["kim.js", "lee.hy", "it.admin"])}`.split("\\")[1]!, 10, `10.20.0.${Math.floor(r() * 200)}`);
  return out;
}

// ---------- 인시던트 묶음 (DB 트리거 edr_attach_alert 와 같은 규칙) ----------
const RANKS: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
function groupIncidents(alerts: Alert[], rules: DetectionRule[], devices: Device[]): Incident[] {
  const ruleMap = new Map(rules.map((r) => [r.rule_id, r]));
  const host = new Map(devices.map((d) => [d.id, d.hostname]));
  const incs: (Incident & { _alerts: Alert[] })[] = [];
  let next = 300;
  for (const a of [...alerts].sort((x, y) => x.created_at.localeCompare(y.created_at))) {
    if (a.resolution === "suppressed") continue;
    const ip = (a.details.src_ip ?? a.details.remote_ip) as string | undefined;
    const sha = a.details.sha256 as string | undefined;
    const user = (a.details.user ?? (Array.isArray(a.details.users) ? a.details.users[0] : undefined)) as string | undefined;
    const t = Date.parse(a.created_at);
    const inc = [...incs].reverse().find((i) =>
      (a.device_id && i.device_ids.includes(a.device_id) && Date.parse(i.last_seen_at) > t - 2 * HOUR) ||
      (ip && i.ips.includes(ip) && Date.parse(i.last_seen_at) > t - 24 * HOUR) ||
      (sha && i.hashes.includes(sha) && Date.parse(i.last_seen_at) > t - 24 * HOUR));
    const rule = ruleMap.get(a.rule_id);
    if (!inc) {
      incs.push({
        id: next++, title: a.title, severity: a.severity, status: "open", resolution: null, assigned_to: null,
        device_ids: a.device_id ? [a.device_id] : [], ips: ip ? [ip] : [], hashes: sha ? [sha] : [], users: user ? [user] : [],
        tactics: rule ? [rule.mitre_tactic] : [], techniques: rule ? [rule.mitre_technique] : [], rule_ids: [a.rule_id],
        alert_count: 1, first_seen_at: a.created_at, last_seen_at: a.created_at, created_at: a.created_at, updated_at: a.updated_at, _alerts: [a],
      });
      a.incident_id = next - 1;
      continue;
    }
    const add = <T,>(arr: T[], v: T | undefined) => { if (v != null && !arr.includes(v)) arr.push(v); };
    if (RANKS[a.severity] > RANKS[inc.severity]) inc.severity = a.severity;
    add(inc.device_ids, a.device_id ?? undefined); add(inc.ips, ip); add(inc.hashes, sha); add(inc.users, user);
    add(inc.tactics, rule?.mitre_tactic); add(inc.techniques, rule?.mitre_technique); add(inc.rule_ids, a.rule_id);
    inc.alert_count++; inc.last_seen_at = a.created_at; inc._alerts.push(a);
    if (inc.tactics.length >= 3) inc.title = `다단계 공격 의심: ${(a.device_id && host.get(a.device_id)) || "여러 장치"}${inc.device_ids.length > 1 ? " 외" : ""}`;
    a.incident_id = inc.id;
  }
  return incs.map(({ _alerts, ...i }) => {
    const st = _alerts.every((a) => a.status === "closed") ? "closed" : _alerts.some((a) => a.status === "open") ? "open" : "acknowledged";
    const res = _alerts.find((a) => a.resolution && a.resolution !== "suppressed")?.resolution;
    return { ...i, status: st, resolution: st === "closed" ? ((res as Incident["resolution"]) ?? "benign") : null, assigned_to: _alerts.find((a) => a.assigned_to)?.assigned_to ?? null };
  });
}

// ---------- 상태 (서버 메모리) ----------
const state = (() => {
  const devices = makeDevices();
  const alerts = makeAlerts(devices);
  const rules = RULES.map((r) => ({ ...r }));
  return {
    assets: A.makeDemoAssets(devices),
    docs: D.makeDemoDocs(devices),
    remediation: new Map<string, R.Tracking>(),
    devices,
    alerts,
    rules,
    incidents: groupIncidents(alerts, rules, devices),
    incidentComments: [
      { id: 9001, alert_id: 0, author_id: ME, author_email: "secops@corp.example", body: "SRV-WEB-01 RDP 가 인터넷에 열려 있었음. 방화벽 담당에게 3389 차단 요청, 서버 담당자 연락 중.", created_at: iso(2.3 * HOUR), incident_id: 0 },
    ] as (AlertComment & { incident_id: number })[],
    queries: [
      { id: 1, name: "인코딩된 PowerShell", query: 'process.name = powershell.exe and process.cmdline ~ "-enc"', hours: 168, created_at: iso(20 * DAY), created_by: ME },
      { id: 2, name: "서버 외부 RDP 로그온", query: "event.id = 4624 and event.logon_type = 10 and device.hostname ~ SRV", hours: 168, created_at: iso(12 * DAY), created_by: ME },
    ] as SavedQuery[],
    comments: [
      { id: 1, alert_id: 2001, author_id: ME, author_email: "secops@corp.example", body: "SRV-WEB-01 RDP 외부 노출 확인. 방화벽 담당자에게 3389 차단 요청함.", created_at: iso(2.5 * HOUR) },
    ] as AlertComment[],
    suppressions: [
      { id: 1, rule_id: "EDR-PERSIST-002", device_id: null, match: { entry: "OneDrive" }, reason: "OneDrive 자동 업데이트 — 정상", created_at: iso(9 * DAY), expires_at: null, hit_count: 37 },
    ] as Suppression[],
    keys: [
      { id: "k1", label: "전사 배포 (GPO)", max_uses: 1000, used_count: 64, expires_at: iso(-20 * DAY), revoked: false, created_at: iso(10 * DAY) },
      { id: "k2", label: "파일럿 IT팀", max_uses: 20, used_count: 12, expires_at: iso(15 * DAY), revoked: true, created_at: iso(45 * DAY) },
    ] as EnrollmentKey[],
    members: [
      { user_id: ME, email: "secops@corp.example", role: "admin", created_at: iso(60 * DAY), managed_by: "manual" },
      { user_id: "u2", email: "it.lee@corp.example", role: "analyst", created_at: iso(50 * DAY), managed_by: "sso" },
      { user_id: "u3", email: "cto@corp.example", role: "viewer", created_at: iso(30 * DAY), managed_by: "sso" },
    ] as Member[],
    audit: [
      { id: 6, actor_id: ME, actor_email: "secops@corp.example", action: "suppression.create", target_type: "suppression", target_id: "1", target_label: "EDR-PERSIST-002 · OneDrive 자동 업데이트 — 정상", changes: { rule_id: "EDR-PERSIST-002", match: { entry: "OneDrive" } }, created_at: iso(9 * DAY) },
      { id: 5, actor_id: ME, actor_email: "secops@corp.example", action: "rule.enable", target_type: "rule", target_id: "EDR-PERSIST-003", target_label: "예약 작업 생성·변경", changes: { enabled: [false, true] }, created_at: iso(3 * DAY) },
      { id: 4, actor_id: "u2", actor_email: "it.lee@corp.example", action: "rule.disable", target_type: "rule", target_id: "EDR-PERSIST-003", target_label: "예약 작업 생성·변경", changes: { enabled: [true, false] }, created_at: iso(3 * DAY + 2 * HOUR) },
      { id: 3, actor_id: ME, actor_email: "secops@corp.example", action: "enrollment_key.revoke", target_type: "enrollment_key", target_id: "k2", target_label: "파일럿 IT팀", changes: { revoked: [false, true] }, created_at: iso(20 * DAY) },
      { id: 2, actor_id: ME, actor_email: "secops@corp.example", action: "enrollment_key.create", target_type: "enrollment_key", target_id: "k1", target_label: "전사 배포 (GPO)", changes: { max_uses: 1000 }, created_at: iso(10 * DAY) },
      { id: 1, actor_id: ME, actor_email: "secops@corp.example", action: "enrollment_key.create", target_type: "enrollment_key", target_id: "k2", target_label: "파일럿 IT팀", changes: { max_uses: 20 }, created_at: iso(45 * DAY) },
    ] as AuditEntry[],
    notifications: [
      { id: 1, name: "SOC 슬랙", kind: "slack", target: "#soc-alerts", secret_ref: "SLACK_WEBHOOK_SOC", min_severity: "high", rule_prefixes: [], enabled: true, updated_at: iso(5 * DAY), last_sent_at: iso(2 * HOUR), pending: 0, failed: 0 },
      { id: 2, name: "보안팀 이메일", kind: "email", target: "secops@corp.example, soc-lead@corp.example", secret_ref: "", min_severity: "critical", rule_prefixes: [], enabled: true, updated_at: iso(12 * DAY), last_sent_at: iso(1 * DAY), pending: 0, failed: 0 },
      { id: 3, name: "SIEM(Splunk)", kind: "syslog", target: "siem.corp.example:514", secret_ref: "", min_severity: "low", rule_prefixes: [], enabled: false, updated_at: iso(30 * DAY), last_sent_at: null, pending: 0, failed: 0 },
    ] as NotificationChannel[],
    nextId: 5000,
  };
})();

/** 데모에서도 조치를 감사 기록에 남긴다(실제는 DB 트리거가 남김). */
function audit(action: string, target_type: string, target_id: string | null, target_label: string | null, changes: Record<string, unknown> = {}) {
  state.audit.unshift({ id: state.nextId++, actor_id: ME, actor_email: viewer.email, action, target_type, target_id, target_label, changes, created_at: new Date().toISOString() });
}

// 데모 조치 목록: 몇 건은 담당자·진행 상태가 있고, 한 건은 이미 해결 확인됨
{
  const rows = R.remediationRows(state.assets, state.docs, state.devices, state.remediation, true, new Map(), { view: "active" });
  const day = (n: number) => new Date(Date.now() + n * DAY).toISOString().slice(0, 10);
  const set = (i: number, status: R.Tracking["status"], assignee: string | null, note: string, due: number | null, ago: number) => {
    const r = rows[i];
    if (r) state.remediation.set(R.keyOf(r.device_id, r.kind, r.item_key),
      { title: r.title, status, assignee, note, due_date: due == null ? null : day(due), updated_at: iso(ago), updated_by: ME });
  };
  set(0, "in_progress", "u2", "사용자 부재 — 내일 오전 원격 지원 예약", 2, 3 * HOUR);
  set(1, "in_progress", ME, "", -1, 2 * DAY);
  set(3, "done", "u2", "업데이트 배포함, 다음 수집 때 확인", null, 40 * MIN);
  set(6, "exception", ME, "개발 장비 — 테스트용으로 필요(보안팀 승인)", null, 6 * DAY);
  const d = state.devices.find((x) => x.status === "active");
  if (d) state.remediation.set(R.keyOf(d.id, "posture", "smb1"),
    { title: "SMBv1 꺼짐", status: "done", assignee: "u2", note: "Windows 기능에서 해제", due_date: null, updated_at: iso(4 * DAY), updated_by: "u2" });
}

// 데모 사건(SRV-WEB-01 인시던트)에 처리 기록 연결
{
  const web = state.incidents.find((i) => i.title.startsWith("다단계"));
  if (web) state.incidentComments.forEach((c) => (c.incident_id = web.id));
}

const procCache = new Map<string, ProcessRow[]>();
const evCache = new Map<string, EventRow[]>();
const eventsOf = (d: Device) => {
  if (!evCache.has(d.id)) evCache.set(d.id, makeEvents(d));
  return evCache.get(d.id)!;
};
const refreshIncident = (id: number) => {
  const inc = state.incidents.find((i) => i.id === id);
  if (!inc) return;
  const al = state.alerts.filter((a) => a.incident_id === id);
  inc.status = al.every((a) => a.status === "closed") ? "closed" : al.some((a) => a.status === "open") ? "open" : "acknowledged";
  inc.updated_at = new Date().toISOString();
};
const procsOf = (d: Device) => {
  if (!procCache.has(d.id)) procCache.set(d.id, makeProcesses(d));
  return procCache.get(d.id)!;
};
const devById = (id: string | null) => state.devices.find((d) => d.id === id) ?? null;
const ageMs = (t: string | null) => (t ? Date.now() - Date.parse(t) : Infinity);

function overview(): Overview {
  const open: Partial<Record<Severity, number>> = {};
  state.alerts.filter((a) => a.status !== "closed").forEach((a) => (open[a.severity] = (open[a.severity] ?? 0) + 1));
  const health = state.devices.map((d) => d.health).filter((h) => h != null);
  const cpu = health.map((h) => h.cpu_percent), mem = health.map((h) => h.working_set_mb);
  const avg = (xs: number[]) => Math.round((xs.reduce((s, x) => s + x, 0) / xs.length) * 100) / 100;
  const since = (h: number) => state.alerts.filter((a) => ageMs(a.created_at) < h * HOUR);
  const week = since(24 * 7);
  const byRule = new Map<string, number>();
  week.forEach((a) => byRule.set(a.rule_id, (byRule.get(a.rule_id) ?? 0) + 1));
  const byDev = new Map<string, { n: number; high: number }>();
  week.filter((a) => a.status !== "closed").forEach((a) => {
    const v = byDev.get(a.device_id!) ?? { n: 0, high: 0 };
    v.n++; if (a.severity === "critical" || a.severity === "high") v.high++;
    byDev.set(a.device_id!, v);
  });
  const closed = state.alerts.filter((a) => a.status === "closed" && a.resolution !== "suppressed");
  return {
    open_alerts: open,
    alerts_24h: since(24).length,
    alerts_prev_24h: state.alerts.filter((a) => ageMs(a.created_at) >= 24 * HOUR && ageMs(a.created_at) < 48 * HOUR).length,
    devices: {
      total: state.devices.length,
      online: state.devices.filter((d) => ageMs(d.last_seen_at) < 15 * MIN).length,
      stale: state.devices.filter((d) => ageMs(d.last_seen_at) >= 15 * MIN && ageMs(d.last_seen_at) < DAY).length,
      offline: state.devices.filter((d) => ageMs(d.last_seen_at) >= DAY).length,
      avg_cpu: avg(cpu), max_cpu: Math.max(...cpu), avg_mem: avg(mem), max_mem: Math.max(...mem),
      cpu_buckets: [0, 0.25, 0.5, 1, 2].map((lo, i, e) => cpu.filter((c) => c >= lo && c < (e[i + 1] ?? Infinity)).length),
    },
    failed_logons_24h: 1873,
    malicious_hashes: 2,
    pending_hashes: 41,
    mttr_minutes: closed.length ? Math.round(closed.reduce((s, a) => s + (Date.parse(a.updated_at) - Date.parse(a.created_at)), 0) / closed.length / MIN) || 47 : null,
    top_rules: [...byRule].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([rule_id, n]) => {
      const r = state.rules.find((x) => x.rule_id === rule_id);
      return { rule_id, n, title: r?.title ?? null, mitre_technique: r?.mitre_technique ?? null };
    }),
    top_devices: [...byDev].sort((a, b) => b[1].n - a[1].n).slice(0, 6).map(([id, v]) => ({ id, hostname: devById(id)?.hostname ?? "?", ...v })),
  };
}

const viewer: Viewer = {
  userId: ME, email: "secops@corp.example", demo: true,
  tenants: [{ id: TENANT, name: "우리회사", role: "admin" }], tenant: { id: TENANT, name: "우리회사", role: "admin" },
};

export const demoSource: DataSource = {
  async viewer() { return viewer; },
  async overview() { return overview(); },

  async alertTrend(_t, days) {
    const buckets = new Map<string, TrendPoint>();
    state.alerts.filter((a) => ageMs(a.created_at) < days * DAY).forEach((a) => {
      const d = new Date(a.created_at);
      if (days > 2) d.setHours(0, 0, 0, 0); else d.setMinutes(0, 0, 0);
      const k = d.toISOString() + a.severity;
      const p = buckets.get(k) ?? { bucket: d.toISOString(), severity: a.severity, n: 0 };
      p.n++; buckets.set(k, p);
    });
    return [...buckets.values()].sort((a, b) => a.bucket.localeCompare(b.bucket));
  },

  async logonFailures(_t, hours) {
    const r = rng(99);
    const now = new Date(); now.setMinutes(0, 0, 0);
    return Array.from({ length: hours }, (_, i) => {
      const t = new Date(now.getTime() - (hours - 1 - i) * HOUR);
      const spike = hours - 1 - i === 3 ? 640 : hours - 1 - i === 4 ? 410 : 0;
      return { bucket: t.toISOString(), n: Math.floor(18 + r() * 40 + spike) };
    });
  },

  async alertsSince(_t, hours) { return state.alerts.filter((a) => ageMs(a.created_at) < hours * HOUR); },

  async alerts(_t, f) {
    let rows = state.alerts.filter((a) => ageMs(a.created_at) < (f.days ?? 30) * DAY);
    if (f.severity?.length) rows = rows.filter((a) => f.severity!.includes(a.severity));
    if (!f.status || f.status === "active") rows = rows.filter((a) => a.status !== "closed");
    else if (f.status !== "all") rows = rows.filter((a) => a.status === f.status);
    if (f.rule) rows = rows.filter((a) => a.rule_id === f.rule);
    if (f.device) rows = rows.filter((a) => a.device_id === f.device);
    if (f.source) rows = rows.filter((a) => (a.source ?? "edr") === f.source);
    if (f.q) rows = rows.filter((a) => a.title.toLowerCase().includes(f.q!.toLowerCase()) || (a.hostname ?? "").toLowerCase().includes(f.q!.toLowerCase()));
    const page = Math.max(1, f.page ?? 1);
    return { rows: rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), total: rows.length, page, pageSize: PAGE_SIZE };
  },

  async alert(_t, id) {
    const alert = state.alerts.find((a) => a.id === id);
    if (!alert) return null;
    return {
      alert, comments: state.comments.filter((c) => c.alert_id === id),
      rule: state.rules.find((r) => r.rule_id === alert.rule_id) ?? null, device: devById(alert.device_id),
    };
  },

  async devices(_t, { q, state: st = "all", sort = "hostname", page = 1 }) {
    let rows = [...state.devices];
    if (q) rows = rows.filter((d) => d.hostname.toLowerCase().includes(q.toLowerCase()) || (d.last_ip ?? "").includes(q));
    if (st === "online") rows = rows.filter((d) => ageMs(d.last_seen_at) < 15 * MIN);
    if (st === "stale") rows = rows.filter((d) => ageMs(d.last_seen_at) >= 15 * MIN && ageMs(d.last_seen_at) < DAY);
    if (st === "offline") rows = rows.filter((d) => ageMs(d.last_seen_at) >= DAY);
    const open = new Map<string, number>();
    state.alerts.filter((a) => a.status !== "closed").forEach((a) => open.set(a.device_id!, (open.get(a.device_id!) ?? 0) + 1));
    rows.sort((a, b) =>
      sort === "cpu" ? (b.health?.cpu_percent ?? -1) - (a.health?.cpu_percent ?? -1)
      : sort === "memory" ? (b.health?.working_set_mb ?? -1) - (a.health?.working_set_mb ?? -1)
      : sort === "last_seen" ? ageMs(b.last_seen_at) - ageMs(a.last_seen_at)
      : sort === "alerts" ? (open.get(b.id) ?? 0) - (open.get(a.id) ?? 0)
      : a.hostname.localeCompare(b.hostname));
    const pageRows = rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE).map((d) => ({ ...d, open_alerts: open.get(d.id) ?? 0 }));
    return { rows: pageRows, total: rows.length, page, pageSize: PAGE_SIZE };
  },

  async device(_t, id) { return devById(id); },

  async deviceTimeline(_t, id, hours) {
    const d = devById(id);
    if (!d) return [];
    const items: TimelineItem[] = state.alerts.filter((a) => a.device_id === id && ageMs(a.created_at) < hours * HOUR)
      .map((a) => ({ ts: a.created_at, kind: "alert", severity: a.severity, title: a.title, detail: { ...a.details, alert_id: a.id, rule_id: a.rule_id, status: a.status } }));
    procsOf(d).filter((p) => ageMs(p.create_time) < hours * HOUR)
      .forEach((p) => items.push({ ts: p.create_time, kind: "process", severity: "info", title: p.name, detail: { pid: p.pid, path: p.path, command_line: p.command_line, user: p.username, sha256: p.sha256 } }));
    if (d.hostname === "SRV-WEB-01") {
      for (let i = 0; i < 6; i++) items.push({ ts: iso(3.1 * HOUR + i * 4 * MIN), kind: "event", severity: "low", title: "4625 administrator ← 45.155.205.99", detail: { event_id: 4625, logon_type: 10, src_ip: "45.155.205.99" } });
      items.push({ ts: iso(2.7 * HOUR), kind: "event", severity: "info", title: "4624 administrator ← 45.155.205.99", detail: { event_id: 4624, logon_type: 10, src_ip: "45.155.205.99" } });
      items.push({ ts: iso(2.4 * HOUR), kind: "autorun", severity: "medium", title: "추가: WinSvcHelper", detail: { location: "HKLM\\…\\Run", command: "C:\\ProgramData\\svch\\svchelper.exe -k" } });
    }
    state.assets.changes.filter((c) => c.device_id === id && ageMs(c.observed_at) < hours * HOUR).forEach((c) => items.push({
      ts: c.observed_at, kind: "software", severity: c.change === "installed" ? "low" : "info",
      title: `${{ installed: "설치: ", removed: "삭제: ", updated: "업데이트: " }[c.change]}${c.name}${c.version ? ` ${c.version}` : ""}`,
      detail: { change: c.change, version: c.version, prev_version: c.prev_version, publisher: c.publisher } }));
    return items.sort((a, b) => b.ts.localeCompare(a.ts));
  },

  async deviceProcesses(_t, id) { const d = devById(id); return d ? procsOf(d) : []; },
  async deviceConnections(_t, id, { externalOnly }) {
    const d = devById(id);
    if (!d) return [];
    const rows = makeConnections(d, procsOf(d));
    return externalOnly ? rows.filter((r) => r.is_external) : rows;
  },
  async deviceAutoruns(_t, id) { const d = devById(id); return d ? makeAutoruns(d) : []; },

  async rules() {
    return state.rules.map((r) => ({ ...r, hits_7d: state.alerts.filter((a) => a.rule_id === r.rule_id && ageMs(a.created_at) < 7 * DAY).length }));
  },
  async suppressions() { return state.suppressions; },

  async enrollmentKeys() { return state.keys; },
  async members() { return state.members; },

  async updateAlerts(_t, ids, patch) {
    state.alerts.forEach((a) => {
      if (!ids.includes(a.id)) return;
      if (patch.status) a.status = patch.status;
      if (patch.resolution !== undefined) a.resolution = patch.resolution;
      if (patch.assignToMe) a.assigned_to = ME;
      a.updated_at = new Date().toISOString();
      audit(patch.status === "closed" ? "alert.close" : "alert.update", "alert", String(a.id), a.title, { ...(patch.status && { status: patch.status }), ...(patch.resolution !== undefined && { resolution: patch.resolution }), ...(patch.assignToMe && { assigned_to: "나" }) });
    });
    new Set(state.alerts.filter((a) => ids.includes(a.id)).map((a) => a.incident_id)).forEach((i) => i && refreshIncident(i));
  },
  async addComment(_t, alertId, body) {
    state.comments.push({ id: state.nextId++, alert_id: alertId, author_id: ME, author_email: viewer.email, body, created_at: new Date().toISOString() });
  },
  async createSuppression(_t, s) {
    const id = state.nextId++;
    state.suppressions.unshift({ id, rule_id: s.rule_id, device_id: s.device_id, match: s.match, reason: s.reason,
      created_at: new Date().toISOString(), expires_at: s.days ? new Date(Date.now() + s.days * DAY).toISOString() : null, hit_count: 0 });
    audit("suppression.create", "suppression", String(id), `${s.rule_id ?? ""} · ${s.reason}`, { rule_id: s.rule_id, match: s.match });
  },
  async deleteSuppression(_t, id) {
    const s = state.suppressions.find((x) => x.id === id);
    state.suppressions = state.suppressions.filter((x) => x.id !== id);
    if (s) audit("suppression.delete", "suppression", String(id), `${s.rule_id ?? ""} · ${s.reason}`, { rule_id: s.rule_id, match: s.match });
  },
  async setRuleEnabled(ruleId, enabled) {
    const r = state.rules.find((x) => x.rule_id === ruleId);
    if (r && r.enabled !== enabled) { audit(enabled ? "rule.enable" : "rule.disable", "rule", ruleId, r.title, { enabled: [r.enabled, enabled] }); r.enabled = enabled; }
  },
  async createEnrollmentKey(_t, label, days, maxUses) {
    const key = `edr_enr_${hex(rng(Date.now()), 48)}`;
    const id = `k${state.nextId++}`;
    state.keys.unshift({ id, label, max_uses: maxUses, used_count: 0, expires_at: new Date(Date.now() + days * DAY).toISOString(), revoked: false, created_at: new Date().toISOString() });
    audit("enrollment_key.create", "enrollment_key", id, label, { max_uses: maxUses });
    return key;
  },
  async revokeEnrollmentKey(_t, id) {
    const k = state.keys.find((x) => x.id === id);
    if (k && !k.revoked) { k.revoked = true; audit("enrollment_key.revoke", "enrollment_key", id, k.label, { revoked: [false, true] }); }
  },
  // ---------------- 인시던트 ----------------
  async incidents(_t, f) {
    let rows = state.incidents.filter((i) => ageMs(i.last_seen_at) < (f.days ?? 30) * DAY);
    if (f.severity?.length) rows = rows.filter((i) => f.severity!.includes(i.severity));
    if (!f.status || f.status === "active") rows = rows.filter((i) => i.status !== "closed");
    else if (f.status !== "all") rows = rows.filter((i) => i.status === f.status);
    if (f.q) rows = rows.filter((i) => i.title.toLowerCase().includes(f.q!.toLowerCase()) || i.device_ids.some((d) => devById(d)?.hostname.toLowerCase().includes(f.q!.toLowerCase())));
    rows = [...rows].sort((a, b) => b.last_seen_at.localeCompare(a.last_seen_at));
    const page = Math.max(1, f.page ?? 1);
    return { rows: rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE).map((i) => ({ ...i, hostnames: i.device_ids.map((d) => devById(d)?.hostname ?? "?") })), total: rows.length, page, pageSize: PAGE_SIZE };
  },

  async incident(_t, id) {
    const inc = state.incidents.find((i) => i.id === id);
    if (!inc) return null;
    const devices = inc.device_ids.map((d) => devById(d)).filter((d): d is Device => !!d);
    const processes: Record<string, ProcessRow[]> = {}, connections: Record<string, ConnectionRow[]> = {};
    devices.slice(0, 5).forEach((d) => { processes[d.id] = procsOf(d); connections[d.id] = makeConnections(d, procsOf(d)).filter((c) => c.is_external); });
    return {
      incident: { ...inc, hostnames: devices.map((d) => d.hostname) },
      alerts: state.alerts.filter((a) => a.incident_id === id).sort((a, b) => a.created_at.localeCompare(b.created_at)),
      comments: state.incidentComments.filter((c) => c.incident_id === id),
      devices, rules: state.rules.filter((r) => inc.rule_ids.includes(r.rule_id)), processes, connections,
    };
  },

  async updateIncident(_t, id, patch) {
    const inc = state.incidents.find((i) => i.id === id);
    if (!inc) return;
    state.alerts.filter((a) => a.incident_id === id).forEach((a) => {
      if (patch.status === "closed" && a.status !== "closed") { a.status = "closed"; a.resolution = patch.resolution ?? "benign"; }
      if (patch.status === "acknowledged" && a.status === "open") a.status = "acknowledged";
      if (patch.status === "open") { a.status = "open"; a.resolution = null; }
      if (patch.assignToMe) a.assigned_to = ME;
    });
    if (patch.status) inc.status = patch.status;
    inc.resolution = patch.status === "closed" ? patch.resolution ?? "benign" : null;
    if (patch.assignToMe) inc.assigned_to = ME;
    inc.updated_at = new Date().toISOString();
    audit(patch.status === "closed" ? "incident.close" : patch.status === "open" ? "incident.reopen" : "incident.update", "incident", String(id), inc.title,
      { ...(patch.status && { status: patch.status }), ...(patch.status === "closed" && { resolution: inc.resolution }), ...(patch.assignToMe && { assigned_to: "나" }) });
  },

  async addIncidentComment(_t, id, body) {
    state.incidentComments.push({ id: state.nextId++, alert_id: 0, incident_id: id, author_id: ME, author_email: viewer.email, body, created_at: new Date().toISOString() });
  },

  // ---------------- 엔터티 ----------------
  async entity(_t, kind, value, days) {
    const v = value.toLowerCase();
    const within = (ts: string) => ageMs(ts) < days * DAY;
    const obs: { device: Device; ts: string; tag: string }[] = [];
    const facts: Record<string, unknown> = {};
    for (const d of state.devices) {
      if (kind === "ip") {
        makeConnections(d, procsOf(d)).filter((c) => c.remote_ip === value && within(c.observed_at)).forEach((c) => obs.push({ device: d, ts: c.observed_at, tag: "connection" }));
        eventsOf(d).filter((e) => e.src_ip === value && within(e.event_time)).forEach((e) => obs.push({ device: d, ts: e.event_time, tag: `logon_${e.event_id}` }));
      } else if (kind === "hash") {
        procsOf(d).filter((p) => p.sha256 === v).forEach((p) => obs.push({ device: d, ts: p.create_time, tag: p.name + "|" + (p.path ?? "") }));
      } else {
        eventsOf(d).filter((e) => (e.target_user ?? "").toLowerCase() === v && within(e.event_time)).forEach((e) => obs.push({ device: d, ts: e.event_time, tag: `logon_${e.event_id}|${e.src_ip ?? ""}` }));
      }
    }
    if (kind === "ip") {
      facts.is_public = !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(value);
      facts.logon_failures = obs.filter((o) => o.tag === "logon_4625").length;
      facts.logon_success = obs.filter((o) => o.tag === "logon_4624").length;
      facts.connections = obs.filter((o) => o.tag === "connection").length;
    } else if (kind === "hash") {
      facts.names = [...new Set(obs.map((o) => o.tag.split("|")[0]))];
      facts.paths = [...new Set(obs.map((o) => o.tag.split("|")[1]).filter(Boolean))];
      const mal = v === "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b" || v.startsWith("9f2c4e7a");
      facts.reputation = { verdict: mal ? "malicious" : obs.length ? "clean" : "unknown", vt_malicious: mal ? 52 : 0, vt_total: mal ? 71 : 72, checked_at: iso(2 * HOUR) };
      facts.running_now = obs.length;
      facts.autoruns = state.devices.filter((d) => makeAutoruns(d).some((a) => a.command?.toLowerCase().includes("svchelper") && mal)).length;
    } else {
      facts.logon_failures = obs.filter((o) => o.tag.startsWith("logon_4625")).length;
      facts.logon_success = obs.filter((o) => o.tag.startsWith("logon_4624")).length;
      facts.source_ips = [...new Set(obs.map((o) => o.tag.split("|")[1]).filter(Boolean))];
    }
    const byDev = new Map<string, { id: string; hostname: string; n: number; last: string }>();
    obs.forEach((o) => {
      const cur = byDev.get(o.device.id) ?? { id: o.device.id, hostname: o.device.hostname, n: 0, last: o.ts };
      cur.n++; if (o.ts > cur.last) cur.last = o.ts;
      byDev.set(o.device.id, cur);
    });
    const ts = obs.map((o) => o.ts).sort();
    const key = kind === "ip" ? ["src_ip", "remote_ip"] : kind === "hash" ? ["sha256"] : ["user"];
    const alerts = state.alerts.filter((a) => key.some((k) => String(a.details[k] ?? "").toLowerCase() === v) ||
      (kind === "user" && Array.isArray(a.details.users) && a.details.users.map(String).map((x) => x.toLowerCase()).includes(v)));
    const incidents = state.incidents.filter((i) => (kind === "ip" ? i.ips : kind === "hash" ? i.hashes : i.users).map((x) => x.toLowerCase()).includes(v));
    const profile: EntityProfile = {
      kind, value, first_seen: ts[0] ?? null, last_seen: ts.at(-1) ?? null, observations: obs.length,
      devices: [...byDev.values()].sort((a, b) => b.last.localeCompare(a.last)), facts,
      alerts: alerts.slice(0, 50), incidents: incidents.map((i) => ({ ...i, hostnames: i.device_ids.map((d) => devById(d)?.hostname ?? "?") })),
    };
    return profile;
  },

  async attackMatrix(_t, days) {
    return state.rules.map((r) => {
      const hits = state.alerts.filter((a) => a.rule_id === r.rule_id && ageMs(a.created_at) < days * DAY);
      return { technique: r.mitre_technique, tactic: r.mitre_tactic, hits: hits.length, last_seen: hits.map((h) => h.created_at).sort().at(-1) ?? null };
    });
  },

  // ---------------- 쿼리 헌팅 ----------------
  async runQuery(_t, query, hours) {
    const t0 = Date.now();
    let rows: Record<string, unknown>[] = [];
    for (const d of state.devices) {
      const base = { device_id: d.id, hostname: d.hostname };
      if (query.dataset === "process") rows.push(...procsOf(d).map((p) => ({ ...base, ...p, ts: p.create_time })));
      else if (query.dataset === "net") rows.push(...makeConnections(d, procsOf(d)).map((c) => ({ ...base, ...c, ts: c.observed_at })));
      else if (query.dataset === "event") rows.push(...eventsOf(d).map((e) => ({ ...base, ...e, ts: e.event_time })));
      else rows.push(...makeAutoruns(d).map((a) => ({ ...base, ...a, ts: a.last_seen_at })));
    }
    rows = rows.filter((r) => (query.dataset === "process" ? true : ageMs(String(r.ts)) < hours * HOUR) &&
      query.terms.every((t) => matches(r, t)));
    rows.sort((a, b) => String(b.ts).localeCompare(String(a.ts)));
    return { dataset: query.dataset, rows: rows.slice(0, 500), truncated: rows.length > 500, ms: Date.now() - t0 + 3 };
  },

  async savedQueries() { return [...state.queries].sort((a, b) => a.name.localeCompare(b.name)); },
  async saveQuery(_t, name, query, hours) { state.queries.push({ id: state.nextId++, name, query, hours, created_at: new Date().toISOString(), created_by: ME }); },
  async deleteQuery(_t, id) { state.queries = state.queries.filter((q) => q.id !== id); },

  // ---------------- 운영 상태 · 감사 기록 ----------------
  async systemStatus(): Promise<SystemStatus> {
    const now = Date.now();
    const m = new Date(now); m.setUTCDate(1); m.setUTCMonth(m.getUTCMonth() + 3);
    return {
      now: new Date(now).toISOString(), detections_at: iso(40_000), maintenance_at: iso(9 * HOUR), scheduler: "pg_cron",
      partitions_until: m.toISOString().slice(0, 10), last_ingest_at: iso(12_000),
      devices_reporting_1h: state.devices.filter((d) => d.last_seen_at && ageMs(d.last_seen_at) < HOUR).length, pending_hashes: 3,
    };
  },
  async ssoGroupRoles(): Promise<SsoGroupRole[]> {
    return [
      { provider: "keycloak", idp_group: "EDR-Admins", role: "admin", created_at: iso(60 * DAY) },
      { provider: "keycloak", idp_group: "EDR-Analysts", role: "analyst", created_at: iso(60 * DAY) },
      { provider: "keycloak", idp_group: "EDR-Viewers", role: "viewer", created_at: iso(60 * DAY) },
    ];
  },

  // ---------------- 자산 · 소프트웨어 ----------------
  async assetOverview() { return A.assetOverview(state.assets, state.devices); },
  async assets(_t, { q, filter = "all", page = 1, pageSize = PAGE_SIZE }) {
    let rows = A.assetRows(state.assets, state.devices);
    if (q) rows = rows.filter((r) => [r.hostname, r.serial_number, r.model, r.last_user, r.manufacturer].some((v) => (v ?? "").toLowerCase().includes(q.toLowerCase())));
    if (filter === "unsupported") rows = rows.filter((r) => state.assets.posture.get(r.device_id)?.get("os_supported")?.status === "fail");
    if (filter === "ending") rows = rows.filter((r) => state.assets.posture.get(r.device_id)?.get("os_supported")?.status === "warn");
    if (filter === "low_disk") rows = rows.filter((r) => (r.disk_free_gb ?? Infinity) < 10);
    rows.sort((a, b) => a.hostname.localeCompare(b.hostname));
    return { rows: rows.slice((page - 1) * pageSize, page * pageSize), total: rows.length, page, pageSize };
  },
  async deviceInventory(_t, id) { return state.assets.inventory.get(id) ?? null; },
  async deviceSoftware(_t, id) { return state.assets.software.get(id) ?? []; },
  async softwareCatalog(_t, { q, page = 1, pageSize = PAGE_SIZE }) {
    const rows = A.softwareCatalog(state.assets, q);
    return { rows: rows.slice((page - 1) * pageSize, page * pageSize), total: rows.length, page, pageSize };
  },
  async softwareInstalls(_t, name) { return A.softwareInstalls(state.assets, state.devices, name); },
  async softwareChanges(_t, { device, days = 30, page = 1, pageSize = PAGE_SIZE }) {
    const rows = state.assets.changes.filter((c) => (!device || c.device_id === device) && ageMs(c.observed_at) < days * DAY);
    return { rows: rows.slice((page - 1) * pageSize, page * pageSize), total: rows.length, page, pageSize };
  },
  async softwareExposure() { return A.softwareExposure(state.assets, state.devices); },
  async createSoftwarePolicy(_t, p) {
    const id = state.nextId++;
    state.assets.policies.push({ id, ...p, builtin: false, enabled: true, created_at: new Date().toISOString() });
    audit("sw_policy.create", "sw_policy", String(id), `${p.kind === "prohibited" ? "금지" : "취약"}: ${p.name_pattern}`, { kind: p.kind, fixed_version: p.fixed_version, severity: p.severity });
  },
  async setSoftwarePolicyEnabled(_t, id, enabled) {
    const p = state.assets.policies.find((x) => x.id === id);
    if (p && p.enabled !== enabled) { audit("sw_policy.update", "sw_policy", String(id), `${p.kind === "prohibited" ? "금지" : "취약"}: ${p.name_pattern}`, { enabled: [p.enabled, enabled] }); p.enabled = enabled; }
  },
  async deleteSoftwarePolicy(_t, id) {
    const p = state.assets.policies.find((x) => x.id === id);
    state.assets.policies = state.assets.policies.filter((x) => x.id !== id);
    if (p) audit("sw_policy.delete", "sw_policy", String(id), `${p.kind === "prohibited" ? "금지" : "취약"}: ${p.name_pattern}`, { kind: p.kind });
  },

  // ---------------- 보안 상태 ----------------
  async postureOverview() { return A.postureOverview(state.assets, state.devices); },
  async postureDevices(_t, { check, status = "fail", page = 1, pageSize = PAGE_SIZE }) {
    const rows = A.postureDevices(state.assets, state.devices, check, status);
    return { rows: rows.slice((page - 1) * pageSize, page * pageSize), total: rows.length, page, pageSize };
  },
  async devicePosture(_t, id) { return { score: A.postureScore(state.assets, id), items: A.devicePosture(state.assets, id) }; },
  async setPostureCheckEnabled(_t, checkId, enabled) {
    const c = A.POSTURE_CHECKS.find((x) => x.check_id === checkId);
    if (!c) throw new Error("없는 점검 항목입니다");
    state.assets.postureEnabled.set(checkId, enabled);
    audit(enabled ? "posture_policy.enable" : "posture_policy.disable", "posture_policy", checkId, c.title, { enabled });
  },

  // ---------------- 위협 지표 ----------------
  async iocs() { return state.assets.iocs; },
  async createIocs(_t, list) {
    let created = 0, skipped = 0;
    for (const i of list) {
      if (state.assets.iocs.some((x) => x.type === i.type && x.value === i.value)) { skipped++; continue; }
      const id = state.nextId++;
      state.assets.iocs.unshift({ id, type: i.type, value: i.value, severity: i.severity, description: i.description, source: i.source, enabled: true,
        expires_at: i.days ? new Date(Date.now() + i.days * DAY).toISOString() : null, hit_count: 0, last_hit_at: null,
        created_by: ME, created_by_email: viewer.email, created_at: new Date().toISOString() });
      audit("ioc.create", "ioc", String(id), `${i.type === "ip" ? "IP " : "해시 "}${i.value}`, { severity: i.severity, description: i.description });
      created++;
    }
    return { created, skipped, hits: 0 };
  },
  async setIocEnabled(_t, id, enabled) {
    const i = state.assets.iocs.find((x) => x.id === id);
    if (i && i.enabled !== enabled) { audit("ioc.update", "ioc", String(id), `${i.type === "ip" ? "IP " : "해시 "}${i.value}`, { enabled: [i.enabled, enabled] }); i.enabled = enabled; }
  },
  async deleteIoc(_t, id) {
    const i = state.assets.iocs.find((x) => x.id === id);
    state.assets.iocs = state.assets.iocs.filter((x) => x.id !== id);
    if (i) audit("ioc.delete", "ioc", String(id), `${i.type === "ip" ? "IP " : "해시 "}${i.value}`, { severity: i.severity });
  },

  // ---------------- 알림 연동 ----------------
  async notificationChannels() { return state.notifications.map((c) => ({ ...c, rule_prefixes: [...c.rule_prefixes] })); },
  async saveNotificationChannel(_t, input) {
    const now = new Date().toISOString();
    if (input.id) {
      const c = state.notifications.find((x) => x.id === input.id);
      if (c) { Object.assign(c, { name: input.name, kind: input.kind, target: input.target, secret_ref: input.secret_ref, min_severity: input.min_severity, rule_prefixes: [...input.rule_prefixes], enabled: input.enabled, updated_at: now });
        audit("notification.channel.update", "notification_channel", String(c.id), c.name, { kind: c.kind, enabled: c.enabled, min_severity: c.min_severity }); }
    } else {
      const id = state.nextId++;
      state.notifications.push({ id, name: input.name, kind: input.kind, target: input.target, secret_ref: input.secret_ref, min_severity: input.min_severity, rule_prefixes: [...input.rule_prefixes], enabled: input.enabled, updated_at: now, last_sent_at: null, pending: 0, failed: 0 });
      audit("notification.channel.create", "notification_channel", String(id), input.name, { kind: input.kind, min_severity: input.min_severity, enabled: input.enabled });
    }
  },
  async deleteNotificationChannel(_t, id) {
    const c = state.notifications.find((x) => x.id === id);
    state.notifications = state.notifications.filter((x) => x.id !== id);
    if (c) audit("notification.channel.delete", "notification_channel", String(id), c.name, { kind: c.kind });
  },
  async testNotificationChannel(_t, id) {
    const c = state.notifications.find((x) => x.id === id);
    if (c) c.last_sent_at = new Date().toISOString();
  },

  // ---------------- 문서 감사 ----------------
  async docPolicy() { return { ...state.docs.policy }; },
  async saveDocPolicy(_t, p) {
    const { confirmNotice, ...rest } = p;
    const before = state.docs.policy;
    const now = new Date().toISOString();
    const next = { ...before, ...rest, updated_at: now,
      ...(confirmNotice ? { notice_confirmed_at: now, notice_confirmed_by: ME, notice_confirmed_by_email: viewer.email } : {}) };
    if (next.enabled && !next.notice_confirmed_at) throw new Error("직원 고지 완료를 확인해야 문서 감사를 켤 수 있습니다");
    const keys = ["enabled", "interval_hours", "folders", "extra_paths", "extensions", "detect", "keywords", "stale_days", "max_file_mb", "notice_confirmed_at"] as const;
    const diff = Object.fromEntries(keys.filter((k) => JSON.stringify(before[k]) !== JSON.stringify(next[k])).map((k) => [k, [before[k], next[k]]]));
    state.docs.policy = next;
    if (Object.keys(diff).length === 0) return;
    const act = before.enabled !== next.enabled ? (next.enabled ? "doc_scan.enable" : "doc_scan.disable") : "doc_scan.policy";
    audit(act, "doc_scan", null, "문서 감사 정책", diff);
  },
  async docOverview() { return D.docOverview(state.docs, state.devices); },
  async docFindings(_t, { kind, q, device, keyword, page = 1, pageSize = PAGE_SIZE, purpose = "view" }) {
    // 조회·내보내기 감사(조회는 같은 사람 10분에 한 번) — 실제는 DB 함수 console_doc_findings 가 남김
    const recentView = state.audit.some((a) => a.action === "doc_scan.view" && a.actor_id === ME && ageMs(a.created_at) < 10 * MIN);
    if (purpose === "export" || !recentView) {
      audit(purpose === "export" ? "doc_scan.export" : "doc_scan.view", "doc_scan", kind,
        kind === "pii" ? "개인정보 문서" : kind === "keyword" ? "키워드 문서" : "오래된 문서",
        Object.fromEntries(Object.entries({ device_id: device, q, keyword }).filter(([, v]) => v)));
    }
    const rows = D.docFindings(state.docs, state.devices, { kind, q, device, keyword });
    return { rows: rows.slice((page - 1) * pageSize, page * pageSize), total: rows.length, page, pageSize };
  },
  async docDevices() { return D.docDevices(state.docs, state.devices); },
  async requestDocScan(_t, ids) {
    let n = 0;
    for (const id of ids) {
      const d = devById(id);
      if (!d || state.docs.requests.has(id)) continue;
      const rid = state.nextId++;
      state.docs.requests.set(id, { requested_at: new Date().toISOString(), picked: false });
      state.audit.unshift({ id: rid, actor_id: ME, actor_email: viewer.email, action: "doc_scan.request", target_type: "device", target_id: id,
        target_label: d.hostname, changes: { request_id: rid }, created_at: new Date().toISOString() });
      n++;
    }
    return n;
  },

  // ---------------- PC 조치 목록 ----------------
  async remediationOverview() { return R.remediationOverview(state.assets, state.docs, state.devices, state.remediation, true); },
  async remediation(_t, { page = 1, pageSize = PAGE_SIZE, ...opts }) {
    const emails = new Map(state.members.map((m) => [m.user_id, m.email ?? ""]));
    const rows = R.remediationRows(state.assets, state.docs, state.devices, state.remediation, true, emails, opts);
    return { rows: rows.slice((page - 1) * pageSize, page * pageSize), total: rows.length, page, pageSize };
  },
  async updateRemediation(_t, items, patch) {
    if (patch.assignee && !state.members.some((m) => m.user_id === patch.assignee)) throw new Error("담당자는 이 조직의 구성원이어야 합니다");
    const now = new Date().toISOString();
    const audits: { device: string; label: string; diff: Record<string, unknown> }[] = [];
    for (const it of items) {
      const k = R.keyOf(it.device_id, it.kind, it.item_key);
      const before = state.remediation.get(k) ?? { title: it.title, status: "open" as const, assignee: null, note: "", due_date: null, updated_at: now, updated_by: null };
      const next: R.Tracking = { ...before, title: it.title || before.title, status: patch.status ?? before.status,
        assignee: patch.assignee === undefined ? before.assignee : patch.assignee, note: patch.note ?? before.note,
        due_date: patch.due_date === undefined ? before.due_date : patch.due_date, updated_at: now, updated_by: ME };
      const diff = Object.fromEntries((["status", "assignee", "note", "due_date"] as const)
        .filter((f) => before[f] !== next[f]).map((f) => [f, [before[f], next[f]]]));
      state.remediation.set(k, next);
      audits.push({ device: it.device_id, label: `${devById(it.device_id)?.hostname ?? "?"} · ${next.title}`, diff });
    }
    // 여러 건이면 대표 한 줄 — 실제는 DB 함수 console_remediation_update 가 남김
    if (items.length > 1) {
      audit("remediation.bulk", "remediation", null, `조치 항목 ${items.length}건`,
        Object.fromEntries(Object.entries({ count: items.length, ...patch }).filter(([, v]) => v !== undefined)));
    } else if (audits[0] && Object.keys(audits[0].diff).length) {
      const d = audits[0].diff;
      audit("status" in d ? "remediation.status" : "assignee" in d ? "remediation.assign" : "remediation.update", "remediation", audits[0].device, audits[0].label, d);
    }
    return items.length;
  },

  async auditLog(_t, opts) {
    const page = Math.max(1, opts.page ?? 1);
    const rows = (opts.action ? state.audit.filter((a) => a.action.startsWith(opts.action!)) : state.audit)
      .toSorted((a, b) => b.created_at.localeCompare(a.created_at));
    return { rows: rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), total: rows.length, page, pageSize: PAGE_SIZE };
  },
};
