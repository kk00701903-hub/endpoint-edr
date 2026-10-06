import "server-only";
import type {
  AssetOverview, AssetRow, Device, DeviceInventory, DevicePostureItem, DeviceSoftware, Ioc, PostureCheckSummary, PostureDeviceRow,
  PostureOverview, PostureStatus, Severity, SoftwareChange, SoftwareExposure, SoftwareInstall, SoftwareTitle,
} from "./types";
// 정책 일치 규칙은 화면과 함께 쓴다
import { policyMatches, versionCmp, likeMatch, type PolicyRule } from "../software-policy";

// ---------------------------------------------------------------------------
// 데모 모드의 자산·보안 상태·소프트웨어 정책·위협 지표 예시 데이터와 계산.
// 계산 규칙은 DB(마이그레이션 0008)와 같게 맞춘다: 보안 점수, OS 수명 주기, 정책 일치(이름 포함·'*'·버전 미만).
// ---------------------------------------------------------------------------

const DAY = 86_400_000, HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
const dayStr = (msAhead: number) => new Date(Date.now() + msAhead).toISOString().slice(0, 10);

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

export interface DemoPolicy extends PolicyRule {
  id: number; severity: Severity; reference: string | null; reason: string; builtin: boolean; created_at: string;
}

// ---------- 점검 항목 (supabase posture_checks 와 같은 내용) ----------
type CheckDef = Omit<PostureCheckSummary, "pass" | "warn" | "fail" | "unknown" | "enabled">;
export const POSTURE_CHECKS: CheckDef[] = [
  { check_id: "av_realtime", title: "악성코드 실시간 검사", category: "악성코드 방어", weight: 25, default_enabled: true, drift_alert: true, source: "agent",
    description: "Microsoft Defender 실시간 보호가 켜져 있거나, 다른 백신의 실시간 감시 서비스가 실행 중인지 봅니다.",
    remediation: "Windows 보안 → 바이러스 및 위협 방지 → 실시간 보호 켜기. 회사 백신을 쓰면 그 서비스가 실행 중인지 확인합니다." },
  { check_id: "firewall", title: "Windows 방화벽", category: "네트워크", weight: 20, default_enabled: true, drift_alert: true, source: "agent",
    description: "도메인·개인·공용 세 프로필 모두 방화벽이 켜져 있고 방화벽 서비스가 실행 중인지 봅니다(그룹 정책 값 우선).",
    remediation: "제어판 → Windows Defender 방화벽 → 세 프로필 모두 켜기. 그룹 정책으로 꺼 두었다면 정책을 확인합니다." },
  { check_id: "os_supported", title: "지원되는 Windows 버전", category: "업데이트", weight: 20, default_enabled: true, drift_alert: false, source: "server",
    description: "Microsoft 보안 업데이트를 아직 받는 Windows 버전인지 봅니다(서버가 수명 주기 표로 판단). 90일 안에 끝나면 주의로 표시합니다.",
    remediation: "Windows 업데이트로 최신 기능 업데이트(예: Windows 11 25H2)를 설치합니다. 확장 보안 업데이트(ESU)에 가입한 PC 는 예외로 둘 수 있습니다." },
  { check_id: "auto_update", title: "자동 업데이트", category: "업데이트", weight: 10, default_enabled: true, drift_alert: false, source: "agent",
    description: "Windows Update 서비스가 꺼져 있거나 그룹 정책으로 자동 업데이트를 막지 않았는지 봅니다.",
    remediation: "services.msc 에서 Windows Update 시작 유형을 \"수동\" 이상으로, 그룹 정책의 \"자동 업데이트 구성\"을 확인합니다." },
  { check_id: "uac", title: "사용자 계정 컨트롤(UAC)", category: "계정·인증", weight: 10, default_enabled: true, drift_alert: false, source: "agent",
    description: "관리자 권한 실행 전에 확인을 받는 UAC 가 켜져 있는지 봅니다.",
    remediation: "제어판 → 사용자 계정 → 사용자 계정 컨트롤 설정 변경 → 기본값 이상으로." },
  { check_id: "wdigest", title: "평문 자격 증명 저장 안 함", category: "계정·인증", weight: 10, default_enabled: true, drift_alert: true, source: "agent",
    description: "WDigest 가 로그온 비밀번호를 메모리에 평문으로 남기도록 설정되지 않았는지 봅니다(공격 도구가 자주 켜는 설정).",
    remediation: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest 의 UseLogonCredential 을 0 으로(또는 값 삭제). 바뀐 경위를 함께 조사합니다." },
  { check_id: "smb1", title: "SMBv1 꺼짐", category: "네트워크", weight: 10, default_enabled: true, drift_alert: false, source: "agent",
    description: "랜섬웨어 확산에 쓰였던 옛 파일 공유 방식(SMBv1)이 꺼져 있는지 봅니다.",
    remediation: "Windows 기능 켜기/끄기에서 \"SMB 1.0/CIFS 파일 공유 지원\" 해제." },
  { check_id: "rdp_nla", title: "원격 데스크톱 보안", category: "네트워크", weight: 10, default_enabled: true, drift_alert: false, source: "agent",
    description: "원격 데스크톱이 꺼져 있거나, 켜져 있다면 연결 전에 계정 인증(NLA)을 요구하는지 봅니다.",
    remediation: "설정 → 시스템 → 원격 데스크톱 → \"네트워크 수준 인증 필요\" 켜기. 쓰지 않으면 원격 데스크톱 끄기." },
  { check_id: "autologon", title: "자동 로그온 비밀번호 없음", category: "계정·인증", weight: 5, default_enabled: true, drift_alert: false, source: "agent",
    description: "자동 로그온용 비밀번호가 레지스트리에 저장돼 있지 않은지 봅니다(값 이름만 확인하고 내용은 읽지 않음).",
    remediation: "netplwiz 에서 자동 로그온 해제, Winlogon 의 DefaultPassword 값 삭제." },
  { check_id: "screen_lock", title: "화면 잠금 15분 이내", category: "계정·인증", weight: 5, default_enabled: true, drift_alert: false, source: "agent",
    description: "자리를 비웠을 때 15분 안에 화면이 잠기는지 봅니다(컴퓨터 비활성 한도 정책 또는 로그온한 사용자의 암호 보호 화면 보호기).",
    remediation: "그룹 정책 \"대화형 로그온: 컴퓨터 비활성 한도\"를 900초 이하로, 또는 화면 보호기 대기 15분 이하 + \"다시 시작할 때 로그온 화면 표시\"." },
  { check_id: "lsa_protection", title: "LSA 보호", category: "계정·인증", weight: 5, default_enabled: false, drift_alert: false, source: "agent",
    description: "로그온 정보를 다루는 LSA 프로세스가 보호 모드(RunAsPPL)로 실행되는지 봅니다. 호환성 확인이 필요해 기본은 점수에서 뺍니다.",
    remediation: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa 의 RunAsPPL 을 1 로(재부팅 필요). 먼저 호환성 감사 모드로 확인합니다." },
  { check_id: "ps_logging", title: "PowerShell 스크립트 기록", category: "가시성", weight: 5, default_enabled: false, drift_alert: false, source: "agent",
    description: "PowerShell 스크립트 블록 기록이 켜져 있어 사고 조사 때 실행 내용을 볼 수 있는지 봅니다. 기본은 점수에서 뺍니다.",
    remediation: "그룹 정책 → Windows PowerShell → \"PowerShell 스크립트 블록 로깅 설정\" 사용." },
];

// ---------- 장치별 자산 정보 ----------
const MODELS: Record<"LT" | "PC" | "WS" | "SRV", readonly (readonly [string, string, string])[]> = {
  LT: [["LENOVO", "21AHCTO1WW", "ThinkPad T14 Gen 3"], ["Dell Inc.", "Latitude 5440", ""], ["HP", "HP EliteBook 840 G9", ""], ["SAMSUNG ELECTRONICS CO., LTD.", "NT950XEE-X71A", ""]],
  PC: [["Dell Inc.", "OptiPlex 7010", ""], ["HP", "HP ProDesk 400 G9", ""], ["LG Electronics", "B70EV", ""]],
  WS: [["Dell Inc.", "Precision 3660", ""], ["HP", "HP Z2 Tower G9 Workstation", ""]],
  SRV: [["Dell Inc.", "PowerEdge R650", ""], ["VMware, Inc.", "VMware20,1", ""], ["HPE", "ProLiant DL360 Gen10 Plus", ""]],
};

type SwDef = { name: string; publisher: string; versions: string[]; who: (h: string, i: number) => boolean; scope?: "user" };
const SOFTWARE: SwDef[] = [
  { name: "AhnLab V3 Endpoint Security 9.0", publisher: "AhnLab, Inc.", versions: ["9.0.80.3"], who: () => true },
  { name: "Microsoft Edge", publisher: "Microsoft Corporation", versions: ["130.0.2849.68"], who: () => true },
  { name: "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810", publisher: "Microsoft Corporation", versions: ["14.40.33810.0"], who: () => true },
  { name: "Google Chrome", publisher: "Google LLC", versions: ["130.0.6723.92", "130.0.6723.70", "129.0.6668.90"], who: (h) => !h.startsWith("SRV") },
  { name: "Microsoft 365 Apps for enterprise - ko-kr", publisher: "Microsoft Corporation", versions: ["16.0.18025.20140"], who: (h) => !h.startsWith("SRV") },
  { name: "Microsoft Teams", publisher: "Microsoft Corporation", versions: ["24257.205.3165.4024"], who: (h) => !h.startsWith("SRV"), scope: "user" },
  { name: "Hancom Office 2022", publisher: "Hancom Inc.", versions: ["12.0.0.3650"], who: (h) => !h.startsWith("SRV") && !h.startsWith("DEV") },
  { name: "Adobe Acrobat Reader (64-bit)", publisher: "Adobe", versions: ["24.003.20112", "24.002.21005"], who: (h) => !h.startsWith("SRV") },
  { name: "Zoom Workplace", publisher: "Zoom Video Communications, Inc.", versions: ["6.2.5.46987"], who: (h) => /^(MGT|SAL|HR)/.test(h), scope: "user" },
  { name: "7-Zip 24.09 (x64)", publisher: "Igor Pavlov", versions: ["24.09"], who: (_h, i) => i % 3 === 0 },
  { name: "7-Zip 23.01 (x64)", publisher: "Igor Pavlov", versions: ["23.01"], who: (_h, i) => i % 7 === 1 },
  { name: "WinRAR 7.01 (64-bit)", publisher: "win.rar GmbH", versions: ["7.01.0"], who: (_h, i) => i % 5 === 2 },
  { name: "WinRAR 6.11 (64-bit)", publisher: "win.rar GmbH", versions: ["6.11.0"], who: (h, i) => i % 9 === 4 && !h.startsWith("SRV") },
  { name: "Notepad++ (64-bit x64)", publisher: "Notepad++ Team", versions: ["8.7", "8.6.9"], who: (h, i) => h.startsWith("DEV") || h.startsWith("SRV") || i % 6 === 0 },
  { name: "Visual Studio Code", publisher: "Microsoft Corporation", versions: ["1.94.2"], who: (h) => h.startsWith("DEV"), scope: "user" },
  { name: "Git", publisher: "The Git Development Community", versions: ["2.46.2"], who: (h) => h.startsWith("DEV") },
  { name: "Docker Desktop", publisher: "Docker Inc.", versions: ["4.34.2"], who: (h) => h.startsWith("DEV-WS") },
  { name: "Python 3.12.6 (64-bit)", publisher: "Python Software Foundation", versions: ["3.12.6150.0"], who: (h) => h.startsWith("DEV") },
  { name: "Python 2.7.18", publisher: "Python Software Foundation", versions: ["2.7.18150"], who: (h) => h === "DEV-WS-043" },
  { name: "Adobe Flash Player 32 NPAPI", publisher: "Adobe", versions: ["32.0.0.465"], who: (h) => h === "HR-PC-031" || h === "FIN-PC-040" },
  { name: "AnyDesk", publisher: "AnyDesk Software GmbH", versions: ["8.1.0"], who: (h) => h === "SAL-LT-025" || h === "FIN-LT-013", scope: "user" },
  { name: "Microsoft SQL Server 2019 (64-bit)", publisher: "Microsoft Corporation", versions: ["15.0.4385.2"], who: (h) => h === "SRV-ERP-01" },
  { name: "Veeam Backup & Replication", publisher: "Veeam Software Group GmbH", versions: ["12.2.0.334"], who: (h) => h === "SRV-BACKUP-01" },
];

export interface DemoAssets {
  inventory: Map<string, DeviceInventory>;
  software: Map<string, DeviceSoftware[]>;
  posture: Map<string, Map<string, { status: PostureStatus; detail: string; changed_at: string; failing_since: string | null; checked_at: string }>>;
  changes: SoftwareChange[];
  policies: DemoPolicy[];
  postureEnabled: Map<string, boolean>;
  iocs: Ioc[];
}

function lifecycle(build: number, edition: string, product: "client" | "server"): { label: string; eos: string | null } {
  const ent = /Enterprise|Education/.test(edition);
  const tbl: Record<string, [string, number, number]> = {
    // build: [이름, 일반(Home·Pro) 종료까지 일수, 엔터프라이즈 종료까지 일수] — 2026-10-02 기준 Microsoft 일정
    "19045": ["Windows 10 22H2", -353, -353],
    "22631": ["Windows 11 23H2", -325, 39],
    "26100": ["Windows 11 24H2", 11, 375],
    "26200": ["Windows 11 25H2", 375, 738],
    "20348": ["Windows Server 2022", 1838, 1838],
  };
  const row = tbl[String(build)];
  if (!row) return { label: product === "server" ? "Windows Server" : "Windows", eos: null };
  const days = ent ? row[2] : row[1];
  // 실제 날짜는 고정 일정이지만, 데모는 오늘 기준 상대 일수로 만든다(언제 띄워도 같은 모양)
  return { label: row[0], eos: dayStr(days * DAY) };
}

export function makeDemoAssets(devices: Device[]): DemoAssets {
  const inventory = new Map<string, DeviceInventory>();
  const software = new Map<string, DeviceSoftware[]>();
  const posture: DemoAssets["posture"] = new Map();
  const changes: SoftwareChange[] = [];

  devices.forEach((d, i) => {
    const r = rng(hashStr(d.hostname));
    const kind = d.hostname.startsWith("SRV") ? "SRV" : (d.hostname.split("-")[1] as "LT" | "PC" | "WS");
    const [maker, model] = pick(r, MODELS[kind] ?? MODELS.PC);
    const build = Number(d.os_version?.split(".").at(-1) ?? 0);
    const server = kind === "SRV";
    const edition = server ? "ServerStandard" : i % 6 === 5 ? "Professional" : "Enterprise";
    const lc = lifecycle(build, edition, server ? "server" : "client");
    const mem = server ? pick(r, [32768, 65536, 131072]) : kind === "WS" ? 65536 : pick(r, [16384, 16384, 32768, 8192]);
    const total = server ? 558.9 : pick(r, [237.8, 476.3, 953.3]);
    const free = d.hostname === "FIN-PC-040" || d.hostname === "DSN-WS-028" ? 6.2 : Math.round(total * (0.12 + r() * 0.6) * 10) / 10;
    const name = server ? "Windows Server 2022 Standard" : `Windows ${build >= 22000 ? "11" : "10"} ${edition === "Enterprise" ? "Enterprise" : "Pro"}`;
    inventory.set(d.id, {
      device_id: d.id, os_name: name, os_edition: edition,
      os_display_version: { 19045: "22H2", 22631: "23H2", 26100: "24H2", 26200: "25H2", 20348: "21H2" }[build] ?? null,
      os_build: build, os_ubr: build === 26100 ? 6584 : build === 22631 ? 5909 : build === 19045 ? 6332 : 2655,
      os_product: server ? "server" : "client", os_arch: "amd64", os_installed_at: iso((200 + r() * 600) * DAY),
      os_label: lc.label, os_end_of_support: lc.eos,
      manufacturer: maker, model, serial_number: maker.startsWith("VMware") ? null : `${maker.slice(0, 2).toUpperCase()}${Math.floor(r() * 1e7).toString(36).toUpperCase()}`,
      bios_version: maker.startsWith("LENOVO") ? "N3MET19W (1.18 )" : `${1 + Math.floor(r() * 3)}.${Math.floor(r() * 20)}.0`,
      cpu: server ? "Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz" : pick(r, ["Intel(R) Core(TM) i5-1345U", "Intel(R) Core(TM) i7-1365U", "13th Gen Intel(R) Core(TM) i7-13700", "AMD Ryzen 7 PRO 7840U w/ Radeon 780M Graphics"]),
      cpu_cores: server ? 32 : pick(r, [8, 12, 16]), memory_mb: mem, disk_total_gb: total, disk_free_gb: free,
      domain: "BING", domain_joined: d.hostname !== "DSN-WS-028",
      last_user: server ? "BING\\svc.admin" : `BING\\${pick(r, ["kim", "lee", "park", "choi", "jung", "kang", "cho", "yoon"])}.${pick(r, ["js", "mh", "yj", "hs", "sk", "dw"])}`,
      adapters: [{ name: server ? "Ethernet0" : pick(r, ["이더넷", "Wi-Fi"]), mac: Array.from({ length: 6 }, () => Math.floor(r() * 256).toString(16).padStart(2, "0").toUpperCase()).join(":"), ips: d.last_ip ? [d.last_ip] : [] }],
      software_count: 0, collected_at: iso(r() * 6 * HOUR), updated_at: iso(r() * 6 * HOUR),
    });

    const list: DeviceSoftware[] = [];
    SOFTWARE.forEach((s) => {
      if (!s.who(d.hostname, i)) return;
      list.push({ name: s.name, version: pick(r, s.versions), publisher: s.publisher, install_date: null, scope: s.scope ?? "machine", arch: s.scope ? null : "x64",
        first_seen_at: s.name === "AnyDesk" ? iso((d.hostname === "SAL-LT-025" ? 3 : 40) * DAY) : iso((30 + r() * 30) * DAY) });
    });
    list.forEach((s) => { s.install_date = s.first_seen_at.slice(0, 10).replaceAll("-", ""); });
    list.sort((a, b) => a.name.localeCompare(b.name));
    software.set(d.id, list);
    inventory.get(d.id)!.software_count = list.length;

    // 보안 상태
    const p = new Map<string, { status: PostureStatus; detail: string; changed_at: string; failing_since: string | null; checked_at: string }>();
    const set = (id: string, status: PostureStatus, detail: string, sinceMs = (20 + r() * 20) * DAY) =>
      p.set(id, { status, detail, changed_at: iso(sinceMs), failing_since: status === "fail" ? iso(sinceMs) : null, checked_at: iso(r() * HOUR) });
    const h = d.hostname;
    set("av_realtime", h === "DSN-WS-028" || h === "MGT-LT-058" ? "fail" : "pass",
      h === "DSN-WS-028" ? "실시간 감시 중인 백신을 찾지 못함(Defender 서비스 중지, 알려진 백신 서비스 없음)" : h === "MGT-LT-058" ? "Microsoft Defender 실시간 보호 꺼짐(또는 수동 모드), 실행 중인 다른 백신 없음" : "AhnLab V3 실시간 감시 동작");
    set("firewall", ["DEV-WS-019", "DEV-LT-022", "SRV-BACKUP-01"].includes(h) ? "fail" : "pass",
      h === "SRV-BACKUP-01" ? "도메인 프로필 꺼짐" : ["DEV-WS-019", "DEV-LT-022"].includes(h) ? "공용 프로필 꺼짐" : "세 프로필 모두 켜짐");
    set("auto_update", i % 13 === 3 ? "fail" : "pass", i % 13 === 3 ? "그룹 정책으로 자동 업데이트 꺼짐(NoAutoUpdate=1)" : "자동 업데이트 막혀 있지 않음");
    set("uac", h === "DEV-WS-043" ? "fail" : "pass", h === "DEV-WS-043" ? "UAC 꺼짐(EnableLUA=0)" : "켜짐");
    set("wdigest", h === "SRV-WEB-01" ? "fail" : "pass", h === "SRV-WEB-01" ? "WDigest 평문 자격 증명 저장 켜짐(UseLogonCredential=1)" : "꺼짐", h === "SRV-WEB-01" ? 2.3 * HOUR : undefined);
    set("smb1", build === 19045 || h === "SRV-FILE-01" ? "fail" : "pass", build === 19045 || h === "SRV-FILE-01" ? "SMBv1 켜짐: 서버(SMB1 기능 설치됨)" : "꺼짐");
    set("rdp_nla", h === "SRV-WEB-01" || h === "SRV-ERP-01" ? "fail" : "pass",
      h === "SRV-WEB-01" || h === "SRV-ERP-01" ? "원격 데스크톱 켜짐, 네트워크 수준 인증(NLA) 꺼짐" : server ? "원격 데스크톱 켜짐, 네트워크 수준 인증(NLA) 사용" : "원격 데스크톱 꺼짐");
    set("autologon", h === "HR-PC-031" ? "fail" : "pass", h === "HR-PC-031" ? "자동 로그온 켜짐, 비밀번호가 레지스트리에 저장됨(DefaultPassword)" : "자동 로그온 꺼짐");
    if (server) set("screen_lock", "unknown", "로그온한 사용자가 없어 화면 보호기 설정을 확인하지 못함");
    else set("screen_lock", i % 5 === 1 ? "fail" : "pass", i % 5 === 1 ? "로그온 사용자 1명 중 1명이 15분 안에 화면이 잠기지 않음" : "컴퓨터 비활성 한도 600초");
    set("lsa_protection", server || i % 4 === 0 ? "pass" : "fail", server || i % 4 === 0 ? "LSA 보호 켜짐" : "LSA 보호 꺼짐(RunAsPPL 없음)");
    set("ps_logging", server ? "pass" : "fail", server ? "스크립트 블록 기록 켜짐" : "스크립트 블록 기록 꺼짐");
    const eosMs = lc.eos ? Date.parse(lc.eos) - Date.now() : null;
    const osStatus: PostureStatus = eosMs == null ? "unknown" : eosMs < 0 ? "fail" : eosMs < 90 * DAY ? "warn" : "pass";
    set("os_supported", osStatus, lc.eos ? `${lc.label} — ${lc.eos} ${osStatus === "fail" ? "지원 종료" : osStatus === "warn" ? `지원 종료 예정(${Math.ceil(eosMs! / DAY)}일 남음)` : "까지 지원"}` : "수명 주기 정보 없음");
    posture.set(d.id, p);
  });

  // 최근 30일 설치·삭제·업데이트 이력
  let cid = 1;
  const r = rng(99);
  devices.filter((d) => !d.hostname.startsWith("SRV")).forEach((d) => {
    changes.push({ id: cid++, device_id: d.id, hostname: d.hostname, change: "updated", name: "Google Chrome", version: "130.0.6723.92", prev_version: "130.0.6723.70", publisher: "Google LLC", observed_at: iso(r() * 4 * DAY) });
    if (r() < 0.3) changes.push({ id: cid++, device_id: d.id, hostname: d.hostname, change: "updated", name: "Microsoft Edge", version: "130.0.2849.68", prev_version: "130.0.2849.56", publisher: "Microsoft Corporation", observed_at: iso(5 * DAY + r() * 3 * DAY) });
  });
  const by = (h: string) => devices.find((d) => d.hostname === h);
  const add = (h: string, change: SoftwareChange["change"], name: string, version: string, prev: string | null, publisher: string, ago: number) => {
    const d = by(h);
    if (d) changes.push({ id: cid++, device_id: d.id, hostname: h, change, name, version, prev_version: prev, publisher, observed_at: iso(ago) });
  };
  add("SAL-LT-025", "installed", "AnyDesk", "8.1.0", null, "AnyDesk Software GmbH", 3 * DAY);
  add("DEV-LT-022", "installed", "Docker Desktop", "4.34.2", null, "Docker Inc.", 6 * DAY);
  add("FIN-PC-040", "removed", "TeamViewer", "15.58.4", null, "TeamViewer", 12 * DAY);
  add("MGT-LT-058", "installed", "Zoom Workplace", "6.2.5.46987", null, "Zoom Video Communications, Inc.", 9 * DAY);
  add("DEV-WS-019", "updated", "Notepad++ (64-bit x64)", "8.7", "8.6.9", "Notepad++ Team", 2 * DAY);
  changes.sort((a, b) => b.observed_at.localeCompare(a.observed_at));

  const builtin = (id: number, name: string, pub: string | null, fixed: string | null, sev: Severity, ref: string, reason: string): DemoPolicy =>
    ({ id, kind: "vulnerable", severity: sev, name_pattern: name, publisher_pattern: pub, fixed_version: fixed, reference: ref, reason, builtin: true, enabled: true, created_at: iso(60 * DAY) });
  const policies: DemoPolicy[] = [
    builtin(1, "WinRAR", "win.rar", "6.23", "high", "CVE-2023-38831", "압축 파일을 열기만 해도 악성 코드가 실행될 수 있는 취약점(실제 공격에 쓰임). 6.23 이상으로 업데이트"),
    builtin(2, "7-Zip", "Igor Pavlov", "24.09", "medium", "CVE-2025-0411", "압축을 풀 때 인터넷에서 받은 파일 표시(MotW)가 빠지는 취약점(실제 공격에 쓰임). 24.09 이상으로 업데이트"),
    builtin(3, "Adobe Flash Player", null, null, "high", "https://www.adobe.com/products/flashplayer/end-of-life.html", "2020년 12월 31일 지원 종료. 보안 업데이트가 없으므로 삭제"),
    builtin(4, "Microsoft Silverlight", null, null, "medium", "https://learn.microsoft.com/lifecycle/products/silverlight-5", "2021년 10월 12일 지원 종료. 보안 업데이트가 없으므로 삭제"),
    builtin(5, "Python 2.7", null, null, "low", "https://www.python.org/doc/sunset-python-2/", "2020년 1월 1일 지원 종료. Python 3 으로 옮기고 삭제"),
    { id: 6, kind: "prohibited", severity: "high", name_pattern: "AnyDesk", publisher_pattern: null, fixed_version: null, reference: "정보보호 지침 제12조", reason: "승인되지 않은 원격 제어 도구 — 사내 원격 지원은 승인된 도구만", builtin: false, enabled: true, created_at: iso(20 * DAY) },
    { id: 7, kind: "prohibited", severity: "medium", name_pattern: "*torrent", publisher_pattern: null, fixed_version: null, reference: null, reason: "P2P 파일 공유 프로그램 사용 금지", builtin: false, enabled: true, created_at: iso(20 * DAY) },
  ];

  const iocs: Ioc[] = [
    { id: 1, type: "ip", value: "45.155.205.99", severity: "high", description: "SRV-WEB-01 무차별 대입 출발지(사내 분석)", source: "사내 분석", enabled: true, expires_at: null, hit_count: 1, last_hit_at: iso(2.1 * HOUR), created_by: "u2", created_by_email: "it.lee@corp.example", created_at: iso(2.2 * HOUR) },
    { id: 2, type: "sha256", value: "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b", severity: "critical", description: "svchelper.exe 백도어", source: "사내 분석", enabled: true, expires_at: null, hit_count: 1, last_hit_at: iso(2.1 * HOUR), created_by: "u2", created_by_email: "it.lee@corp.example", created_at: iso(2.15 * HOUR) },
    { id: 3, type: "ip", value: "185.220.101.0/24", severity: "medium", description: "Tor 출구 노드 대역", source: "공개 위협 정보", enabled: true, expires_at: iso(-80 * DAY), hit_count: 0, last_hit_at: null, created_by: "00000000-0000-4000-8000-0000000000me", created_by_email: "secops@corp.example", created_at: iso(10 * DAY) },
    { id: 4, type: "sha256", value: "b5c1e0f4a3d29be7c8f6e1d0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0", severity: "high", description: "랜섬웨어 드로퍼(보안 공지)", source: "KISA 보안 공지", enabled: true, expires_at: iso(-60 * DAY), hit_count: 0, last_hit_at: null, created_by: "00000000-0000-4000-8000-0000000000me", created_by_email: "secops@corp.example", created_at: iso(30 * DAY) },
    { id: 5, type: "ip", value: "203.0.113.47", severity: "low", description: "스캐너(오탐 확인 후 꺼 둠)", source: "사내 분석", enabled: false, expires_at: null, hit_count: 4, last_hit_at: iso(6 * DAY), created_by: "u2", created_by_email: "it.lee@corp.example", created_at: iso(14 * DAY) },
  ];

  return { inventory, software, posture, changes, policies, postureEnabled: new Map(), iocs };
}

// ---------- 계산 (DB 함수와 같은 규칙) ----------

export const checkEnabled = (a: DemoAssets, c: CheckDef) => a.postureEnabled.get(c.check_id) ?? c.default_enabled;

export function postureScore(a: DemoAssets, deviceId: string): number | null {
  const p = a.posture.get(deviceId);
  if (!p) return null;
  let total = 0, ok = 0;
  POSTURE_CHECKS.forEach((c) => {
    const s = p.get(c.check_id);
    if (!s || s.status === "unknown" || !checkEnabled(a, c)) return;
    total += c.weight;
    if (s.status !== "fail") ok += c.weight;
  });
  return total ? Math.round((100 * ok) / total) : null;
}

const fails = (a: DemoAssets, deviceId: string) =>
  POSTURE_CHECKS.filter((c) => checkEnabled(a, c) && a.posture.get(deviceId)?.get(c.check_id)?.status === "fail").map((c) => c.title);

export function postureOverview(a: DemoAssets, devices: Device[]): PostureOverview {
  const scored = devices.map((d) => ({ d, s: postureScore(a, d.id) })).filter((x): x is { d: Device; s: number } => x.s != null);
  const avg = scored.length ? Math.round(scored.reduce((t, x) => t + x.s, 0) / scored.length) : null;
  return {
    score: avg, devices: devices.length, scored: scored.length,
    buckets: [scored.filter((x) => x.s < 50).length, scored.filter((x) => x.s >= 50 && x.s < 70).length, scored.filter((x) => x.s >= 70 && x.s < 90).length, scored.filter((x) => x.s >= 90).length],
    checks: POSTURE_CHECKS.map((c) => {
      const n = (st: PostureStatus) => devices.filter((d) => a.posture.get(d.id)?.get(c.check_id)?.status === st).length;
      return { ...c, enabled: checkEnabled(a, c), pass: n("pass"), warn: n("warn"), fail: n("fail"), unknown: n("unknown") };
    }),
    worst: scored.sort((x, y) => x.s - y.s || x.d.hostname.localeCompare(y.d.hostname)).slice(0, 8)
      .map((x) => ({ device_id: x.d.id, hostname: x.d.hostname, score: x.s, fails: fails(a, x.d.id) })),
  };
}

export function postureDevices(a: DemoAssets, devices: Device[], check: string | undefined, status: PostureStatus): PostureDeviceRow[] {
  return devices
    .filter((d) => !check || a.posture.get(d.id)?.get(check)?.status === status)
    .map((d) => {
      const s = check ? a.posture.get(d.id)?.get(check) : undefined;
      return { device_id: d.id, hostname: d.hostname, score: postureScore(a, d.id), status: s?.status ?? null, detail: s?.detail ?? null, checked_at: s?.checked_at ?? null, fails: fails(a, d.id) };
    })
    .sort((x, y) => (x.score ?? 999) - (y.score ?? 999) || x.hostname.localeCompare(y.hostname));
}

export function devicePosture(a: DemoAssets, deviceId: string): DevicePostureItem[] {
  const p = a.posture.get(deviceId);
  return POSTURE_CHECKS.map((c) => {
    const s = p?.get(c.check_id);
    return { check_id: c.check_id, title: c.title, description: c.description, remediation: c.remediation, category: c.category, weight: c.weight,
      enabled: checkEnabled(a, c), drift_alert: c.drift_alert, status: s?.status ?? null, detail: s?.detail ?? null,
      changed_at: s?.changed_at ?? null, failing_since: s?.failing_since ?? null, checked_at: s?.checked_at ?? null };
  });
}

export function assetOverview(a: DemoAssets, devices: Device[]): AssetOverview {
  const inv = devices.map((d) => a.inventory.get(d.id)).filter((x): x is DeviceInventory => !!x);
  const today = new Date().toISOString().slice(0, 10), in90 = dayStr(90 * DAY);
  const groups = new Map<string, AssetOverview["os"][number]>();
  inv.forEach((i) => {
    const k = i.os_label ?? i.os_name ?? "알 수 없음";
    const g = groups.get(k + i.os_end_of_support) ?? { label: k, product: i.os_product, end_of_support: i.os_end_of_support, n: 0 };
    g.n++; groups.set(k + i.os_end_of_support, g);
  });
  const makers = new Map<string, number>();
  inv.forEach((i) => makers.set(i.manufacturer ?? "알 수 없음", (makers.get(i.manufacturer ?? "알 수 없음") ?? 0) + 1));
  const titles = new Set<string>();
  a.software.forEach((l) => l.forEach((s) => titles.add(s.name)));
  return {
    devices: devices.length, inventoried: inv.length, software_titles: titles.size,
    installs_7d: a.changes.filter((c) => c.change === "installed" && Date.now() - Date.parse(c.observed_at) < 7 * DAY).length,
    unsupported: inv.filter((i) => i.os_end_of_support && i.os_end_of_support < today).length,
    ending_90d: inv.filter((i) => i.os_end_of_support && i.os_end_of_support >= today && i.os_end_of_support <= in90).length,
    domain_joined: inv.filter((i) => i.domain_joined).length,
    low_disk: inv.filter((i) => (i.disk_free_gb ?? Infinity) < 10).length,
    os: [...groups.values()].sort((x, y) => y.n - x.n || x.label.localeCompare(y.label)),
    manufacturers: [...makers].map(([label, n]) => ({ label, n })).sort((x, y) => y.n - x.n).slice(0, 6),
  };
}

export function assetRows(a: DemoAssets, devices: Device[]): AssetRow[] {
  return devices.map((d) => ({ ...(a.inventory.get(d.id) ?? emptyInventory(d.id)), hostname: d.hostname, last_seen_at: d.last_seen_at }));
}
const emptyInventory = (id: string): DeviceInventory => ({
  device_id: id, os_name: null, os_edition: null, os_display_version: null, os_build: null, os_ubr: null, os_product: null, os_arch: null,
  os_installed_at: null, os_label: null, os_end_of_support: null, manufacturer: null, model: null, serial_number: null, bios_version: null,
  cpu: null, cpu_cores: null, memory_mb: null, disk_total_gb: null, disk_free_gb: null, domain: null, domain_joined: null, last_user: null,
  adapters: [], software_count: 0, collected_at: null, updated_at: new Date().toISOString(),
});

export function softwareCatalog(a: DemoAssets, q?: string): SoftwareTitle[] {
  const m = new Map<string, SoftwareTitle & { ids: Set<string> }>();
  a.software.forEach((list, id) => list.forEach((s) => {
    if (q && !likeMatch(s.name, q) && !likeMatch(s.publisher, q)) return;
    const t = m.get(s.name) ?? { name: s.name, publisher: s.publisher, versions: [], devices: 0, first_seen_at: s.first_seen_at, ids: new Set() };
    if (!t.versions.includes(s.version)) t.versions.push(s.version);
    t.ids.add(id);
    if (s.first_seen_at < t.first_seen_at) t.first_seen_at = s.first_seen_at;
    m.set(s.name, t);
  }));
  return [...m.values()].map(({ ids, ...t }) => ({ ...t, devices: ids.size, versions: t.versions.sort((x, y) => versionCmp(y, x)) }))
    .sort((x, y) => y.devices - x.devices || x.name.localeCompare(y.name));
}

export function softwareInstalls(a: DemoAssets, devices: Device[], name: string): SoftwareInstall[] {
  const out: SoftwareInstall[] = [];
  devices.forEach((d) => a.software.get(d.id)?.filter((s) => s.name === name).forEach((s) =>
    out.push({ device_id: d.id, hostname: d.hostname, version: s.version, publisher: s.publisher, scope: s.scope, install_date: s.install_date, first_seen_at: s.first_seen_at })));
  return out.sort((x, y) => x.hostname.localeCompare(y.hostname));
}

const SEV_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
export function softwareExposure(a: DemoAssets, devices: Device[]): SoftwareExposure[] {
  return a.policies.map((p) => {
    const hits: { id: string; host: string; name: string; version: string }[] = [];
    devices.forEach((d) => a.software.get(d.id)?.forEach((s) => { if (policyMatches(p, s)) hits.push({ id: d.id, host: d.hostname, name: s.name, version: s.version }); }));
    const ids = [...new Set(hits.map((h) => h.id))];
    return {
      policy_id: p.id, kind: p.kind, severity: p.severity, name_pattern: p.name_pattern, publisher_pattern: p.publisher_pattern, fixed_version: p.fixed_version,
      reference: p.reference, reason: p.reason, builtin: p.builtin, enabled: p.enabled, created_at: p.created_at,
      software: [...new Set(hits.map((h) => h.name))].slice(0, 10), versions: [...new Set(hits.map((h) => h.version))].slice(0, 10),
      devices: ids.length, device_ids: ids.slice(0, 200), hostnames: ids.slice(0, 8).map((id) => hits.find((h) => h.id === id)!.host),
    };
  }).sort((x, y) => y.devices - x.devices || SEV_RANK[y.severity] - SEV_RANK[x.severity] || x.policy_id - y.policy_id);
}
