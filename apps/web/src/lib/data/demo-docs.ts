import "server-only";
import type { Device, DocDeviceRow, DocFindingKind, DocFindingRow, DocOverview, DocPiiKind, DocScanPolicy } from "./types";
import { DOC_POLICY_DEFAULT } from "./doc-defaults";

// ---------------------------------------------------------------------------
// 데모 모드의 문서 감사 예시 데이터와 계산. 규칙은 DB(마이그레이션 0009)와 같게 맞춘다:
//   개인정보·키워드 문서는 건수 많은 순, 오래된 문서는 오래된 순. 서버에는 위치와 건수만 있다.
// ---------------------------------------------------------------------------

const DAY = 86_400_000, HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

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

type Finding = Omit<DocFindingRow, "hostname">;
interface Scan { last_scan_at: string; status: "running" | "done"; files_scanned: number; files_skipped: number }

export interface DemoDocs {
  policy: DocScanPolicy;
  findings: Finding[];
  scans: Map<string, Scan>;
  requests: Map<string, { requested_at: string; picked: boolean }>;
}

const USERS = ["kim.minji", "lee.junho", "park.seoyeon", "choi.hyun", "jung.daeun", "kang.taeho"];
// [폴더, 파일명, 개인정보, 키워드]
const PII_DOCS: [string, string, Partial<Record<DocPiiKind, number>>, Record<string, number>][] = [
  ["Documents", "고객명단_2023.xlsx", { rrn: 214, phone: 0 }, {}],
  ["Desktop", "급여대장_2024-03.xlsx", { rrn: 87 }, { 대외비: 1 }],
  ["Downloads", "지원자_이력서_모음.pdf", { rrn: 12, passport: 3 }, {}],
  ["Documents\\영업", "회원정보_추출.csv", { rrn: 1530, card: 41 }, {}],
  ["Documents\\인사", "인사기록카드_홍길동.hwp", { rrn: 1, driver: 1 }, { 대외비: 2 }],
  ["Desktop", "외국인 근로자 명부.xlsx", { frn: 38 }, {}],
  ["Downloads", "출장자_여권사본.pdf", { passport: 6 }, {}],
  ["Documents", "법인카드_사용내역.xls", { card: 9 }, {}],
];
const KW_DOCS: [string, string, Record<string, number>][] = [
  ["Documents\\기획", "2025_사업계획_대외비.pptx", { 대외비: 14, 기밀: 2 }],
  ["Desktop", "M&A_검토_메모.docx", { 기밀: 6 }],
  ["Documents", "신제품_원가표.xlsx", { 영업비밀: 3 }],
  ["Downloads", "회의록_0312.hwpx", { 대외비: 1 }],
];
const OLD_DOCS: [string, string, string | null][] = [
  ["Documents\\백업", "2016_거래처_목록.xls", null],
  ["Documents", "옛날_제안서.ppt", null],
  ["Desktop", "스캔_2017.pdf", null],
  ["Documents\\보관", "인수인계_2018.doc", "암호가 걸린 문서"],
  ["Downloads", "설치안내_2019.txt", null],
  ["Documents\\백업", "2015_회계자료.hwp", null],
];

export function makeDemoDocs(devices: Device[]): DemoDocs {
  const policy: DocScanPolicy = {
    ...DOC_POLICY_DEFAULT,
    enabled: true,
    keywords: ["대외비", "기밀", "영업비밀"],
    notice_confirmed_at: iso(21 * DAY),
    notice_confirmed_by: "00000000-0000-4000-8000-0000000000me",
    notice_confirmed_by_email: "secops@corp.example",
    updated_at: iso(21 * DAY),
  };
  const findings: Finding[] = [];
  const scans = new Map<string, Scan>();
  const requests = new Map<string, { requested_at: string; picked: boolean }>();
  // 서버(SRV) 는 사용자 문서가 거의 없다. 일부 PC 는 아직 검사 전
  const pcs = devices.filter((d) => !d.hostname.startsWith("SRV"));
  pcs.forEach((d, i) => {
    const r = rng(hashStr(d.id) ^ 0x5d0c);
    if (i % 7 === 6) return; // 아직 검사 결과 없음
    const user = pick(r, USERS);
    const base = `C:\\Users\\${user}`;
    const add = (folder: string, name: string, f: Partial<Finding>) => {
      const path = `${base}\\${folder}\\${name}`;
      if (findings.some((x) => x.device_id === d.id && x.path === path)) return;
      findings.push({
        device_id: d.id, path, ext: name.split(".").pop()!.toLowerCase(), size: Math.round(20_000 + r() * 4_000_000),
        modified_at: iso((5 + r() * 400) * DAY), pii: {}, pii_total: 0, keywords: {}, keyword_total: 0, stale: false, unreadable: null,
        last_seen_at: iso(r() * 30 * HOUR), ...f,
      });
    };
    const nPii = d.hostname.includes("HR") || d.hostname.includes("FIN") ? 3 : Math.floor(r() * 2.2);
    for (let k = 0; k < nPii; k++) {
      const [folder, name, pii, kw] = pick(r, PII_DOCS);
      // 같은 이름의 문서라도 PC 마다 건수가 다르게
      const scale = 0.2 + r() * 1.1;
      const p = Object.fromEntries(Object.entries(pii).filter(([, n]) => n > 0).map(([k, n]) => [k, Math.max(1, Math.round(n * scale))])) as Partial<Record<DocPiiKind, number>>;
      add(folder, name, { pii: p, pii_total: Object.values(p).reduce((s, n) => s + (n ?? 0), 0), keywords: kw,
        keyword_total: Object.values(kw).reduce((s, n) => s + n, 0) });
    }
    if (r() < 0.45) {
      const [folder, name, kw] = pick(r, KW_DOCS);
      add(folder, name, { keywords: kw, keyword_total: Object.values(kw).reduce((s, n) => s + n, 0) });
    }
    const nOld = Math.floor(r() * 3.5);
    for (let k = 0; k < nOld; k++) {
      const [folder, name, unreadable] = pick(r, OLD_DOCS);
      add(folder, name, { stale: true, unreadable, modified_at: iso((1100 + r() * 2000) * DAY) });
    }
    scans.set(d.id, { last_scan_at: iso((1 + r() * 140) * HOUR), status: i === 2 ? "running" : "done",
      files_scanned: Math.round(300 + r() * 4000), files_skipped: Math.round(r() * 25) });
  });
  if (pcs[0]) requests.set(pcs[0].id, { requested_at: iso(25 * 60_000), picked: true });
  return { policy, findings, scans, requests };
}

export function docOverview(s: DemoDocs, devices: Device[]): DocOverview {
  const byKind: Partial<Record<DocPiiKind, number>> = {};
  const byWord: Record<string, number> = {};
  for (const f of s.findings) {
    for (const [k, n] of Object.entries(f.pii)) byKind[k as DocPiiKind] = (byKind[k as DocPiiKind] ?? 0) + (n ?? 0);
    for (const k of Object.keys(f.keywords)) byWord[k] = (byWord[k] ?? 0) + 1;
  }
  const done = [...s.scans.values()].filter((x) => x.status === "done");
  const pii = s.findings.filter((f) => f.pii_total > 0);
  const stale = s.findings.filter((f) => f.stale);
  return {
    devices: devices.filter((d) => d.status === "active").length,
    devices_scanned: done.length,
    last_scan_at: done.map((x) => x.last_scan_at).sort().at(-1) ?? null,
    running: s.scans.size - done.length,
    pending_requests: s.requests.size,
    pii_files: pii.length,
    pii_devices: new Set(pii.map((f) => f.device_id)).size,
    pii_by_kind: byKind,
    keyword_files: s.findings.filter((f) => f.keyword_total > 0).length,
    keywords_by_word: byWord,
    stale_files: stale.length,
    stale_bytes: stale.reduce((t, f) => t + (f.size ?? 0), 0),
  };
}

export function docFindings(s: DemoDocs, devices: Device[], opts: { kind: DocFindingKind; q?: string; device?: string; keyword?: string }): DocFindingRow[] {
  const name = new Map(devices.map((d) => [d.id, d.hostname]));
  const q = opts.q?.toLowerCase();
  return s.findings
    .filter((f) => (opts.kind === "pii" ? f.pii_total > 0 : opts.kind === "keyword" ? f.keyword_total > 0 : f.stale))
    .filter((f) => !opts.device || f.device_id === opts.device)
    .filter((f) => !opts.keyword || opts.keyword in f.keywords)
    .map((f) => ({ ...f, hostname: name.get(f.device_id) ?? "?" }))
    .filter((f) => !q || f.path.toLowerCase().includes(q) || f.hostname.toLowerCase().includes(q))
    .sort((a, b) =>
      opts.kind === "pii" ? b.pii_total - a.pii_total || a.hostname.localeCompare(b.hostname)
        : opts.kind === "keyword" ? b.keyword_total - a.keyword_total || a.hostname.localeCompare(b.hostname)
          : (a.modified_at ?? "").localeCompare(b.modified_at ?? ""));
}

export function docDevices(s: DemoDocs, devices: Device[]): DocDeviceRow[] {
  const count = (id: string, f: (x: Finding) => boolean) => s.findings.filter((x) => x.device_id === id && f(x)).length;
  return devices.filter((d) => d.status === "active").map((d) => {
    const sc = s.scans.get(d.id);
    const rq = s.requests.get(d.id);
    return {
      device_id: d.id, hostname: d.hostname, last_seen_at: d.last_seen_at,
      last_scan_at: sc?.last_scan_at ?? null, last_status: sc?.status ?? null, files_scanned: sc?.files_scanned ?? null, files_skipped: sc?.files_skipped ?? null,
      pii_files: count(d.id, (x) => x.pii_total > 0), keyword_files: count(d.id, (x) => x.keyword_total > 0), stale_files: count(d.id, (x) => x.stale),
      pending_request_at: rq?.requested_at ?? null, request_picked: rq ? rq.picked : null,
    };
  }).sort((a, b) => b.pii_files - a.pii_files || a.hostname.localeCompare(b.hostname));
}

