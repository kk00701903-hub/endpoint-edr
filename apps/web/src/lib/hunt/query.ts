// ---------------------------------------------------------------------------
// 헌팅 쿼리 언어 (EQL/KQL 를 단순화한 형태)
//
//   process.name = "powershell.exe" and process.cmdline ~ "-enc"
//   net.remote_port = 3389 and net.direction = inbound
//   event.id = 4625 and event.src_ip = 45.155.205.99
//   autorun.command ~ "\programdata\"
//   device.hostname ~ SRV and process.user ~ admin
//
//   연산자: =  !=  ~(포함)  !~(미포함)  >  <  >=  <=
//   조건은 and 로만 잇는다. 한 쿼리는 한 데이터셋(process/net/event/autorun)만 본다.
//   SQL 로 바꾸지 않고 필드 목록에 있는 컬럼만 허용 → 주입 불가.
// ---------------------------------------------------------------------------

export type Dataset = "process" | "net" | "event" | "autorun";
export type Op = "=" | "!=" | "~" | "!~" | ">" | "<" | ">=" | "<=";
type FieldKind = "text" | "number" | "ip" | "bool";

export interface FieldDef {
  key: string;            // 쿼리에 쓰는 이름
  dataset: Dataset | "any";
  column: string;         // DB 컬럼
  kind: FieldKind;
  label: string;          // 화면 표시
  example: string;
}

export const FIELDS: FieldDef[] = [
  { key: "process.name", dataset: "process", column: "name", kind: "text", label: "프로세스 이름", example: "powershell.exe" },
  { key: "process.cmdline", dataset: "process", column: "command_line", kind: "text", label: "명령줄", example: "-enc" },
  { key: "process.path", dataset: "process", column: "path", kind: "text", label: "실행 파일 경로", example: "\\AppData\\" },
  { key: "process.user", dataset: "process", column: "username", kind: "text", label: "실행 계정", example: "SYSTEM" },
  { key: "process.sha256", dataset: "process", column: "sha256", kind: "text", label: "파일 해시", example: "3a7bd3…" },
  { key: "process.pid", dataset: "process", column: "pid", kind: "number", label: "PID", example: "4321" },
  { key: "net.remote_ip", dataset: "net", column: "remote_ip", kind: "ip", label: "원격 IP", example: "45.155.205.99" },
  { key: "net.remote_port", dataset: "net", column: "remote_port", kind: "number", label: "원격 포트", example: "443" },
  { key: "net.local_port", dataset: "net", column: "local_port", kind: "number", label: "로컬 포트", example: "3389" },
  { key: "net.direction", dataset: "net", column: "direction", kind: "text", label: "방향", example: "inbound" },
  { key: "net.process", dataset: "net", column: "process_name", kind: "text", label: "통신 프로세스", example: "svchost.exe" },
  { key: "net.external", dataset: "net", column: "is_external", kind: "bool", label: "외부 통신", example: "true" },
  { key: "event.id", dataset: "event", column: "event_id", kind: "number", label: "이벤트 ID", example: "4625" },
  { key: "event.user", dataset: "event", column: "target_user", kind: "text", label: "대상 계정", example: "administrator" },
  { key: "event.src_ip", dataset: "event", column: "src_ip", kind: "ip", label: "출발지 IP", example: "203.0.113.47" },
  { key: "event.logon_type", dataset: "event", column: "logon_type", kind: "number", label: "로그온 유형", example: "10" },
  { key: "autorun.name", dataset: "autorun", column: "entry_name", kind: "text", label: "자동 실행 이름", example: "OneDrive" },
  { key: "autorun.command", dataset: "autorun", column: "command", kind: "text", label: "자동 실행 명령", example: "\\ProgramData\\" },
  { key: "autorun.location", dataset: "autorun", column: "location", kind: "text", label: "자동 실행 위치", example: "ScheduledTask" },
  { key: "device.hostname", dataset: "any", column: "hostname", kind: "text", label: "장치 이름", example: "SRV-WEB-01" },
];

export const DATASET_LABEL: Record<Dataset, string> = { process: "프로세스", net: "네트워크 연결", event: "보안 이벤트", autorun: "자동 실행" };

export interface Term { field: FieldDef; op: Op; value: string }
export interface ParsedQuery { dataset: Dataset; terms: Term[] }
export type ParseResult = { ok: true; query: ParsedQuery } | { ok: false; error: string; at?: number };

const OPS: Op[] = [">=", "<=", "!=", "!~", "=", "~", ">", "<"];

export function parseQuery(src: string): ParseResult {
  const text = src.trim();
  if (!text) return { ok: false, error: "조건을 입력하세요. 예: process.name = powershell.exe" };
  // and 로 나누되 따옴표 안의 and 는 건드리지 않는다
  const parts: { s: string; at: number }[] = [];
  let buf = "", quote = false, start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '"') quote = !quote;
    if (!quote && /\s/.test(c) && /^and\s/i.test(text.slice(i + 1)) && buf.trim()) {
      parts.push({ s: buf, at: start });
      i += 4;
      buf = "";
      start = i + 1;
      continue;
    }
    buf += c;
  }
  if (quote) return { ok: false, error: "따옴표가 닫히지 않았습니다" };
  if (buf.trim()) parts.push({ s: buf, at: start });
  if (/\bor\b/i.test(text.replace(/"[^"]*"/g, ""))) return { ok: false, error: "or 는 아직 지원하지 않습니다. 쿼리를 두 개로 나눠 실행하세요" };

  const terms: Term[] = [];
  let dataset: Dataset | null = null;
  for (const p of parts) {
    const m = p.s.trim().match(/^([a-z_.]+)\s*(>=|<=|!=|!~|=|~|>|<)\s*(.+)$/i);
    if (!m) return { ok: false, error: `"${p.s.trim()}" 를 이해하지 못했습니다. 형식: 필드 연산자 값`, at: p.at };
    const [, key, op, raw] = m as unknown as [string, string, Op, string];
    const field = FIELDS.find((f) => f.key === key.toLowerCase());
    if (!field) return { ok: false, error: `알 수 없는 필드 "${key}". 사용 가능: ${FIELDS.map((f) => f.key).join(", ")}`, at: p.at };
    if (!OPS.includes(op)) return { ok: false, error: `알 수 없는 연산자 ${op}` };
    let value = raw.trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    if (!value) return { ok: false, error: `${key} 의 값이 비어 있습니다`, at: p.at };
    if (field.kind === "number" && (!/^-?\d+$/.test(value) || op === "~" || op === "!~")) return { ok: false, error: `${key} 는 숫자 필드입니다 (=, !=, >, < 사용)` };
    if (field.kind === "ip" && !["=", "!="].includes(op)) return { ok: false, error: `${key} 는 = 또는 != 만 쓸 수 있습니다` };
    if (field.kind === "ip" && !/^[0-9a-f.:]+$/i.test(value)) return { ok: false, error: `${value} 는 IP 주소 형식이 아닙니다` };
    if (field.kind === "bool" && !["true", "false"].includes(value.toLowerCase())) return { ok: false, error: `${key} 값은 true 또는 false` };
    if (field.kind === "text" && [">", "<", ">=", "<="].includes(op)) return { ok: false, error: `${key} 는 글자 필드입니다 (=, !=, ~, !~ 사용)` };
    if (field.dataset !== "any") {
      if (dataset && dataset !== field.dataset) return { ok: false, error: `한 쿼리에는 한 종류의 기록만 쓸 수 있습니다 (지금: ${DATASET_LABEL[dataset]}, ${DATASET_LABEL[field.dataset]})` };
      dataset = field.dataset;
    }
    terms.push({ field, op, value });
  }
  if (!dataset) return { ok: false, error: "process. / net. / event. / autorun. 로 시작하는 조건이 하나 이상 필요합니다" };
  return { ok: true, query: { dataset, terms } };
}

/** 메모리 위 배열에 같은 쿼리를 적용(데모 데이터용). DB 쪽은 supabase-source 가 같은 의미로 번역한다. */
export function matches(row: Record<string, unknown>, t: Term): boolean {
  const raw = row[t.field.column];
  if (t.field.kind === "number") {
    const a = Number(raw), b = Number(t.value);
    return t.op === "=" ? a === b : t.op === "!=" ? a !== b : t.op === ">" ? a > b : t.op === "<" ? a < b : t.op === ">=" ? a >= b : a <= b;
  }
  if (t.field.kind === "bool") return String(raw) === t.value.toLowerCase() ? t.op === "=" : t.op === "!=";
  const s = String(raw ?? "").toLowerCase(), v = t.value.toLowerCase();
  if (t.op === "=") return s === v;
  if (t.op === "!=") return s !== v;
  if (t.op === "~") return s.includes(v);
  if (t.op === "!~") return !s.includes(v);
  return false;
}

export const EXAMPLE_QUERIES: { name: string; query: string; why: string }[] = [
  { name: "인코딩된 PowerShell", query: 'process.name = powershell.exe and process.cmdline ~ "-enc"', why: "난독화된 명령 실행 — 공격 도구의 전형" },
  { name: "ProgramData 에서 실행된 파일", query: 'process.path ~ "\\programdata\\" and process.name !~ msmpeng', why: "정상 프로그램이 거의 쓰지 않는 경로" },
  { name: "외부에서 들어온 RDP", query: "net.local_port = 3389 and net.direction = inbound and net.external = true", why: "RDP 가 인터넷에 노출됐는지" },
  { name: "관리자 계정 로그온 실패", query: "event.id = 4625 and event.user ~ admin", why: "무차별 대입 대상 계정" },
  { name: "사용자 경로의 자동 실행", query: 'autorun.command ~ "\\appdata\\"', why: "사용자 권한으로 심은 지속성" },
];

/** 연산자 없이 값만 입력하면(예: 45.155.205.99, 해시, powershell) 알맞은 쿼리로 바꿔 준다 */
export function normalizeQuery(q: string): string {
  const t = q.trim();
  if (!t || /(>=|<=|!=|!~|=|~|>|<)/.test(t)) return t;
  if (/^[0-9a-f]{64}$/i.test(t)) return `process.sha256 = ${t.toLowerCase()}`;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(t)) return `net.remote_ip = ${t}`;
  return `process.name ~ ${t.includes(" ") ? `"${t}"` : t}`;
}
