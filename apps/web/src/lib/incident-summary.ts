// ---------------------------------------------------------------------------
// 인시던트 자동 요약 — 경보 순서를 사람이 읽는 문장으로 바꾼다.
// 생성형 AI 를 쓰지 않는 규칙 기반이라 같은 입력에는 항상 같은 문장이 나오고, 사내 데이터가 외부로 나가지 않는다.
// ---------------------------------------------------------------------------
import type { Alert, Incident } from "./data/types";

export const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact",
] as const;

export const TACTIC_KO: Record<string, string> = {
  Reconnaissance: "정찰", "Resource Development": "자원 개발", "Initial Access": "초기 침투", Execution: "실행",
  Persistence: "지속성 확보", "Privilege Escalation": "권한 상승", "Defense Evasion": "방어 회피",
  "Credential Access": "자격 증명 탈취", Discovery: "내부 탐색", "Lateral Movement": "내부 확산",
  Collection: "정보 수집", "Command and Control": "원격 제어(C2)", Exfiltration: "유출", Impact: "피해 발생",
};

const s = (v: unknown) => (typeof v === "string" || typeof v === "number" ? String(v) : "");
const fileName = (p: string) => p.split("\\").pop() ?? p;

function step(a: Alert): string {
  const d = a.details;
  switch (a.rule_id) {
    case "EDR-AUTH-001": return `${s(d.src_ip) || "외부"}에서 로그온 ${s(d.failures) ? `${s(d.failures)}회 ` : ""}실패(무차별 대입)`;
    case "EDR-AUTH-002": return `같은 출발지에서 ${s(d.user) || "계정"} 로그온 성공`;
    case "EDR-AUTH-003": return `외부 IP ${s(d.src_ip)}에서 원격 데스크톱 로그온`;
    case "EDR-NET-001": return `외부 ${s(d.remote_ip)}에서 RDP 포트로 연결`;
    case "EDR-ACCT-001": return `로컬 계정 생성${a.title.includes(":") ? `(${a.title.split(":").pop()!.trim()})` : ""}`;
    case "EDR-ACCT-002": return "보안 그룹에 구성원 추가";
    case "EDR-PERSIST-001": return `서비스 설치${a.title.includes(":") ? `(${a.title.split(":").pop()!.trim()})` : ""}`;
    case "EDR-PERSIST-002": return `자동 실행 등록(${s(d.entry) || "항목"})`;
    case "EDR-PERSIST-003": return "예약 작업 생성";
    case "EDR-MAL-001": return `평판 악성 파일 실행(${fileName(s(d.path)) || "파일"}${s(d.vt_malicious) ? `, 백신 ${s(d.vt_malicious)}/${s(d.vt_total)} 탐지` : ""})`;
    case "EDR-LOG-001": return "이벤트 로그 삭제";
    default: return a.title;
  }
}

export interface Summary {
  headline: string;
  narrative: string[];      // 시간 순 단계
  assessment: string;
  recommendations: string[]; // 사람이 할 조치(이 시스템은 차단하지 않음)
  stages: string[];          // 진행된 ATT&CK 전술(순서대로)
}

export function summarize(inc: Incident, alerts: Alert[], hostnames: Record<string, string>): Summary {
  const ordered = [...alerts].sort((a, b) => a.created_at.localeCompare(b.created_at));
  // 연속된 같은 규칙은 한 단계로 합친다
  const steps: string[] = [];
  let prev = "";
  let repeat = 0;
  for (const a of ordered) {
    const host = a.device_id ? hostnames[a.device_id] ?? a.hostname ?? "" : "";
    const key = a.rule_id + host;
    if (key === prev) { repeat++; continue; }
    if (repeat > 0) steps[steps.length - 1] += ` 외 ${repeat}건`;
    repeat = 0;
    prev = key;
    const multi = inc.device_ids.length > 1 && host ? `[${host}] ` : "";
    steps.push(multi + step(a));
  }
  if (repeat > 0) steps[steps.length - 1] += ` 외 ${repeat}건`;

  // 경보가 많은 장치부터
  const perDev = new Map<string, number>();
  ordered.forEach((a) => a.device_id && perDev.set(a.device_id, (perDev.get(a.device_id) ?? 0) + 1));
  const hosts = [...inc.device_ids].sort((x, y) => (perDev.get(y) ?? 0) - (perDev.get(x) ?? 0)).map((id) => hostnames[id]).filter(Boolean);
  const mins = Math.max(1, Math.round((Date.parse(inc.last_seen_at) - Date.parse(inc.first_seen_at)) / 60000));
  const span = mins < 60 ? `${mins}분` : mins < 1440 ? `${Math.round(mins / 60)}시간` : `${Math.round(mins / 1440)}일`;
  const stages = TACTIC_ORDER.filter((t) => inc.tactics.includes(t));
  const headline = `${hosts.length > 1 ? `${hosts[0]} 등 장치 ${hosts.length}대` : hosts[0] ?? "장치"}에서 ${span} 동안 경보 ${inc.alert_count}건`;

  const has = (r: string) => inc.rule_ids.includes(r);
  let assessment: string;
  if (stages.length >= 3) {
    assessment = `ATT&CK ${stages.length}개 단계(${stages.map((t) => TACTIC_KO[t]).join(" → ")})가 이어진 정황입니다. 단일 오탐보다 실제 침해일 가능성을 먼저 확인하세요.`;
  } else if (has("EDR-MAL-001")) {
    assessment = "악성으로 알려진 파일이 실행되었습니다. 같은 해시가 다른 PC 에도 있는지 먼저 확인하세요.";
  } else if (has("EDR-AUTH-001") && !has("EDR-AUTH-002")) {
    assessment = "로그온 실패만 있고 성공은 아직 없습니다. 출발지 차단과 계정 잠금 정책을 확인하세요.";
  } else if (inc.rule_ids.every((r) => r.startsWith("EDR-PERSIST"))) {
    assessment = "자동 실행·서비스·예약 작업 변경입니다. 소프트웨어 설치·업데이트 일정과 맞는지 확인하면 대부분 판단할 수 있습니다.";
  } else {
    assessment = `${stages.map((t) => TACTIC_KO[t]).join(", ") || "기타"} 단계의 활동입니다.`;
  }

  const rec: string[] = [];
  const pubIps = inc.ips.filter((ip) => !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip));
  if (pubIps.length) rec.push(`방화벽에서 출발지 ${pubIps.join(", ")} 차단, RDP(3389) 외부 노출 여부 점검`);
  if (has("EDR-AUTH-002") || has("EDR-AUTH-003")) rec.push(`로그온에 성공한 계정(${inc.users.join(", ") || "해당 계정"}) 비밀번호 변경과 세션 종료`);
  if (has("EDR-ACCT-001") || has("EDR-ACCT-002")) rec.push("새로 만들어지거나 그룹에 추가된 계정을 확인하고 불필요하면 삭제");
  const malHost = ordered.find((a) => a.rule_id === "EDR-MAL-001")?.device_id;
  if (has("EDR-MAL-001")) rec.push(`기존 보안 솔루션으로 ${(malHost && hostnames[malHost]) || hosts[0] || "해당 PC"} 네트워크 격리·정밀 검사, 같은 해시가 있는 다른 PC 확인`);
  if (has("EDR-PERSIST-002") || has("EDR-PERSIST-001") || has("EDR-PERSIST-003")) rec.push("새로 등록된 자동 실행·서비스·예약 작업이 승인된 프로그램인지 확인");
  if (has("EDR-LOG-001")) rec.push("지워진 기간의 로그를 다른 곳(백업, 중앙 로그 서버)에서 확보");
  if (!rec.length) rec.push("관련 PC 사용자에게 해당 시간대 작업 내용을 확인");

  return { headline, narrative: steps, assessment, recommendations: rec, stages };
}
