import type { AlertStatus, Resolution, Role, Severity } from "./data/types";

/** 서버 렌더링 시점의 현재 시각(렌더 함수 안에서 Date.now 를 직접 부르지 않기 위함) */
export const nowMs = () => Date.now();

const rtf = new Intl.RelativeTimeFormat("ko", { numeric: "auto" });

/** "3분 전", "어제" 처럼 사람이 읽는 상대 시간 */
export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "기록 없음";
  const s = Math.round((Date.parse(iso) - now) / 1000);
  const a = Math.abs(s);
  if (a < 45) return "방금";
  if (a < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (a < 86400) return rtf.format(Math.round(s / 3600), "hour");
  if (a < 86400 * 30) return rtf.format(Math.round(s / 86400), "day");
  return rtf.format(Math.round(s / (86400 * 30)), "month");
}

const dtf = new Intl.DateTimeFormat("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: "Asia/Seoul" });
export const stamp = (iso: string | null | undefined) => (iso ? dtf.format(new Date(iso)) : "—");

const dayFmt = new Intl.DateTimeFormat("ko-KR", { month: "numeric", day: "numeric", timeZone: "Asia/Seoul" });
export const day = (iso: string) => dayFmt.format(new Date(iso));
const fullDayFmt = new Intl.DateTimeFormat("ko-KR", { year: "numeric", month: "long", day: "numeric", timeZone: "Asia/Seoul" });
/** 연도까지: 2027년 1월 1일 */
export const fullDay = (iso: string) => fullDayFmt.format(new Date(iso));
const hourFmt = new Intl.DateTimeFormat("ko-KR", { hour: "2-digit", hour12: false, timeZone: "Asia/Seoul" });
export const hour = (iso: string) => hourFmt.format(new Date(iso));

export const num = (n: number | null | undefined) => (n == null ? "—" : n.toLocaleString("ko-KR"));

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1 << 20) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1 << 20)).toFixed(1)} MB`;
}

export function duration(sec: number): string {
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}일 ${h}시간`;
  if (h) return `${h}시간 ${m}분`;
  return `${m}분`;
}

export const SEVERITY_LABEL: Record<Severity, string> = { critical: "긴급", high: "높음", medium: "보통", low: "낮음" };
export const STATUS_LABEL: Record<AlertStatus, string> = { open: "새 경보", acknowledged: "조사 중", closed: "종결" };
export const RESOLUTION_LABEL: Record<Resolution, string> = {
  true_positive: "실제 위협", false_positive: "오탐", benign: "정상 활동", suppressed: "예외 규칙으로 종결",
};
export const ROLE_LABEL: Record<Role, string> = { owner: "소유자", admin: "관리자", analyst: "분석가", viewer: "열람자" };

export type Liveness = "online" | "stale" | "offline";
export function liveness(lastSeen: string | null): Liveness {
  const a = lastSeen ? Date.now() - Date.parse(lastSeen) : Infinity;
  return a < 15 * 60_000 ? "online" : a < 86_400_000 ? "stale" : "offline";
}
export const LIVENESS_LABEL: Record<Liveness, string> = { online: "연결됨", stale: "응답 지연", offline: "연결 끊김" };

/** 빌드 번호로 사람이 아는 이름을 붙인다 */
export function winName(v: string | null): string {
  if (!v) return "—";
  const build = Number(v.split(".").at(-1));
  const map: Record<number, string> = { 19045: "Windows 10 22H2", 22621: "Windows 11 22H2", 22631: "Windows 11 23H2", 26100: "Windows 11 24H2", 20348: "Windows Server 2022", 17763: "Windows Server 2019", 26200: "Windows 11 25H2" };
  return map[build] ?? v;
}
