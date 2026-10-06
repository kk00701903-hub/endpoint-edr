// 소프트웨어 정책(취약 버전·금지) 일치 규칙 — DB 함수 edr_sw_matches / edr_version_cmp / edr_like 와 같게 맞춘다.
// 화면(장치 상세의 설치 프로그램 표시)과 데모 데이터가 함께 쓴다.
import type { SoftwarePolicyKind } from "./data/types";

/** "6.22.0" < "6.23" — 숫자 부분만 차례로 비교. -1 / 0 / 1 */
export function versionCmp(a: string | null | undefined, b: string | null | undefined): number {
  const x = (a ?? "").match(/\d{1,30}/g)?.map(Number) ?? [];
  const y = (b ?? "").match(/\d{1,30}/g)?.map(Number) ?? [];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** 이름 조건: 대소문자 무시 "포함", '*' 는 아무 글자 */
export function likeMatch(value: string | null | undefined, pattern: string): boolean {
  const re = new RegExp(pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*"), "i");
  return re.test(value ?? "");
}

export interface PolicyRule {
  kind: SoftwarePolicyKind;
  name_pattern: string;
  publisher_pattern: string | null;
  fixed_version: string | null;
  enabled: boolean;
}

export const policyMatches = (p: PolicyRule, s: { name: string; version: string; publisher: string | null }) =>
  p.enabled && likeMatch(s.name, p.name_pattern) && (!p.publisher_pattern || likeMatch(s.publisher, p.publisher_pattern))
  && (p.kind === "prohibited" || !p.fixed_version || versionCmp(s.version, p.fixed_version) < 0);
