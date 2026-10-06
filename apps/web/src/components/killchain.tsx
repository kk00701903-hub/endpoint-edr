import { cn } from "@/lib/cn";
import { TACTIC_KO, TACTIC_ORDER } from "@/lib/incident-summary";

// 정찰·자원 개발은 엔드포인트에서 볼 수 없으므로 뺀 12단계
export const STAGES = TACTIC_ORDER.filter((t) => t !== "Reconnaissance" && t !== "Resource Development");

/**
 * 킬체인 단계 막대 — 인시던트가 공격 흐름의 어디까지 진행됐는지.
 * compact: 목록용 작은 막대(라벨 없음, 툴팁), full: 단계 이름 표시.
 */
export function KillChain({ tactics, compact = false, className }: { tactics: string[]; compact?: boolean; className?: string }) {
  const lit = new Set(tactics);
  const last = Math.max(-1, ...STAGES.map((t, i) => (lit.has(t) ? i : -1)));
  if (compact) {
    return (
      <span className={cn("inline-flex items-center gap-[2px]", className)} role="img"
        aria-label={`진행 단계: ${STAGES.filter((t) => lit.has(t)).map((t) => TACTIC_KO[t]).join(", ") || "없음"}`}>
        {STAGES.map((t, i) => (
          <span key={t} title={TACTIC_KO[t]}
            className={cn("h-2.5 w-2 rounded-[1.5px]", lit.has(t) ? "bg-sev-high" : i <= last ? "bg-line-strong" : "bg-surface-3")} />
        ))}
      </span>
    );
  }
  return (
    <ol className={cn("grid grid-cols-6 gap-px overflow-hidden rounded-md border border-line bg-line lg:grid-cols-12", className)} aria-label="공격 단계 (MITRE ATT&CK 전술)">
      {STAGES.map((t, i) => {
        const on = lit.has(t);
        return (
          <li key={t} className={cn("flex min-h-14 flex-col justify-between px-2 py-1.5", on ? "bg-sev-critical-wash" : "bg-surface")}>
            <span className={cn("h-1 w-full rounded-full", on ? "bg-sev-high" : i <= last ? "bg-line-strong" : "bg-surface-3")} aria-hidden />
            <span className={cn("mt-1.5 text-[12px] leading-tight", on ? "font-semibold text-ink" : "text-muted")}>{TACTIC_KO[t]}</span>
            <span className="sr-only">{on ? "관측됨" : "관측 안 됨"}</span>
          </li>
        );
      })}
    </ol>
  );
}
