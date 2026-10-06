import Link from "next/link";
import type { Severity } from "@/lib/data/types";
import { SEVERITIES } from "@/lib/data/types";
import { SEVERITY_LABEL, num } from "@/lib/format";
import { SEV_BG } from "../ui";

/** 처리 대기 경보의 심각도 비율 막대. 각 구간은 해당 심각도 경보 목록으로 이어진다. */
export function SeverityStrip({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const total = SEVERITIES.reduce((s, k) => s + (counts[k] ?? 0), 0);
  return (
    <div>
      <div className="flex h-3 gap-[2px] overflow-hidden rounded-full bg-surface-3" role="img"
        aria-label={SEVERITIES.map((s) => `${SEVERITY_LABEL[s]} ${counts[s] ?? 0}건`).join(", ")}>
        {total > 0 && SEVERITIES.map((s) => (counts[s] ?? 0) > 0 && (
          <div key={s} className={SEV_BG[s]} style={{ width: `${((counts[s] ?? 0) / total) * 100}%`, minWidth: 6 }} />
        ))}
      </div>
      <dl className="mt-3 grid grid-cols-4 gap-2">
        {SEVERITIES.map((s) => (
          <Link key={s} href={`/alerts?severity=${s}`} className="group rounded-md px-1 py-1 hover:bg-surface-2">
            <dt className="flex items-center gap-1.5 text-[13px] text-ink-2">
              <span aria-hidden className={`h-3 w-1.5 rounded-[2px] ${SEV_BG[s]}`} />{SEVERITY_LABEL[s]}
            </dt>
            <dd className="mt-0.5 text-[22px] font-semibold tabular-nums group-hover:text-accent">{num(counts[s] ?? 0)}</dd>
          </Link>
        ))}
      </dl>
    </div>
  );
}

/** 에이전트 CPU 사용률 분포 — "기존 보안 솔루션과 충돌 없이 가볍게 도는가"를 전 PC 에 대해 보여준다. */
export function CpuHistogram({ counts = [] }: { counts?: number[] }) {
  const labels = ["0.25% 미만", "0.25~0.5%", "0.5~1%", "1~2%", "2% 이상"];
  const max = Math.max(1, ...counts);
  return (
    <div className="space-y-1.5" role="table" aria-label="에이전트 CPU 사용률 분포">
      {labels.map((l, i) => (
        <div key={l} role="row" className="grid grid-cols-[6.5rem_1fr_2.5rem] items-center gap-3 text-[13px]">
          <span role="rowheader" className="text-ink-2">{l}</span>
          <span role="cell" className="relative h-4 rounded-sm bg-surface-2" title={`${counts[i] ?? 0}대`}>
            <span className={`absolute inset-y-0 left-0 rounded-sm ${i >= 4 ? "bg-warn" : "bg-accent"}`} style={{ width: `${((counts[i] ?? 0) / max) * 100}%`, minWidth: counts[i] ? 4 : 0 }} />
          </span>
          <span role="cell" className="text-right tabular-nums">{counts[i] ?? 0}대</span>
        </div>
      ))}
    </div>
  );
}
