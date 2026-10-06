"use client";

import Link from "next/link";
import { useMemo, useRef, useState } from "react";
import type { Severity } from "@/lib/data/types";
import { SEVERITIES } from "@/lib/data/types";
import { SEVERITY_LABEL, hour, stamp } from "@/lib/format";

export interface LanePoint {
  id: number;
  created_at: string;
  severity: Severity;
  title: string;
  hostname: string | null;
}

const ROW = 34;
const LEFT = 64;
const W = 1000;
const FILL: Record<Severity, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)",
};

/**
 * 관제 레인: 지난 N시간의 경보를 심각도별 줄에 시간순 점으로 찍는다.
 * 같은 시각에 몰린 경보(공격 연쇄)가 한눈에 보이게 하는 것이 목적.
 */
export function Swimlane({ points, now, hours = 24 }: { points: LanePoint[]; now: number; hours?: number }) {
  const [hover, setHover] = useState<{ p: LanePoint; x: number; y: number } | null>(null);
  const wrap = useRef<HTMLDivElement>(null);
  const start = now - hours * 3_600_000;
  const H = ROW * SEVERITIES.length + 28;
  const x = (iso: string) => LEFT + ((Date.parse(iso) - start) / (now - start)) * (W - LEFT - 12);

  const ticks = useMemo(() => {
    const out: string[] = [];
    const t = new Date(start);
    t.setMinutes(0, 0, 0);
    const step = hours <= 24 ? 3 : 12;
    for (let ms = t.getTime() + 3_600_000; ms < now; ms += 3_600_000) {
      const d = new Date(ms);
      if (d.getHours() % step === 0 && now - ms > 90 * 60_000) out.push(d.toISOString());
    }
    return out;
  }, [start, now, hours]);

  const visible = points.filter((p) => Date.parse(p.created_at) >= start);

  return (
    <div className="overflow-x-auto">
    <div ref={wrap} className="relative min-w-[720px]">
      <svg viewBox={`0 0 ${W} ${H}`} className="block w-full" role="img" aria-label={`지난 ${hours}시간 경보 ${visible.length}건의 시간 분포`}>
        {SEVERITIES.map((s, i) => (
          <g key={s}>
            <line x1={LEFT} x2={W - 4} y1={i * ROW + ROW / 2} y2={i * ROW + ROW / 2} stroke="var(--chart-grid)" strokeWidth={1} />
            <text x={0} y={i * ROW + ROW / 2 + 4} fontSize={12} fill="var(--ink-2)">{SEVERITY_LABEL[s]}</text>
          </g>
        ))}
        {ticks.map((t) => (
          <g key={t}>
            <line x1={x(t)} x2={x(t)} y1={0} y2={ROW * 4} stroke="var(--chart-grid)" strokeDasharray="2 4" />
            <text x={x(t)} y={H - 8} fontSize={11} fill="var(--muted)" textAnchor="middle">{hour(t)}</text>
          </g>
        ))}
        <line x1={W - 12} x2={W - 12} y1={0} y2={ROW * 4} stroke="var(--accent)" strokeWidth={1.5} />
        <text x={W - 12} y={H - 8} fontSize={11} fill="var(--accent)" textAnchor="end">지금</text>
        {visible.map((p) => {
          const cx = x(p.created_at);
          const cy = SEVERITIES.indexOf(p.severity) * ROW + ROW / 2;
          const on = hover?.p.id === p.id;
          return (
            <Link key={p.id} href={`/alerts?id=${p.id}&status=all`} aria-label={`${SEVERITY_LABEL[p.severity]} ${p.title}`}>
              <circle cx={cx} cy={cy} r={12} fill="transparent"
                onMouseEnter={() => setHover({ p, x: cx, y: cy })} onMouseLeave={() => setHover(null)}
                onFocus={() => setHover({ p, x: cx, y: cy })} onBlur={() => setHover(null)} />
              <circle cx={cx} cy={cy} r={on ? 7 : 5.5} fill={FILL[p.severity]} stroke="var(--surface)" strokeWidth={2} pointerEvents="none" />
            </Link>
          );
        })}
      </svg>
      {hover && (
        <div
          className="pointer-events-none absolute z-10 w-64 -translate-x-1/2 -translate-y-full rounded-md border border-line bg-surface px-3 py-2 text-[13px] shadow-lg"
          style={{ left: `${(hover.x / W) * 100}%`, top: `calc(${(hover.y / H) * 100}% - 10px)` }}
        >
          <div className="text-xs text-muted">{stamp(hover.p.created_at)} · {hover.p.hostname ?? "장치 미상"}</div>
          <div className="mt-0.5 font-medium leading-snug">{hover.p.title}</div>
        </div>
      )}
    </div>
    </div>
  );
}
