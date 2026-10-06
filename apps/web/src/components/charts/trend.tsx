"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Severity, TrendPoint } from "@/lib/data/types";
import { SEVERITY_LABEL, day, hour, num } from "@/lib/format";

const ORDER: Severity[] = ["low", "medium", "high", "critical"]; // 아래에서 위로 쌓는 순서
const FILL: Record<Severity, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)",
};

type Row = { bucket: string; total: number } & Partial<Record<Severity, number>>;

function pivot(points: TrendPoint[], days: number): Row[] {
  const map = new Map<string, Row>();
  // 비어 있는 날도 0 으로 채워 축이 끊기지 않게
  const today = new Date(); today.setHours(0, 0, 0, 0);
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86_400_000).toISOString();
    map.set(d.slice(0, 10), { bucket: d, total: 0 });
  }
  points.forEach((p) => {
    const k = new Date(p.bucket); k.setHours(0, 0, 0, 0);
    const key = k.toISOString().slice(0, 10);
    const row = map.get(key);
    if (!row) return; // 표시 범위 밖
    row[p.severity] = (row[p.severity] ?? 0) + Number(p.n);
    row.total += Number(p.n);
    map.set(key, row);
  });
  return [...map.values()];
}

function TrendTip({ active, payload }: { active?: boolean; payload?: { payload: Row }[] }) {
  if (!active || !payload?.[0]) return null;
  const r = payload[0].payload;
  return (
    <div className="rounded-md border border-line bg-surface px-3 py-2 text-[13px] shadow-lg">
      <div className="mb-1 font-medium">{day(r.bucket)} 경보 {num(r.total)}건</div>
      {[...ORDER].reverse().map((s) => (
        <div key={s} className="flex items-center justify-between gap-6 tabular-nums">
          <span className="inline-flex items-center gap-1.5 text-ink-2">
            <span className="h-2.5 w-1.5 rounded-sm" style={{ background: FILL[s] }} />{SEVERITY_LABEL[s]}
          </span>
          <span>{num(r[s] ?? 0)}</span>
        </div>
      ))}
    </div>
  );
}

export function AlertTrend({ points, days }: { points: TrendPoint[]; days: number }) {
  const data = pivot(points, days);
  return (
    <div>
      <ul className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-[13px] text-ink-2" aria-label="범례">
        {[...ORDER].reverse().map((s) => (
          <li key={s} className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-1.5 rounded-sm" style={{ background: FILL[s] }} aria-hidden />{SEVERITY_LABEL[s]}
          </li>
        ))}
      </ul>
      <div className="h-52">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: 0 }} barCategoryGap="22%">
            <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
            <XAxis dataKey="bucket" tickFormatter={(v: string) => day(v)} tick={{ fontSize: 11, fill: "var(--muted)" }} tickLine={false} axisLine={{ stroke: "var(--line)" }} interval="preserveStartEnd" minTickGap={18} />
            <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "var(--muted)" }} tickLine={false} axisLine={false} width={36} />
            <Tooltip content={<TrendTip />} cursor={{ fill: "var(--surface-3)", opacity: 0.6 }} />
            {ORDER.map((s, i) => (
              <Bar key={s} dataKey={s} stackId="a" fill={FILL[s]} stroke="var(--surface)" strokeWidth={1}
                radius={i === ORDER.length - 1 ? [3, 3, 0, 0] : 0} isAnimationActive={false} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function LogonTip({ active, payload }: { active?: boolean; payload?: { payload: { bucket: string; n: number } }[] }) {
  if (!active || !payload?.[0]) return null;
  const r = payload[0].payload;
  return (
    <div className="rounded-md border border-line bg-surface px-3 py-2 text-[13px] shadow-lg tabular-nums">
      {hour(r.bucket)}대 로그온 실패 <strong>{num(Number(r.n))}</strong>회
    </div>
  );
}

export function LogonFailures({ points }: { points: { bucket: string; n: number }[] }) {
  const data = points.map((p) => ({ ...p, n: Number(p.n) }));
  return (
    <div className="h-44">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: 0 }} barCategoryGap="18%">
          <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
          <XAxis dataKey="bucket" tickFormatter={(v: string) => hour(v)} tick={{ fontSize: 11, fill: "var(--muted)" }} tickLine={false} axisLine={{ stroke: "var(--line)" }} interval="preserveStartEnd" minTickGap={24} />
          <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "var(--muted)" }} tickLine={false} axisLine={false} width={36} />
          <Tooltip content={<LogonTip />} cursor={{ fill: "var(--surface-3)", opacity: 0.6 }} />
          <Bar dataKey="n" fill="var(--accent)" radius={[3, 3, 0, 0]} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
