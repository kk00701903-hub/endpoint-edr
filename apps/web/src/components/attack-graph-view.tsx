"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import { Cog, Globe, KeyRound, Maximize2, Minus, Monitor, Pin, Plus, Radio } from "lucide-react";
import { cn } from "@/lib/cn";
import type { AttackGraph, GraphNode, NodeKind } from "@/lib/attack-graph";
import type { Severity } from "@/lib/data/types";
import { SEVERITY_LABEL } from "@/lib/format";
import { Mono } from "./ui";

const COL_W = 214, NODE_W = 160, NODE_H = 50, ROW_H = 70, PAD_X = 16, PAD_Y = 34;
const ICON: Record<NodeKind, typeof Globe> = { ip: Globe, user: KeyRound, device: Monitor, process: Cog, persistence: Pin, remote: Radio };
const KIND_LABEL: Record<NodeKind, string> = { ip: "출발지 IP", user: "계정", device: "장치", process: "프로세스", persistence: "남긴 흔적", remote: "외부 통신" };
const SEV_STROKE: Record<Severity, string> = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)" };

/**
 * 공격 그래프 — 왼쪽(들어온 곳)에서 오른쪽(남긴 것)으로 흐른다.
 * 경보와 연결된 노드는 심각도 색 테두리, 공격 경로의 선은 진하게. 노드를 누르면 오른쪽에 상세.
 */
export function AttackGraphView({ graph }: { graph: AttackGraph }) {
  const firstHot = graph.nodes.find((n) => n.kind === "process" && n.severity) ?? graph.nodes.find((n) => n.severity) ?? graph.nodes[0];
  const [sel, setSel] = useState<string | null>(firstHot?.id ?? null);
  const [hover, setHover] = useState<string | null>(null);
  const [zoom, setZoom] = useState<number | null>(null); // null = 화면에 맞춤(단, 너무 작아지지 않게)
  const [boxW, setBoxW] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!box.current) return;
    const ro = new ResizeObserver(([e]) => setBoxW(e!.contentRect.width));
    ro.observe(box.current);
    return () => ro.disconnect();
  }, []);
  const pos = useMemo(() => {
    // 각 열은 세로 가운데 정렬
    const perLayer = new Map<number, GraphNode[]>();
    graph.nodes.forEach((n) => perLayer.set(n.layer, [...(perLayer.get(n.layer) ?? []), n]));
    const height = Math.max(...[...perLayer.values()].map((l) => l.length)) * ROW_H;
    const m = new Map<string, { x: number; y: number }>();
    perLayer.forEach((list, layer) => {
      const offset = (height - list.length * ROW_H) / 2;
      list.sort((a, b) => a.row - b.row).forEach((n, i) => m.set(n.id, { x: PAD_X + layer * COL_W, y: PAD_Y + offset + i * ROW_H }));
    });
    return { m, height };
  }, [graph]);

  if (graph.nodes.length === 0) {
    return <p className="px-4 py-10 text-center text-[13px] text-ink-2">그래프로 그릴 관계가 없습니다. 경보에 IP·계정·파일 정보가 없거나, 장치의 프로세스 정보가 아직 수집되지 않았습니다.</p>;
  }

  const W = PAD_X * 2 + (graph.layers - 1) * COL_W + NODE_W;
  const H = PAD_Y + pos.height + 8;
  const fit = boxW ? Math.min(1.2, boxW / W) : 1;
  const scale = zoom ?? Math.max(0.8, fit);
  // 마우스를 올렸을 때만 주변을 흐리게 한다(선택만으로는 흐리지 않음)
  const focus = hover;
  const neighbors = new Set<string>(focus ? [focus] : []);
  graph.edges.forEach((e) => { if (e.from === focus) neighbors.add(e.to); if (e.to === focus) neighbors.add(e.from); });
  const selected = graph.nodes.find((n) => n.id === sel) ?? null;
  const layerKinds = new Map<number, NodeKind>();
  graph.nodes.forEach((n) => { if (!layerKinds.has(n.layer)) layerKinds.set(n.layer, n.kind); });

  return (
    <div className="grid 2xl:grid-cols-[minmax(0,1fr)_19rem]">
      <div ref={box} className="relative overflow-x-auto border-line 2xl:border-r">
        <div className="sticky left-0 z-10 flex justify-end gap-1 p-2">
          <div className="flex items-center gap-0.5 rounded-md border border-line bg-surface p-0.5 shadow-sm">
            <button className="rounded p-1 text-ink-2 hover:bg-surface-3" aria-label="축소" onClick={() => setZoom(Math.max(0.4, +(scale - 0.15).toFixed(2)))}><Minus className="size-3.5" /></button>
            <span className="w-10 text-center text-xs tabular-nums text-ink-2">{Math.round(scale * 100)}%</span>
            <button className="rounded p-1 text-ink-2 hover:bg-surface-3" aria-label="확대" onClick={() => setZoom(Math.min(1.6, +(scale + 0.15).toFixed(2)))}><Plus className="size-3.5" /></button>
            <button className="rounded p-1 text-ink-2 hover:bg-surface-3" aria-label="화면에 맞춤" title="화면에 맞춤" onClick={() => setZoom(fit)}><Maximize2 className="size-3.5" /></button>
          </div>
        </div>
        <svg width={W * scale} height={H * scale} viewBox={`0 0 ${W} ${H}`} className="-mt-8 block" role="img" aria-label={`공격 그래프: 노드 ${graph.nodes.length}개, 연결 ${graph.edges.length}개`}>
          <defs>
            <marker id="arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L8,4 L0,8 z" fill="var(--line-strong)" />
            </marker>
            <marker id="arrow-hot" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L8,4 L0,8 z" fill="var(--sev-high)" />
            </marker>
          </defs>
          {[...layerKinds].map(([layer, kind]) => (
            <text key={layer} x={PAD_X + layer * COL_W} y={16} fontSize={11.5} fill="var(--muted)">{KIND_LABEL[kind]}</text>
          ))}
          {graph.edges.map((e) => {
            const a = pos.m.get(e.from), b = pos.m.get(e.to);
            if (!a || !b) return null;
            const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x - 4, y2 = b.y + NODE_H / 2;
            const mx = (x1 + x2) / 2;
            const dim = focus && !(neighbors.has(e.from) && neighbors.has(e.to));
            return (
              <g key={e.from + e.to} opacity={dim ? 0.25 : 1}>
                <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none"
                  stroke={e.hot ? "var(--sev-high)" : "var(--line-strong)"} strokeWidth={e.hot ? 1.75 : 1.25} markerEnd={e.hot ? "url(#arrow-hot)" : "url(#arrow)"} />
                {(e.from === (hover ?? sel) || e.to === (hover ?? sel)) && (
                  <text x={mx} y={(y1 + y2) / 2 - 6} fontSize={11} fill="var(--ink)" textAnchor="middle" paintOrder="stroke" stroke="var(--surface)" strokeWidth={4}>{e.label}</text>
                )}
              </g>
            );
          })}
          {graph.nodes.map((n) => {
            const p = pos.m.get(n.id)!;
            const Icon = ICON[n.kind];
            const dim = focus && !neighbors.has(n.id);
            const on = sel === n.id;
            return (
              <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={dim ? 0.35 : 1} className="cursor-pointer"
                onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)} onClick={() => setSel(n.id)}
                role="button" tabIndex={0} aria-label={`${KIND_LABEL[n.kind]} ${n.label}`} aria-pressed={on}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSel(n.id); } }}>
                <rect width={NODE_W} height={NODE_H} rx={7} fill={n.severity ? "var(--sev-critical-wash)" : "var(--surface-2)"}
                  stroke={on ? "var(--accent)" : n.severity ? SEV_STROKE[n.severity] : "var(--line-strong)"} strokeWidth={on ? 2 : n.severity ? 1.5 : 1} />
                <foreignObject x={10} y={8} width={NODE_W - 20} height={NODE_H - 12}>
                  <div className="flex items-start gap-2 text-left">
                    <Icon className="mt-0.5 size-4 shrink-0 text-ink-2" strokeWidth={1.75} aria-hidden />
                    <div className="min-w-0 leading-tight">
                      <div className={cn("truncate text-[12.5px] font-medium", (n.kind === "ip" || n.kind === "remote") && "font-mono text-[12px]")}>{n.label}</div>
                      <div className="truncate text-[11px] text-muted">{n.sub ?? KIND_LABEL[n.kind]}</div>
                    </div>
                  </div>
                </foreignObject>
              </g>
            );
          })}
        </svg>
      </div>
      <aside className="border-t border-line p-4 2xl:border-t-0" aria-label="노드 상세">
        {selected ? (
          <>
            <div className="text-xs text-muted">{KIND_LABEL[selected.kind]}</div>
            <div className={cn("mt-0.5 font-semibold break-all", (selected.kind === "ip" || selected.kind === "remote") && "font-mono")}>{selected.label}</div>
            {selected.severity && <div className="mt-1 text-[13px] text-sev-high">경보 {selected.alertIds.length}건 연결 · {SEVERITY_LABEL[selected.severity]}</div>}
            <dl className="mt-3 grid gap-x-6 gap-y-2 text-[13px] sm:grid-cols-2 2xl:grid-cols-1">
              {Object.entries(selected.detail).filter(([, v]) => v != null && v !== "").map(([k, v]) => (
                <div key={k}><dt className="text-xs text-muted">{k}</dt><dd><Mono className="break-mono">{String(v)}</Mono></dd></div>
              ))}
            </dl>
            {selected.href && <Link href={selected.href} className="mt-4 inline-block text-[13px] text-accent hover:underline">{selected.kind === "device" ? "장치 화면 열기" : "프로필 열기"}</Link>}
          </>
        ) : <p className="text-[13px] text-ink-2">노드를 누르면 상세가 여기에 나옵니다.</p>}
        <ul className="mt-6 space-y-1 border-t border-line pt-3 text-xs text-ink-2">
          <li className="flex items-center gap-2"><span className="h-0.5 w-5 bg-sev-high" />공격 경로(경보와 연결)</li>
          <li className="flex items-center gap-2"><span className="h-0.5 w-5 bg-line-strong" />관련 관계</li>
          <li className="flex items-center gap-2"><span className="size-3 rounded-[3px] border border-sev-high bg-sev-critical-wash" />경보가 붙은 대상</li>
        </ul>
      </aside>
    </div>
  );
}
