"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Copy, Search } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/cn";
import type { ProcessRow } from "@/lib/data/types";
import { ago, stamp } from "@/lib/format";
import { Field, Mono, Verdict } from "./ui";

interface Node extends ProcessRow { children: Node[]; depth: number }

function build(rows: ProcessRow[]): Node[] {
  const byPid = new Map<number, Node>();
  rows.forEach((r) => byPid.set(r.pid, { ...r, children: [], depth: 0 }));
  const roots: Node[] = [];
  byPid.forEach((n) => {
    const parent = n.ppid != null ? byPid.get(n.ppid) : undefined;
    // 부모가 자기보다 늦게 시작했다면 PID 가 재사용된 것 → 부모 관계로 보지 않는다
    if (parent && parent !== n && parent.create_time <= n.create_time) parent.children.push(n);
    else roots.push(n);
  });
  const sortRec = (ns: Node[], depth: number) => {
    ns.sort((a, b) => a.create_time.localeCompare(b.create_time) || a.pid - b.pid);
    ns.forEach((n) => { n.depth = depth; sortRec(n.children, depth + 1); });
  };
  sortRec(roots, 0);
  return roots;
}

const SUSPICIOUS_PATH = /\\(appdata\\local\\temp|temp|users\\public|programdata)\\[^\\]+\.(exe|dll|ps1|bat|vbs)$/i;
const ENCODED = /\s-(e|en|enc|encodedcommand)\s/i;

function flags(p: ProcessRow): string[] {
  const out: string[] = [];
  if (p.path && SUSPICIOUS_PATH.test(p.path)) out.push("임시·공용 경로에서 실행");
  if (p.command_line && ENCODED.test(` ${p.command_line} `) && /powershell|pwsh/i.test(p.name)) out.push("인코딩된 PowerShell 명령");
  if (/-w(indowstyle)?\s+hidden/i.test(p.command_line ?? "")) out.push("숨김 창 실행");
  return out;
}

/** Process Explorer 처럼 부모-자식 트리로 보여주고, 고른 프로세스의 상세를 옆에 띄운다. */
export function ProcessTree({ rows }: { rows: ProcessRow[] }) {
  const [q, setQ] = useState("");
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const roots = useMemo(() => build(rows), [rows]);
  const firstHit = useMemo(() => rows.find((r) => r.verdict === "malicious" || flags(r).length) ?? null, [rows]);
  const [sel, setSel] = useState<number | null>(firstHit?.pid ?? null);
  const selected = rows.find((r) => r.pid === sel) ?? null;

  const term = q.trim().toLowerCase();
  const matches = (n: Node): boolean =>
    !term || n.name.toLowerCase().includes(term) || (n.command_line ?? "").toLowerCase().includes(term) || String(n.pid) === term || n.children.some(matches);

  const flat: Node[] = [];
  const walk = (ns: Node[]) => ns.forEach((n) => {
    if (!matches(n)) return;
    flat.push(n);
    if (!collapsed.has(n.pid) || term) walk(n.children);
  });
  walk(roots);

  const toggle = (pid: number) => setCollapsed((s) => { const c = new Set(s); if (c.has(pid)) c.delete(pid); else c.add(pid); return c; });
  const flagged = rows.filter((r) => r.verdict === "malicious" || r.verdict === "suspicious" || flags(r).length).length;

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
      <div className="overflow-hidden rounded-lg border border-line bg-surface">
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-3 py-2">
          <div className="flex h-7 min-w-52 flex-1 items-center gap-1.5 rounded-md border border-line-strong px-2">
            <Search className="size-3.5 text-muted" aria-hidden />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="이름·명령줄·PID" aria-label="프로세스 검색" className="w-full bg-transparent text-[13px] outline-none" />
          </div>
          <span className="text-[13px] text-ink-2">실행 중 {rows.length}개{flagged > 0 && <> — <strong className="text-sev-high">주의 {flagged}개</strong></>}</span>
          <button className="text-[13px] text-accent hover:underline" onClick={() => setCollapsed(new Set())}>모두 펼치기</button>
        </div>
        <div className="max-h-[64vh] overflow-auto" role="tree" aria-label="프로세스 트리">
          {flat.map((n) => {
            const f = flags(n);
            const bad = n.verdict === "malicious" || n.verdict === "suspicious" || f.length > 0;
            return (
              <div key={`${n.pid}-${n.create_time}`} role="treeitem" aria-selected={sel === n.pid} aria-expanded={n.children.length ? !collapsed.has(n.pid) : undefined}
                className={cn("grid grid-cols-[minmax(0,1fr)_4rem_6.5rem] items-center gap-2 border-b border-line/60 py-1 pr-3 text-[13px] hover:bg-surface-2",
                  sel === n.pid && "bg-accent-soft hover:bg-accent-soft", bad && "bg-sev-critical-wash")}>
                <div className="flex min-w-0 items-center" style={{ paddingLeft: 8 + n.depth * 16 }}>
                  {n.children.length ? (
                    <button onClick={() => toggle(n.pid)} className="mr-0.5 inline-flex size-5 items-center justify-center rounded text-muted hover:bg-surface-3" aria-label={collapsed.has(n.pid) ? "펼치기" : "접기"}>
                      {collapsed.has(n.pid) ? <ChevronRight className="size-3.5" /> : <ChevronDown className="size-3.5" />}
                    </button>
                  ) : <span className="mr-0.5 inline-block size-5" />}
                  <button onClick={() => setSel(n.pid)} className="flex min-w-0 items-center gap-2 text-left">
                    <span className={cn("truncate", bad ? "font-semibold text-sev-high" : "text-ink")}>{n.name}</span>
                    <Verdict verdict={n.verdict} />
                    {collapsed.has(n.pid) && <span className="text-xs text-muted">+{n.children.length}</span>}
                  </button>
                </div>
                <span className="text-right font-mono text-[12px] text-ink-2 tabular-nums">{n.pid}</span>
                <span className="truncate text-right text-xs text-muted">{n.username?.split("\\").at(-1) ?? ""}</span>
              </div>
            );
          })}
          {flat.length === 0 && <p className="px-4 py-8 text-center text-[13px] text-ink-2">‘{q}’ 와 일치하는 프로세스가 없습니다.</p>}
        </div>
      </div>

      <aside className="rounded-lg border border-line bg-surface p-4 xl:sticky xl:top-20 xl:self-start" aria-label="프로세스 상세">
        {selected ? (
          <>
            <div className="flex items-center gap-2">
              <h3 className="text-[16px] font-semibold">{selected.name}</h3>
              <Verdict verdict={selected.verdict} />
            </div>
            {flags(selected).length > 0 && (
              <ul className="mt-2 space-y-1">
                {flags(selected).map((f) => <li key={f} className="rounded bg-sev-critical-wash px-2 py-1 text-[13px] text-sev-high">{f}</li>)}
              </ul>
            )}
            <dl className="mt-3 divide-y divide-line">
              <Field label="PID / 부모">{selected.pid} / {selected.ppid ?? "—"}{selected.ppid != null && rows.find((r) => r.pid === selected.ppid) && <span className="ml-1 text-muted">({rows.find((r) => r.pid === selected.ppid)!.name})</span>}</Field>
              <Field label="시작" suppressHydration>{selected.create_time.startsWith("-") ? "알 수 없음(보호 프로세스)" : `${stamp(selected.create_time)} (${ago(selected.create_time)})`}</Field>
              <Field label="사용자">{selected.username ?? "—"}</Field>
              <Field label="경로">{selected.path ? <Mono className="break-mono">{selected.path}</Mono> : <span className="text-muted">읽을 수 없음</span>}</Field>
              <Field label="명령줄">{selected.command_line ? <Mono className="break-mono">{selected.command_line}</Mono> : "—"}</Field>
              <Field label="SHA-256">
                {selected.sha256 ? (
                  <span className="flex flex-col gap-1">
                    <Mono className="break-mono">{selected.sha256}</Mono>
                    <span className="flex gap-3 text-xs">
                      <button className="inline-flex items-center gap-1 text-accent hover:underline" onClick={() => { navigator.clipboard.writeText(selected.sha256!); toast.success("해시를 복사했습니다"); }}><Copy className="size-3" aria-hidden />복사</button>
                      <Link href={`/hunt?q=${selected.sha256}`} className="text-accent hover:underline">이 파일이 있는 다른 PC 찾기</Link>
                    </span>
                  </span>
                ) : "—"}
              </Field>
            </dl>
          </>
        ) : (
          <p className="py-8 text-center text-[13px] text-ink-2">트리에서 프로세스를 고르면 경로·명령줄·해시를 여기에서 봅니다.</p>
        )}
      </aside>
    </div>
  );
}
