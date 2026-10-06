"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState, useTransition } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Check, ChevronLeft, ChevronRight, ExternalLink, Search, ShieldOff, UserCheck, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { addComment, createSuppression, triageAlerts, type ActionResult } from "@/lib/actions";
import type { Alert, AlertFilter, Page, Resolution, Severity } from "@/lib/data/types";
import { SEVERITIES } from "@/lib/data/types";
import { SEVERITY_LABEL, ago, num, stamp } from "@/lib/format";
import { useActionToast } from "./shell";
import { Button, Empty, Kbd, LivenessTag, Mono, SEV_BG, SeverityTag, StatusTag } from "./ui";
import { liveness } from "@/lib/format";

// 서버에서 내려오는 상세(타입은 data/source.ts 의 AlertDetail 과 같다)
interface Detail {
  alert: Alert;
  comments: { id: number; author_email?: string; author_id: string; body: string; created_at: string }[];
  rule: { rule_id: string; title: string; description: string; mitre_tactic: string; mitre_technique: string; technique_name: string } | null;
  device: { id: string; hostname: string; last_ip: string | null; os_version: string | null; last_seen_at: string | null } | null;
}

export function AlertWorkbench({ page, filter, selectedId, detail, rules, canTriage, me }: {
  page: Page<Alert>; filter: AlertFilter; selectedId: number | null; detail: Detail | null;
  rules: { rule_id: string; title: string }[]; canTriage: boolean; me: string;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const sp = useSearchParams();
  const [checked, setChecked] = useState<Set<number>>(new Set());
  const [pending, start] = useTransition();
  const notify = useActionToast();
  const listRef = useRef<HTMLUListElement>(null);

  const href = useCallback((patch: Record<string, string | null>) => {
    const p = new URLSearchParams(sp.toString());
    Object.entries(patch).forEach(([k, v]) => (v == null || v === "" ? p.delete(k) : p.set(k, v)));
    return `${pathname}?${p.toString()}`;
  }, [sp, pathname]);

  const select = useCallback((id: number) => router.replace(href({ id: String(id) }), { scroll: false }), [router, href]);

  const run = (fn: () => Promise<ActionResult>, after?: () => void) =>
    start(async () => {
      const r = await fn();
      notify(r);
      if (r.ok) { after?.(); router.refresh(); }
    });

  const targets = useMemo(() => (checked.size ? [...checked] : selectedId ? [selectedId] : []), [checked, selectedId]);

  // 키보드: J/K·화살표 이동, X 선택, A 조사 시작, Esc 선택 해제
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t.closest("input, textarea, select, [role=dialog]") || e.metaKey || e.ctrlKey || e.altKey) return;
      const rows = page.rows;
      const i = rows.findIndex((r) => r.id === selectedId);
      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        const n = rows[Math.min(rows.length - 1, i + 1)];
        if (n) select(n.id);
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        const n = rows[Math.max(0, i - 1)];
        if (n) select(n.id);
      } else if (e.key === "x" && selectedId) {
        setChecked((s) => { const c = new Set(s); if (c.has(selectedId)) c.delete(selectedId); else c.add(selectedId); return c; });
      } else if (e.key === "a" && canTriage && targets.length) {
        run(() => triageAlerts({ ids: targets, status: "acknowledged", assignToMe: true }), () => setChecked(new Set()));
      } else if (e.key === "Escape") {
        setChecked(new Set());
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-id="${selectedId}"]`)?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  const sevSet = new Set(filter.severity ?? []);
  const toggleSev = (s: Severity) => {
    const n = new Set(sevSet);
    if (n.has(s)) n.delete(s); else n.add(s);
    return href({ severity: [...n].join(",") || null, page: null });
  };
  const pages = Math.max(1, Math.ceil(page.total / page.pageSize));
  const allChecked = page.rows.length > 0 && page.rows.every((r) => checked.has(r.id));

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
      {/* ---------------- 목록 ---------------- */}
      <section className="flex min-h-[70vh] flex-col overflow-hidden rounded-lg border border-line bg-surface xl:h-[calc(100dvh-11.5rem)] xl:min-h-[32rem]" aria-label="경보 목록">
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2.5">
          <div className="flex gap-1" role="group" aria-label="심각도">
            {SEVERITIES.map((s) => (
              <Link key={s} href={toggleSev(s)} scroll={false} aria-pressed={sevSet.has(s)}
                className={cn("inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-[13px]",
                  sevSet.has(s) ? "border-accent bg-accent-soft text-accent font-medium" : "border-line-strong text-ink-2 hover:text-ink")}>
                <span aria-hidden className={cn("h-3 w-1.5 rounded-[2px]", SEV_BG[s])} />{SEVERITY_LABEL[s]}
              </Link>
            ))}
          </div>
          <select aria-label="처리 상태" value={filter.status ?? "active"} onChange={(e) => router.replace(href({ status: e.target.value, page: null }), { scroll: false })}
            className="h-7 rounded-md border border-line-strong bg-surface px-2 text-[13px]">
            <option value="active">미처리 전체</option>
            <option value="open">새 경보</option>
            <option value="acknowledged">조사 중</option>
            <option value="closed">종결</option>
            <option value="all">모든 상태</option>
          </select>
          <select aria-label="탐지 규칙" value={filter.rule ?? ""} onChange={(e) => router.replace(href({ rule: e.target.value || null, page: null }), { scroll: false })}
            className="h-7 max-w-44 rounded-md border border-line-strong bg-surface px-2 text-[13px]">
            <option value="">모든 규칙</option>
            {rules.map((r) => <option key={r.rule_id} value={r.rule_id}>{r.title}</option>)}
          </select>
          <select aria-label="출처" value={filter.source ?? ""} onChange={(e) => router.replace(href({ source: e.target.value || null, page: null }), { scroll: false })}
            className="h-7 rounded-md border border-line-strong bg-surface px-2 text-[13px]">
            <option value="">모든 출처</option>
            <option value="edr">내장 탐지</option>
            <option value="wazuh">Wazuh</option>
          </select>
          <select aria-label="기간" value={String(filter.days ?? 30)} onChange={(e) => router.replace(href({ days: e.target.value, page: null }), { scroll: false })}
            className="h-7 rounded-md border border-line-strong bg-surface px-2 text-[13px]">
            <option value="1">24시간</option>
            <option value="7">7일</option>
            <option value="30">30일</option>
            <option value="90">90일</option>
          </select>
          <form className="ml-auto flex min-w-40 flex-1 items-center gap-1.5 rounded-md border border-line-strong px-2 sm:max-w-56"
            onSubmit={(e) => { e.preventDefault(); const q = new FormData(e.currentTarget).get("q") as string; router.replace(href({ q, page: null }), { scroll: false }); }}>
            <Search className="size-3.5 text-muted" aria-hidden />
            <input name="q" defaultValue={filter.q ?? ""} placeholder="제목·장치 검색" aria-label="경보 검색" className="h-7 w-full bg-transparent text-[13px] outline-none" />
          </form>
        </div>

        {checked.size > 0 && canTriage && (
          <BulkBar count={checked.size} pending={pending} onClear={() => setChecked(new Set())}
            onAck={() => run(() => triageAlerts({ ids: [...checked], status: "acknowledged", assignToMe: true }), () => setChecked(new Set()))}
            onClose={(res) => run(() => triageAlerts({ ids: [...checked], status: "closed", resolution: res }), () => setChecked(new Set()))} />
        )}

        <div className="flex items-center gap-3 border-b border-line bg-surface-2 px-3 py-1.5 text-xs text-muted">
          <input type="checkbox" aria-label="이 페이지 모두 선택" checked={allChecked} disabled={!canTriage}
            onChange={() => setChecked(allChecked ? new Set() : new Set(page.rows.map((r) => r.id)))} className="size-3.5 accent-[var(--accent)]" />
          <span>{num(page.total)}건 중 {num((page.page - 1) * page.pageSize + (page.rows.length ? 1 : 0))}–{num((page.page - 1) * page.pageSize + page.rows.length)}</span>
        </div>

        {page.rows.length === 0 ? (
          <Empty title="조건에 맞는 경보가 없습니다" action={<Link className="text-accent hover:underline" href={pathname}>필터 초기화</Link>}>
            심각도·상태·기간 조건을 넓혀 보세요.
          </Empty>
        ) : (
          <ul ref={listRef} className="flex-1 divide-y divide-line overflow-y-auto">
            {page.rows.map((a) => {
              const on = a.id === selectedId;
              return (
                <li key={a.id} data-id={a.id} className={cn("relative", a.severity === "critical" && a.status !== "closed" && "bg-sev-critical-wash", on && "bg-accent-soft!")}>
                  <span aria-hidden className={cn("absolute inset-y-0 left-0 w-[3px]", SEV_BG[a.severity], a.status === "closed" && "opacity-30")} />
                  <div className="grid grid-cols-[1.25rem_4.25rem_minmax(0,1fr)_auto] items-center gap-2 py-2.5 pr-3 pl-3">
                    <input type="checkbox" aria-label={`${a.title} 선택`} disabled={!canTriage} checked={checked.has(a.id)}
                      onChange={() => setChecked((s) => { const c = new Set(s); if (c.has(a.id)) c.delete(a.id); else c.add(a.id); return c; })}
                      className="size-3.5 accent-[var(--accent)]" />
                    <SeverityTag severity={a.severity} />
                    <button onClick={() => select(a.id)} className="min-w-0 text-left" aria-current={on ? "true" : undefined}>
                      <span className={cn("block truncate font-medium", a.status === "closed" && "text-ink-2 font-normal")}>{a.title}</span>
                      <span className="block truncate text-[13px] text-ink-2">{a.hostname ?? "장치 미상"} <span className="text-muted">{a.rule_id}</span>
                        {a.source === "wazuh" && <span className="ml-1 rounded border border-line-strong px-1 text-[11px] text-ink-2 align-middle">Wazuh</span>}
                      </span>
                    </button>
                    <span className="flex flex-col items-end gap-1">
                      <span className="text-xs whitespace-nowrap text-muted" title={stamp(a.created_at)} suppressHydrationWarning>{ago(a.created_at)}</span>
                      <StatusTag status={a.status} resolution={a.resolution} />
                    </span>
                  </div>
                </li>
              );
            })}
          </ul>
        )}

        <div className="flex items-center justify-between border-t border-line px-3 py-2 text-[13px] text-ink-2">
          <span className="hidden gap-3 sm:flex">
            <span><Kbd>J</Kbd> <Kbd>K</Kbd> 이동</span><span><Kbd>X</Kbd> 선택</span>{canTriage && <span><Kbd>A</Kbd> 조사 시작</span>}
          </span>
          <span className="flex items-center gap-1">
            <Link aria-disabled={page.page <= 1} href={href({ page: String(page.page - 1) })} scroll={false}
              className={cn("inline-flex size-7 items-center justify-center rounded-md hover:bg-surface-3", page.page <= 1 && "pointer-events-none opacity-40")} aria-label="이전 페이지"><ChevronLeft className="size-4" /></Link>
            <span className="tabular-nums">{page.page} / {pages}</span>
            <Link aria-disabled={page.page >= pages} href={href({ page: String(page.page + 1) })} scroll={false}
              className={cn("inline-flex size-7 items-center justify-center rounded-md hover:bg-surface-3", page.page >= pages && "pointer-events-none opacity-40")} aria-label="다음 페이지"><ChevronRight className="size-4" /></Link>
          </span>
        </div>
      </section>

      {/* ---------------- 상세 ---------------- */}
      <section className="rounded-lg border border-line bg-surface xl:sticky xl:top-20 xl:max-h-[calc(100dvh-6.5rem)] xl:overflow-y-auto" aria-label="경보 상세">
        {detail ? (
          <AlertDetailPane key={detail.alert.id} d={detail} canTriage={canTriage} me={me} pending={pending} run={run} />
        ) : selectedId ? (
          <Empty title="이 경보를 찾을 수 없습니다">다른 조직의 경보이거나 삭제되었습니다.</Empty>
        ) : (
          <Empty title="왼쪽에서 경보를 고르세요">
            무슨 일이 있었는지, 어느 PC 인지, ATT&CK 기법과 처리 기록을 여기에서 봅니다.
          </Empty>
        )}
      </section>
    </div>
  );
}

function BulkBar({ count, pending, onClear, onAck, onClose }: { count: number; pending: boolean; onClear: () => void; onAck: () => void; onClose: (r: "true_positive" | "false_positive" | "benign") => void }) {
  const [res, setRes] = useState<"true_positive" | "false_positive" | "benign">("benign");
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-accent/30 bg-accent-soft px-3 py-2 text-[13px]">
      <strong className="text-accent">{count}건 선택</strong>
      <Button size="sm" onClick={onAck} disabled={pending}><UserCheck className="size-3.5" aria-hidden />조사 시작 · 나에게 지정</Button>
      <span className="inline-flex items-center gap-1">
        <select aria-label="종결 판정" value={res} onChange={(e) => setRes(e.target.value as typeof res)} className="h-7 rounded-md border border-line-strong bg-surface px-2">
          <option value="benign">정상 활동</option>
          <option value="false_positive">오탐</option>
          <option value="true_positive">실제 위협</option>
        </select>
        <Button size="sm" variant="primary" onClick={() => onClose(res)} disabled={pending}><Check className="size-3.5" aria-hidden />종결</Button>
      </span>
      <button onClick={onClear} className="ml-auto inline-flex items-center gap-1 text-ink-2 hover:text-ink"><X className="size-3.5" aria-hidden />선택 해제</button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 상세 패널
// ---------------------------------------------------------------------------
const LOGON_TYPE: Record<number, string> = { 2: "대화형(콘솔)", 3: "네트워크", 4: "배치", 5: "서비스", 7: "잠금 해제", 10: "원격 데스크톱", 11: "캐시된 자격 증명" };
const FIELD_LABEL: Record<string, string> = {
  src_ip: "출발지 IP", remote_ip: "원격 IP", remote_port: "원격 포트", failures: "실패 횟수", failures_before: "앞선 실패 횟수",
  users: "시도한 계정", user: "계정", logon_type: "로그온 유형", logon_types: "로그온 유형", window_minutes: "집계 구간(분)",
  sha256: "SHA-256", path: "파일 경로", image_path: "실행 파일", command: "명령", entry: "항목 이름", location: "위치",
  change: "변경 종류", event_id: "이벤트 ID", process: "프로세스", vt_malicious: "VirusTotal 탐지", event_time: "발생 시각",
};
const HUNTABLE = new Set(["src_ip", "remote_ip", "sha256", "entry"]);

function factValue(k: string, v: unknown, all: Record<string, unknown>): React.ReactNode {
  if (k === "vt_malicious") return `${v} / ${all.vt_total ?? "?"} 개 엔진이 악성으로 판정`;
  if (k === "logon_type") return LOGON_TYPE[Number(v)] ?? String(v);
  if (k === "logon_types" && Array.isArray(v)) return v.map((x) => LOGON_TYPE[Number(x)] ?? x).join(", ");
  if (k === "event_time" && typeof v === "string") return stamp(v);
  if (Array.isArray(v)) return v.join(", ");
  if (k === "change") return v === "added" ? "새로 추가" : v === "modified" ? "내용 변경" : String(v);
  const s = String(v);
  if (["src_ip", "remote_ip", "sha256", "path", "image_path", "command"].includes(k)) return <Mono className="break-mono">{s}</Mono>;
  return s;
}

function AlertDetailPane({ d, canTriage, me, pending, run }: { d: Detail; canTriage: boolean; me: string; pending: boolean; run: (fn: () => Promise<ActionResult>, after?: () => void) => void }) {
  const a = d.alert;
  const [resolution, setResolution] = useState<Exclude<Resolution, "suppressed">>("benign");
  const [comment, setComment] = useState("");
  const facts = Object.entries(a.details).filter(([k, v]) =>
    !["vt_total", "data", "suppression_id"].includes(k) && v != null && v !== "" && (typeof v !== "object" || Array.isArray(v)));
  const attackUrl = d.rule ? `https://attack.mitre.org/techniques/${d.rule.mitre_technique.replace(".", "/")}/` : null;

  return (
    <article>
      <header className="border-b border-line px-5 pt-4 pb-4">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityTag severity={a.severity} />
          <StatusTag status={a.status} resolution={a.resolution} />
          {a.source === "wazuh" && <span className="rounded border border-line-strong px-1.5 py-px text-xs text-ink-2" title="외부 오픈소스 EDR(Wazuh)에서 받은 경보">Wazuh</span>}
          {a.assigned_to && <span className="text-xs text-ink-2">{a.assigned_to === me ? "내가 담당" : "담당자 지정됨"}</span>}
        </div>
        <h2 className="mt-2 text-[18px] leading-snug font-semibold">{a.title}</h2>
        {a.incident_id && (
          <Link href={`/incidents/${a.incident_id}`} className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-accent/40 bg-accent-soft px-2 py-1 text-[12.5px] text-accent hover:underline">
            인시던트 INC-{a.incident_id} 에 포함 — 사건 흐름과 공격 그래프 보기
          </Link>
        )}
        <p className="mt-1 text-[13px] text-ink-2" suppressHydrationWarning>
          {stamp(a.created_at)} 발생 ({ago(a.created_at)}){d.device && <> — <Link href={`/devices/${d.device.id}`} className="font-medium text-ink hover:text-accent">{d.device.hostname}</Link></>}
        </p>

        {canTriage && (
          <div className="mt-4 flex flex-wrap items-center gap-2">
            {a.status !== "acknowledged" && a.status !== "closed" && (
              <Button size="sm" disabled={pending} onClick={() => run(() => triageAlerts({ ids: [a.id], status: "acknowledged", assignToMe: true }))}>
                <UserCheck className="size-3.5" aria-hidden />조사 시작 · 나에게 지정
              </Button>
            )}
            {a.status !== "closed" ? (
              <span className="inline-flex items-center gap-1">
                <select aria-label="종결 판정" value={resolution} onChange={(e) => setResolution(e.target.value as typeof resolution)} className="h-7 rounded-md border border-line-strong bg-surface px-2 text-[13px]">
                  <option value="benign">정상 활동</option>
                  <option value="false_positive">오탐</option>
                  <option value="true_positive">실제 위협</option>
                </select>
                <Button size="sm" variant="primary" disabled={pending} onClick={() => run(() => triageAlerts({ ids: [a.id], status: "closed", resolution }))}>
                  <Check className="size-3.5" aria-hidden />종결
                </Button>
              </span>
            ) : (
              <Button size="sm" disabled={pending} onClick={() => run(() => triageAlerts({ ids: [a.id], status: "open", resolution: null }))}>다시 열기</Button>
            )}
            <SuppressDialog alert={a} run={run} pending={pending} />
          </div>
        )}
      </header>

      <div className="space-y-5 px-5 py-4">
        <section>
          <h3 className="mb-1.5 text-[13px] font-semibold text-ink-2">무슨 일이 있었나</h3>
          {d.rule && <p className="mb-2 text-[14px]">{d.rule.description}</p>}
          <dl className="divide-y divide-line rounded-md border border-line">
            {facts.length === 0 && <div className="px-3 py-2 text-[13px] text-muted">추가 정보 없음</div>}
            {facts.map(([k, v]) => (
              <div key={k} className="grid grid-cols-[7.5rem_minmax(0,1fr)_auto] items-start gap-3 px-3 py-2 text-[13px]">
                <dt className="text-muted">{FIELD_LABEL[k] ?? k}</dt>
                <dd className="min-w-0" suppressHydrationWarning>{factValue(k, v, a.details)}</dd>
                {HUNTABLE.has(k) && typeof v === "string" ? (
                  <Link href={`/hunt?q=${encodeURIComponent(v)}`} className="text-xs whitespace-nowrap text-accent hover:underline">전체 PC 에서 찾기</Link>
                ) : <span />}
              </div>
            ))}
          </dl>
        </section>

        {d.rule && (
          <section className="grid gap-x-6 gap-y-1 text-[13px] sm:grid-cols-2">
            <div>
              <h3 className="mb-1 font-semibold text-ink-2">탐지 규칙</h3>
              <Link href="/rules" className="hover:text-accent">{d.rule.title}</Link> <span className="text-muted">{d.rule.rule_id}</span>
            </div>
            <div>
              <h3 className="mb-1 font-semibold text-ink-2">MITRE ATT&CK</h3>
              {d.rule.mitre_tactic} — {attackUrl && (
                <a href={attackUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
                  {d.rule.mitre_technique} {d.rule.technique_name}<ExternalLink className="size-3" aria-hidden />
                </a>
              )}
            </div>
          </section>
        )}

        {d.device && (
          <section className="text-[13px]">
            <h3 className="mb-1 font-semibold text-ink-2">장치</h3>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
              <Link href={`/devices/${d.device.id}`} className="font-medium hover:text-accent">{d.device.hostname}</Link>
              <LivenessTag state={liveness(d.device.last_seen_at)} />
              {d.device.last_ip && <Mono>{d.device.last_ip}</Mono>}
              <span className="text-ink-2">{d.device.os_version}</span>
              <Link href={`/devices/${d.device.id}?tab=timeline`} className="text-accent hover:underline">이 PC 타임라인</Link>
            </div>
          </section>
        )}

        <section>
          <h3 className="mb-2 text-[13px] font-semibold text-ink-2">처리 기록 {d.comments.length > 0 && <span className="text-muted">{d.comments.length}</span>}</h3>
          <ol className="space-y-2">
            {d.comments.map((c) => (
              <li key={c.id} className="rounded-md bg-surface-2 px-3 py-2 text-[13px]">
                <div className="text-xs text-muted" suppressHydrationWarning>{c.author_email ?? c.author_id.slice(0, 8)} — {stamp(c.created_at)}</div>
                <p className="mt-0.5 whitespace-pre-wrap">{c.body}</p>
              </li>
            ))}
          </ol>
          {canTriage && (
            <form className="mt-2" onSubmit={(e) => { e.preventDefault(); if (!comment.trim()) return; run(() => addComment({ alertId: a.id, body: comment }), () => setComment("")); }}>
              <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={2} placeholder="확인한 내용, 조치, 전달 사항을 남기세요"
                aria-label="처리 메모" className="w-full resize-y rounded-md border border-line-strong bg-surface px-3 py-2 text-[13px] outline-none focus:border-accent" />
              <div className="mt-1.5 flex justify-end"><Button size="sm" type="submit" disabled={pending || !comment.trim()}>메모 남기기</Button></div>
            </form>
          )}
        </section>

        <details className="text-[13px]">
          <summary className="cursor-pointer text-ink-2 hover:text-ink">원본 데이터 (JSON)</summary>
          <pre className="mt-2 max-h-72 overflow-auto rounded-md bg-surface-2 p-3 font-mono text-xs leading-relaxed">{JSON.stringify(a.details, null, 2)}</pre>
        </details>
      </div>
    </article>
  );
}

// ---------------------------------------------------------------------------
// 예외 만들기 — 경보 세부 값 중 일부를 골라 같은 조건의 다음 경보를 자동 종결
// ---------------------------------------------------------------------------
function SuppressDialog({ alert, run, pending }: { alert: Alert; run: (fn: () => Promise<ActionResult>, after?: () => void) => void; pending: boolean }) {
  const candidates = Object.entries(alert.details).filter(([, v]) => ["string", "number", "boolean"].includes(typeof v)) as [string, string | number | boolean][];
  const preferred = new Set(["entry", "src_ip", "sha256", "remote_ip", "image_path"]);
  const [open, setOpen] = useState(false);
  const [keys, setKeys] = useState<Set<string>>(() => new Set(candidates.map(([k]) => k).filter((k) => preferred.has(k))));
  const [scope, setScope] = useState<"device" | "all">("all");
  const [days, setDays] = useState<string>("90");
  const [reason, setReason] = useState("");
  const match = Object.fromEntries(candidates.filter(([k]) => keys.has(k)));

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>
        <Button size="sm" variant="ghost"><ShieldOff className="size-3.5" aria-hidden />예외로 처리</Button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-[#0a111b]/40" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 w-[min(560px,94vw)] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-line bg-surface p-5 shadow-2xl">
          <Dialog.Title className="text-[16px] font-semibold">예외 만들기</Dialog.Title>
          <Dialog.Description className="mt-1 text-[13px] text-ink-2">
            고른 값이 모두 같은 &lsquo;{alert.rule_id}&rsquo; 경보는 앞으로 생기자마자 &lsquo;예외 규칙으로 종결&rsquo; 상태가 됩니다. 기록은 남습니다.
          </Dialog.Description>
          <fieldset className="mt-4">
            <legend className="mb-1.5 text-[13px] font-semibold">일치 조건</legend>
            {candidates.length === 0 && <p className="text-[13px] text-muted">이 경보에는 조건으로 쓸 값이 없습니다. 규칙 전체를 끄려면 탐지 규칙 화면을 쓰세요.</p>}
            <div className="space-y-1">
              {candidates.map(([k, v]) => (
                <label key={k} className="flex items-start gap-2 rounded px-1 py-1 text-[13px] hover:bg-surface-2">
                  <input type="checkbox" className="mt-0.5 size-3.5 accent-[var(--accent)]" checked={keys.has(k)}
                    onChange={() => setKeys((s) => { const c = new Set(s); if (c.has(k)) c.delete(k); else c.add(k); return c; })} />
                  <span className="w-24 shrink-0 text-muted">{FIELD_LABEL[k] ?? k}</span>
                  <span className="min-w-0 break-mono text-[12px]">{String(v)}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <label className="text-[13px]">
              <span className="mb-1 block font-semibold">적용 범위</span>
              <select value={scope} onChange={(e) => setScope(e.target.value as "device" | "all")} className="h-8 w-full rounded-md border border-line-strong bg-surface px-2">
                <option value="all">모든 장치</option>
                <option value="device" disabled={!alert.device_id}>이 장치({alert.hostname})만</option>
              </select>
            </label>
            <label className="text-[13px]">
              <span className="mb-1 block font-semibold">유지 기간</span>
              <select value={days} onChange={(e) => setDays(e.target.value)} className="h-8 w-full rounded-md border border-line-strong bg-surface px-2">
                <option value="30">30일</option>
                <option value="90">90일</option>
                <option value="365">1년</option>
                <option value="">기한 없음</option>
              </select>
            </label>
          </div>
          <label className="mt-3 block text-[13px]">
            <span className="mb-1 block font-semibold">이유</span>
            <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="예: OneDrive 자동 업데이트 — 정상" className="h-8 w-full rounded-md border border-line-strong bg-surface px-2 outline-none focus:border-accent" />
          </label>
          {Object.keys(match).length === 0 && candidates.length > 0 && (
            <p className="mt-3 text-[13px] text-warn">조건을 하나도 고르지 않으면 이 규칙의 모든 경보가 예외 처리됩니다.</p>
          )}
          <div className="mt-5 flex justify-end gap-2">
            <Dialog.Close asChild><Button>취소</Button></Dialog.Close>
            <Button variant="primary" disabled={pending || reason.trim().length < 2}
              onClick={() => run(() => createSuppression({
                rule_id: alert.rule_id, device_id: scope === "device" ? alert.device_id : null, match, reason, days: days ? Number(days) : null,
              }), () => setOpen(false))}>
              예외 만들기
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
