"use client";

import Link from "next/link";
import { useState, useTransition } from "react";
import { updateRemediation } from "@/lib/actions";
import { cn } from "@/lib/cn";
import type { RemediationItem, RemediationPatch, RemediationStatus } from "@/lib/data/types";
import { ago, fullDay } from "@/lib/format";
import { REMEDIATION_KIND, REMEDIATION_STATUS } from "@/lib/remediation-labels";
import { useActionToast } from "./shell";
import { Button, SeverityTag } from "./ui";

// PC 조치 목록 표: 고르기 + 아래 막대에서 상태·담당자·기한·메모를 한꺼번에 바꾼다(한 건도 같은 방법).


const STATUS_TONE: Record<RemediationStatus, string> = {
  open: "border-line-strong text-ink",
  in_progress: "border-accent/40 bg-accent-soft text-accent",
  done: "border-transparent bg-surface-3 text-ink-2",
  exception: "border-transparent bg-surface-3 text-muted",
};
const input = "h-8 rounded-md border border-line-strong bg-surface px-2 text-[13px] outline-none focus:border-accent";
const keyOf = (r: RemediationItem) => `${r.device_id}|${r.kind}|${r.item_key}`;

function sourceHref(r: RemediationItem) {
  if (r.kind === "posture") return `/devices/${r.device_id}?tab=posture`;
  if (r.kind === "software") return `/devices/${r.device_id}?tab=asset`;
  return `/documents?tab=${r.kind === "doc_pii" ? "pii" : "stale"}&device=${r.device_id}`;
}

export function RemediationTable({ rows, members, canEdit, canEditDocs, today }: {
  rows: RemediationItem[]; members: { user_id: string; email: string | null }[]; canEdit: boolean; canEditDocs: boolean; today: string;
}) {
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [status, setStatus] = useState<"" | RemediationStatus>("");
  const [assignee, setAssignee] = useState<string>("");     // "" 바꾸지 않음, "-" 비우기
  const [due, setDue] = useState<string>("");               // "" 바꾸지 않음, "-" 비우기
  const [note, setNote] = useState<string>("");
  const [pending, start] = useTransition();
  const notify = useActionToast();
  const editable = (r: RemediationItem) => canEdit && r.present && (!r.kind.startsWith("doc_") || canEditDocs);
  const selectable = rows.filter(editable);
  const allOn = selectable.length > 0 && selectable.every((r) => sel.has(keyOf(r)));
  const toggle = (k: string, on: boolean) => setSel((s) => { const n = new Set(s); if (on) n.add(k); else n.delete(k); return n; });
  const picked = rows.filter((r) => sel.has(keyOf(r)));

  function apply() {
    const patch: RemediationPatch = {};
    if (status) patch.status = status;
    if (assignee) patch.assignee = assignee === "-" ? null : assignee;
    if (due) patch.due_date = due === "-" ? null : due;
    if (note.trim()) patch.note = note.trim();
    start(async () => {
      const r = await updateRemediation({
        items: picked.map((x) => ({ device_id: x.device_id, kind: x.kind, item_key: x.item_key, title: x.title })),
        ...patch,
      });
      notify(r);
      if (r.ok) { setSel(new Set()); setStatus(""); setAssignee(""); setDue(""); setNote(""); }
    });
  }

  return (
    <>
      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        <table className="w-full min-w-[1080px] text-left text-[13.5px]">
          <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
            <tr>
              <th className="w-9 py-2 pl-4">
                {canEdit && <input type="checkbox" aria-label="이 쪽의 항목 모두 고르기" checked={allOn} disabled={selectable.length === 0}
                  onChange={(e) => setSel(e.target.checked ? new Set(selectable.map(keyOf)) : new Set())} className="size-3.5 accent-[var(--accent)]" />}
              </th>
              <th className="px-3 py-2 font-medium">장치</th>
              <th className="px-3 py-2 font-medium">할 일</th>
              <th className="px-3 py-2 font-medium">심각도</th>
              <th className="px-3 py-2 font-medium">발견</th>
              <th className="px-3 py-2 font-medium">상태</th>
              <th className="px-3 py-2 font-medium">담당자</th>
              <th className="px-4 py-2 font-medium">기한</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((r) => {
              const k = keyOf(r);
              const overdue = r.present && r.due_date && r.due_date < today && r.status !== "done";
              return (
                <tr key={k} className={cn("align-top hover:bg-surface-2", sel.has(k) && "bg-accent-soft/60", !r.present && "text-ink-2")}>
                  <td className="py-2.5 pl-4">
                    {editable(r) && <input type="checkbox" aria-label={`${r.hostname} ${r.title} 고르기`} checked={sel.has(k)}
                      onChange={(e) => toggle(k, e.target.checked)} className="size-3.5 accent-[var(--accent)]" />}
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    <Link href={`/devices/${r.device_id}`} className="font-medium hover:text-accent">{r.hostname}</Link>
                    <div className="text-xs text-muted">{REMEDIATION_KIND[r.kind]}</div>
                  </td>
                  <td className="max-w-[34rem] px-3 py-2.5">
                    <Link href={sourceHref(r)} className="font-medium hover:text-accent">{r.title}</Link>
                    {r.detail && <div className="text-xs text-ink-2 [overflow-wrap:anywhere]">{r.detail}</div>}
                    {r.guidance && (
                      <details className="mt-1 text-xs">
                        <summary className="cursor-pointer text-accent">고치는 방법</summary>
                        <p className="mt-1 text-ink-2 [overflow-wrap:anywhere]">{r.guidance}</p>
                      </details>
                    )}
                    {r.note && <p className="mt-1 rounded bg-surface-3 px-2 py-1 text-xs text-ink-2 [overflow-wrap:anywhere]">{r.note}</p>}
                  </td>
                  <td className="px-3 py-2.5">{r.severity ? <SeverityTag severity={r.severity} /> : <span className="text-muted">—</span>}</td>
                  <td className="px-3 py-2.5 whitespace-nowrap text-ink-2" suppressHydrationWarning>{r.since ? ago(r.since) : "—"}</td>
                  <td className="px-3 py-2.5">
                    {r.present ? (
                      <span className={cn("inline-flex rounded border px-1.5 py-px text-xs whitespace-nowrap", STATUS_TONE[r.status])}
                        title={r.status === "done" ? "완료로 표시했지만 아직 남아 있습니다. 다음 수집·검사에서 다시 확인합니다" : undefined}>
                        {REMEDIATION_STATUS[r.status]}{r.status === "done" ? " · 확인 대기" : ""}
                      </span>
                    ) : <span className="inline-flex rounded border border-transparent bg-surface-3 px-1.5 py-px text-xs text-ok whitespace-nowrap">해결 확인됨</span>}
                    {r.updated_at && <div className="mt-0.5 text-xs text-muted" suppressHydrationWarning>{ago(r.updated_at)}</div>}
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap">{r.assignee_email ?? (r.assignee ? "구성원" : <span className="text-muted">없음</span>)}</td>
                  <td className={cn("px-4 py-2.5 whitespace-nowrap", overdue && "font-medium text-sev-high")}>
                    {r.due_date ? <>{fullDay(r.due_date)}{overdue && <div className="text-xs">기한 지남</div>}</> : <span className="text-muted">—</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {picked.length > 0 && (
        <div className="sticky bottom-3 z-10 mt-3 flex flex-wrap items-end gap-3 rounded-lg border border-line-strong bg-surface p-3 shadow-lg" role="region" aria-label="고른 항목 처리">
          <div className="self-center text-[13px] font-semibold">{picked.length}건 고름</div>
          <label className="grid gap-1 text-xs text-ink-2">상태
            <select value={status} onChange={(e) => setStatus(e.target.value as "" | RemediationStatus)} className={input}>
              <option value="">바꾸지 않음</option>
              {(Object.keys(REMEDIATION_STATUS) as RemediationStatus[]).map((s) => <option key={s} value={s}>{REMEDIATION_STATUS[s]}</option>)}
            </select>
          </label>
          <label className="grid gap-1 text-xs text-ink-2">담당자
            <select value={assignee} onChange={(e) => setAssignee(e.target.value)} className={cn(input, "max-w-56")}>
              <option value="">바꾸지 않음</option>
              <option value="-">담당자 비우기</option>
              {members.map((m) => <option key={m.user_id} value={m.user_id}>{m.email ?? m.user_id}</option>)}
            </select>
          </label>
          <label className="grid gap-1 text-xs text-ink-2">기한
            <span className="flex items-center gap-1">
              <input type="date" value={due === "-" ? "" : due} onChange={(e) => setDue(e.target.value)} className={input} />
              {due !== "-" && <button type="button" onClick={() => setDue("-")} className="text-xs text-ink-2 hover:text-ink">비우기</button>}
              {due === "-" && <span className="text-xs text-muted">기한을 비웁니다</span>}
            </span>
          </label>
          <label className="grid min-w-56 flex-1 gap-1 text-xs text-ink-2">메모(바꿀 때만)
            <input value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} placeholder="예: 사용자에게 연락함, 업데이트 배포 예정" className={input} />
          </label>
          <div className="flex gap-2">
            <Button variant="ghost" onClick={() => setSel(new Set())}>고르기 취소</Button>
            <Button variant="primary" disabled={pending || (!status && !assignee && !due && !note.trim())} onClick={apply}>{pending ? "적용 중" : "적용"}</Button>
          </div>
        </div>
      )}
    </>
  );
}
