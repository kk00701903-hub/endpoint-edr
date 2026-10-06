"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { Check, UserCheck } from "lucide-react";
import { addIncidentComment, triageIncident } from "@/lib/actions";
import type { AlertStatus, Resolution } from "@/lib/data/types";
import { RESOLUTION_LABEL, stamp } from "@/lib/format";
import { useActionToast } from "./shell";
import { Button, StatusTag } from "./ui";

/** 인시던트 처리 패널: 상태·담당·판정 + 처리 기록 */
export function IncidentTriage({ id, status, resolution, assignedToMe, assigned, canTriage, comments }: {
  id: number; status: AlertStatus; resolution: Exclude<Resolution, "suppressed"> | null; assignedToMe: boolean; assigned: boolean; canTriage: boolean;
  comments: { id: number; author_email?: string; author_id: string; body: string; created_at: string }[];
}) {
  const router = useRouter();
  const notify = useActionToast();
  const [pending, start] = useTransition();
  const [res, setRes] = useState<Exclude<Resolution, "suppressed">>("true_positive");
  const [body, setBody] = useState("");
  const run = (fn: () => ReturnType<typeof triageIncident>, after?: () => void) =>
    start(async () => { const r = await fn(); notify(r); if (r.ok) { after?.(); router.refresh(); } });

  return (
    <div className="space-y-5">
      <section>
        <h2 className="mb-2 text-[13px] font-semibold text-ink-2">처리</h2>
        <div className="flex flex-wrap items-center gap-2 text-[13px]">
          <StatusTag status={status} resolution={resolution} />
          <span className="text-ink-2">{assignedToMe ? "내가 담당" : assigned ? "다른 담당자" : "담당자 없음"}</span>
        </div>
        {canTriage ? (
          <div className="mt-3 space-y-2">
            {status !== "closed" && (
              <Button className="w-full" disabled={pending} onClick={() => run(() => triageIncident({ id, status: "acknowledged", assignToMe: true }))}>
                <UserCheck className="size-4" aria-hidden />{status === "acknowledged" && assignedToMe ? "조사 중 (내 담당)" : "조사 시작 · 나에게 지정"}
              </Button>
            )}
            {status !== "closed" ? (
              <fieldset className="rounded-md border border-line p-3">
                <legend className="px-1 text-xs text-muted">종결 판정</legend>
                <div className="grid gap-1">
                  {(["true_positive", "false_positive", "benign"] as const).map((r) => (
                    <label key={r} className="flex items-center gap-2 rounded px-1 py-1 text-[13px] hover:bg-surface-2">
                      <input type="radio" name={`res-${id}`} checked={res === r} onChange={() => setRes(r)} className="accent-[var(--accent)]" />
                      {RESOLUTION_LABEL[r]}
                    </label>
                  ))}
                </div>
                <Button variant="primary" className="mt-2 w-full" disabled={pending} onClick={() => run(() => triageIncident({ id, status: "closed", resolution: res }))}>
                  <Check className="size-4" aria-hidden />인시던트 종결
                </Button>
                <p className="mt-1.5 text-xs text-muted">포함된 미처리 경보도 같은 판정으로 종결됩니다.</p>
              </fieldset>
            ) : (
              <Button className="w-full" disabled={pending} onClick={() => run(() => triageIncident({ id, status: "open" }))}>다시 열기</Button>
            )}
          </div>
        ) : <p className="mt-2 text-xs text-muted">처리는 분석가 이상만 할 수 있습니다.</p>}
      </section>

      <section>
        <h2 className="mb-2 text-[13px] font-semibold text-ink-2">처리 기록 {comments.length > 0 && <span className="text-muted">{comments.length}</span>}</h2>
        <ol className="space-y-2">
          {comments.map((c) => (
            <li key={c.id} className="rounded-md bg-surface-2 px-3 py-2 text-[13px]">
              <div className="text-xs text-muted" suppressHydrationWarning>{c.author_email ?? c.author_id.slice(0, 8)}, {stamp(c.created_at)}</div>
              <p className="mt-0.5 whitespace-pre-wrap">{c.body}</p>
            </li>
          ))}
          {comments.length === 0 && <li className="text-[13px] text-muted">아직 기록이 없습니다.</li>}
        </ol>
        {canTriage && (
          <form className="mt-2" onSubmit={(e) => { e.preventDefault(); if (body.trim()) start(async () => { const r = await addIncidentComment({ id, body }); notify(r); if (r.ok) { setBody(""); router.refresh(); } }); }}>
            <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={3} aria-label="처리 메모" placeholder="확인한 내용, 조치, 전달 사항"
              className="w-full resize-y rounded-md border border-line-strong bg-surface px-3 py-2 text-[13px] outline-none focus:border-accent" />
            <div className="mt-1.5 flex justify-end"><Button size="sm" type="submit" disabled={pending || !body.trim()}>메모 남기기</Button></div>
          </form>
        )}
      </section>
    </div>
  );
}
