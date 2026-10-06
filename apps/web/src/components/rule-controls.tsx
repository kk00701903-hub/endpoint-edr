"use client";

import { useOptimistic, useTransition } from "react";
import { cn } from "@/lib/cn";
import { deleteSuppression, revokeEnrollmentKey, setRuleEnabled } from "@/lib/actions";
import { useActionToast } from "./shell";

export function RuleToggle({ ruleId, enabled, disabled }: { ruleId: string; enabled: boolean; disabled: boolean }) {
  const [pending, start] = useTransition();
  const [on, setOn] = useOptimistic(enabled);
  const notify = useActionToast();
  return (
    <button
      role="switch"
      aria-checked={on}
      aria-label={`${ruleId} ${on ? "끄기" : "켜기"}`}
      title={disabled ? "관리자만 바꿀 수 있습니다" : undefined}
      disabled={disabled || pending}
      onClick={() => start(async () => { setOn(!on); notify(await setRuleEnabled(ruleId, !on)); })}
      className={cn("inline-flex h-6 w-[4.5rem] items-center justify-between gap-1 rounded-full border px-1 text-xs transition-colors disabled:cursor-not-allowed",
        on ? "border-accent bg-accent text-accent-ink" : "border-line-strong bg-surface-3 text-ink-2")}
    >
      {on ? <><span className="pl-1.5">사용</span><span className="size-4 rounded-full bg-accent-ink" /></> : <><span className="size-4 rounded-full bg-surface" /><span className="pr-1.5">꺼짐</span></>}
    </button>
  );
}

export function SuppressionDelete({ id }: { id: number }) {
  const [pending, start] = useTransition();
  const notify = useActionToast();
  return (
    <button disabled={pending} onClick={() => start(async () => notify(await deleteSuppression(id)))} className="text-[13px] text-sev-high hover:underline disabled:opacity-50">
      지우기
    </button>
  );
}

export function RevokeKey({ id }: { id: string }) {
  const [pending, start] = useTransition();
  const notify = useActionToast();
  return (
    <button disabled={pending} onClick={() => { if (confirm("이 등록키를 폐기할까요? 새 PC 는 이 키로 등록할 수 없게 됩니다.")) start(async () => notify(await revokeEnrollmentKey(id))); }}
      className="text-[13px] text-sev-high hover:underline disabled:opacity-50">
      폐기
    </button>
  );
}
