"use client";

import { useState, useTransition } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Bell, Pencil, Plus, Send, Trash2 } from "lucide-react";
import { deleteNotificationChannel, saveNotificationChannel, testNotificationChannel } from "@/lib/actions";
import { cn } from "@/lib/cn";
import type { NewNotificationChannel, NotificationChannel, NotificationKind, Severity } from "@/lib/data/types";
import { SEVERITY_LABEL, ago } from "@/lib/format";
import { useActionToast } from "./shell";
import { Button } from "./ui";

// 알림 연동: 슬랙·이메일·SIEM 채널을 관리한다(관리자만). 비밀값은 .env 에 두고 여기엔 키 이름만.

const KIND_LABEL: Record<NotificationKind, string> = { slack: "슬랙", email: "이메일", syslog: "SIEM(Syslog)", webhook: "웹훅" };
const KIND_HINT: Record<NotificationKind, { target: string; secret: string; needSecret: boolean; needTarget: boolean }> = {
  slack:   { target: "표시용 채널 이름 (예: #soc-alerts)", secret: "웹훅 URL 이 든 .env 키 이름 (예: SLACK_WEBHOOK_SOC)", needSecret: true, needTarget: false },
  email:   { target: "받는 주소(쉼표로 여러 명)", secret: "(비움) SMTP 설정은 .env 공통값", needSecret: false, needTarget: true },
  syslog:  { target: "host:port (TCP 는 뒤에 /tcp)", secret: "(비움)", needSecret: false, needTarget: true },
  webhook: { target: "주소(또는 .env 키 이름 사용)", secret: "URL 이 든 .env 키 이름(선택)", needSecret: false, needTarget: false },
};
const SEVS: Severity[] = ["low", "medium", "high", "critical"];
const input = "h-8 w-full rounded-md border border-line-strong bg-surface px-2 text-[13px] outline-none focus:border-accent";

export function NotificationControls({ channels }: { channels: NotificationChannel[] }) {
  return (
    <div>
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <p className="text-[13px] text-ink-2">경보가 생기면 고른 심각도 이상일 때 이 채널로 보냅니다. 비밀값(웹훅 URL·비밀번호)은 서버 <code className="font-mono text-xs">.env</code> 에 두고 여기엔 키 이름만 적습니다.</p>
        <ChannelDialog trigger={<Button variant="primary" size="sm"><Plus className="size-4" aria-hidden />채널 추가</Button>} />
      </div>
      {channels.length === 0 ? (
        <p className="px-4 py-6 text-center text-[13px] text-ink-2">아직 알림 채널이 없습니다. 슬랙·이메일·SIEM 채널을 추가하세요.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-[13px]">
            <thead className="border-b border-line bg-surface-2 text-xs text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">이름</th><th className="px-3 py-2 font-medium">종류</th>
                <th className="px-3 py-2 font-medium">대상</th><th className="px-3 py-2 font-medium">보내는 기준</th>
                <th className="px-3 py-2 font-medium">상태</th><th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {channels.map((c) => <Row key={c.id} c={c} />)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Row({ c }: { c: NotificationChannel }) {
  const [pending, start] = useTransition();
  const notify = useActionToast();
  return (
    <tr className={cn("align-top", !c.enabled && "text-ink-2")}>
      <td className="px-4 py-2.5 font-medium">{c.name}</td>
      <td className="px-3 py-2.5">{KIND_LABEL[c.kind]}</td>
      <td className="max-w-[18rem] px-3 py-2.5 [overflow-wrap:anywhere]">
        {c.target || <span className="text-muted">—</span>}
        {c.secret_ref && <div className="text-xs text-muted">🔑 .env: {c.secret_ref}</div>}
      </td>
      <td className="px-3 py-2.5">
        {SEVERITY_LABEL[c.min_severity]} 이상
        {c.rule_prefixes.length > 0 && <div className="text-xs text-muted">규칙: {c.rule_prefixes.join(", ")}</div>}
      </td>
      <td className="px-3 py-2.5">
        {c.enabled ? <span className="text-ok">켜짐</span> : <span className="text-muted">꺼짐</span>}
        {(c.pending ?? 0) > 0 && <div className="text-xs text-warn">대기 {c.pending}건</div>}
        {(c.failed ?? 0) > 0 && <div className="text-xs text-sev-high">실패 {c.failed}건</div>}
        {c.last_sent_at && <div className="text-xs text-muted" suppressHydrationWarning>최근 {ago(c.last_sent_at)}</div>}
      </td>
      <td className="px-4 py-2.5">
        <div className="flex items-center justify-end gap-2">
          <button disabled={pending} title="테스트 알림 보내기" aria-label={`${c.name} 테스트 알림`}
            onClick={() => start(async () => notify(await testNotificationChannel(c.id)))}
            className="text-ink-2 hover:text-accent disabled:opacity-50"><Send className="size-4" /></button>
          <ChannelDialog channel={c} trigger={<button title="수정" aria-label={`${c.name} 수정`} className="text-ink-2 hover:text-accent"><Pencil className="size-4" /></button>} />
          <button disabled={pending} title="삭제" aria-label={`${c.name} 삭제`}
            onClick={() => { if (confirm(`'${c.name}' 채널을 지울까요?`)) start(async () => notify(await deleteNotificationChannel(c.id))); }}
            className="text-ink-2 hover:text-sev-high disabled:opacity-50"><Trash2 className="size-4" /></button>
        </div>
      </td>
    </tr>
  );
}

function ChannelDialog({ channel, trigger }: { channel?: NotificationChannel; trigger: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const [pending, start] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const notify = useActionToast();
  const [f, setF] = useState<NewNotificationChannel>(() => init(channel));
  function reset() { setF(init(channel)); setError(null); }

  return (
    <Dialog.Root open={open} onOpenChange={(o) => { setOpen(o); if (o) reset(); }}>
      <Dialog.Trigger asChild>{trigger}</Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-[#0a111b]/40" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 w-[min(560px,94vw)] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-line bg-surface p-5 shadow-2xl">
          <Dialog.Title className="flex items-center gap-2 text-[16px] font-semibold"><Bell className="size-4 text-accent" aria-hidden />{channel ? "알림 채널 수정" : "알림 채널 추가"}</Dialog.Title>
          <Dialog.Description className="mt-1 text-[13px] text-ink-2">비밀값은 서버 <code className="font-mono text-xs">.env</code> 에 저장하고, 여기엔 그 키 이름만 적습니다.</Dialog.Description>
          <form className="mt-4 space-y-3 text-[13px]" onSubmit={(e) => {
            e.preventDefault(); setError(null);
            start(async () => {
              const r = await saveNotificationChannel({ ...f, id: channel?.id });
              notify(r);
              if (r.ok) setOpen(false); else setError(r.error);
            });
          }}>
            <label className="block"><span className="mb-1 block font-semibold">이름</span>
              <input aria-label="채널 이름" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="예: SOC 슬랙" className={input} /></label>
            <div className="grid grid-cols-2 gap-3">
              <label><span className="mb-1 block font-semibold">종류</span>
                <select aria-label="채널 종류" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as NotificationKind })} className={input}>
                  {(Object.keys(KIND_LABEL) as NotificationKind[]).map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
                </select></label>
              <label><span className="mb-1 block font-semibold">보내는 기준(심각도 하한)</span>
                <select aria-label="보내는 기준" value={f.min_severity} onChange={(e) => setF({ ...f, min_severity: e.target.value as Severity })} className={input}>
                  {SEVS.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]} 이상</option>)}
                </select></label>
            </div>
            <label className="block"><span className="mb-1 block font-semibold">대상</span>
              <input aria-label="대상" value={f.target} onChange={(e) => setF({ ...f, target: e.target.value })} placeholder={KIND_HINT[f.kind].target} className={input} />
              <span className="mt-0.5 block text-xs text-muted">{KIND_HINT[f.kind].target}</span></label>
            <label className="block"><span className="mb-1 block font-semibold">비밀값 .env 키 이름</span>
              <input aria-label="비밀값 키 이름" value={f.secret_ref} onChange={(e) => setF({ ...f, secret_ref: e.target.value.toUpperCase() })} placeholder="예: SLACK_WEBHOOK_SOC" className={input} />
              <span className="mt-0.5 block text-xs text-muted">{KIND_HINT[f.kind].secret}</span></label>
            <label className="block"><span className="mb-1 block font-semibold">규칙 접두사 거르기(선택)</span>
              <input aria-label="규칙 접두사" value={f.rule_prefixes.join(", ")} onChange={(e) => setF({ ...f, rule_prefixes: e.target.value.split(",").map((s) => s.trim().toUpperCase()).filter(Boolean) })} placeholder="예: EDR-AUTH, EDR-IOC (비우면 전체)" className={input} /></label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} className="size-4 accent-[var(--accent)]" />이 채널 사용</label>
            {error && <p className="text-[13px] text-sev-high">{error}</p>}
            <div className="flex justify-end gap-2 pt-1">
              <Dialog.Close asChild><Button type="button">취소</Button></Dialog.Close>
              <Button variant="primary" type="submit" disabled={pending || !f.name.trim()}>{channel ? "저장" : "추가"}</Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function init(c?: NotificationChannel): NewNotificationChannel {
  return c
    ? { id: c.id, name: c.name, kind: c.kind, target: c.target, secret_ref: c.secret_ref, min_severity: c.min_severity, rule_prefixes: [...c.rule_prefixes], enabled: c.enabled }
    : { name: "", kind: "slack", target: "", secret_ref: "", min_severity: "high", rule_prefixes: [], enabled: true };
}
