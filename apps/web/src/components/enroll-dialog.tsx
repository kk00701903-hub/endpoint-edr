"use client";

import { useState, useTransition } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Copy, KeyRound } from "lucide-react";
import { toast } from "sonner";
import { createEnrollmentKey } from "@/lib/actions";
import { Button } from "./ui";

/** 등록키 만들기 — 평문 키는 이 창에서 한 번만 보이고 서버에는 해시만 남는다. */
export function EnrollDialog({ ingestUrl }: { ingestUrl: string }) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [days, setDays] = useState(30);
  const [maxUses, setMaxUses] = useState(500);
  const [key, setKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();

  const config = key ? JSON.stringify({ ingest_url: ingestUrl, enrollment_key: key }, null, 2) : "";
  const copy = (text: string, what: string) => { navigator.clipboard.writeText(text); toast.success(`${what}을(를) 복사했습니다`); };

  return (
    <Dialog.Root open={open} onOpenChange={(o) => { setOpen(o); if (!o) { setKey(null); setLabel(""); setError(null); } }}>
      <Dialog.Trigger asChild>
        <Button variant="primary"><KeyRound className="size-4" aria-hidden />등록키 만들기</Button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-[#0a111b]/40" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 w-[min(560px,94vw)] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-line bg-surface p-5 shadow-2xl">
          {!key ? (
            <form onSubmit={(e) => {
              e.preventDefault();
              setError(null);
              start(async () => {
                const r = await createEnrollmentKey({ label, days, maxUses });
                if (r.ok && r.value) setKey(r.value); else if (!r.ok) setError(r.error);
              });
            }}>
              <Dialog.Title className="text-[16px] font-semibold">등록키 만들기</Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-ink-2">
                에이전트가 처음 한 번 서버에 자신을 등록할 때 쓰는 키입니다. 등록이 끝난 PC 는 키를 폐기해도 계속 동작합니다.
              </Dialog.Description>
              <label className="mt-4 block text-[13px]">
                <span className="mb-1 block font-semibold">이름</span>
                <input required value={label} onChange={(e) => setLabel(e.target.value)} placeholder="예: 재무팀 GPO 배포" className="h-8 w-full rounded-md border border-line-strong bg-surface px-2 outline-none focus:border-accent" />
              </label>
              <div className="mt-3 grid grid-cols-2 gap-3 text-[13px]">
                <label><span className="mb-1 block font-semibold">유효 기간(일)</span>
                  <input type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} className="h-8 w-full rounded-md border border-line-strong bg-surface px-2" /></label>
                <label><span className="mb-1 block font-semibold">최대 등록 대수</span>
                  <input type="number" min={1} max={100000} value={maxUses} onChange={(e) => setMaxUses(Number(e.target.value))} className="h-8 w-full rounded-md border border-line-strong bg-surface px-2" /></label>
              </div>
              {error && <p className="mt-3 text-[13px] text-sev-high">{error}</p>}
              <div className="mt-5 flex justify-end gap-2">
                <Dialog.Close asChild><Button type="button">취소</Button></Dialog.Close>
                <Button variant="primary" type="submit" disabled={pending || !label.trim()}>만들기</Button>
              </div>
            </form>
          ) : (
            <div>
              <Dialog.Title className="text-[16px] font-semibold">등록키가 만들어졌습니다</Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-sev-high">
                이 창을 닫으면 키를 다시 볼 수 없습니다. 지금 복사해 두세요.
              </Dialog.Description>
              <div className="mt-4 flex items-center gap-2 rounded-md border border-line-strong bg-surface-2 px-3 py-2">
                <code className="min-w-0 flex-1 break-all font-mono text-[12.5px]">{key}</code>
                <Button size="sm" onClick={() => copy(key, "등록키")}><Copy className="size-3.5" aria-hidden />복사</Button>
              </div>
              <p className="mt-4 text-[13px] font-semibold">PC 의 C:\ProgramData\EndpointEDR\config.json</p>
              <pre className="mt-1 overflow-x-auto rounded-md bg-surface-2 p-3 font-mono text-xs">{config}</pre>
              <div className="mt-5 flex justify-end gap-2">
                <Button onClick={() => copy(config, "config.json")}><Copy className="size-3.5" aria-hidden />config.json 복사</Button>
                <Dialog.Close asChild><Button variant="primary">닫기</Button></Dialog.Close>
              </div>
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
