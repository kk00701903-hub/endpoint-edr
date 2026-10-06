"use client";

import { useRouter } from "next/navigation";
import { useMemo, useRef, useState, useTransition } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { BookmarkPlus, Play, Trash2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { deleteQuery, saveQuery } from "@/lib/actions";
import { EXAMPLE_QUERIES, FIELDS, parseQuery } from "@/lib/hunt/query";
import type { SavedQuery } from "@/lib/data/types";
import { useActionToast } from "./shell";
import { Button, Kbd } from "./ui";

const RANGES = [{ v: 24, l: "24시간" }, { v: 168, l: "7일" }, { v: 720, l: "30일" }, { v: 2160, l: "90일" }];

/** 쿼리 편집기: 필드 자동 완성, 실시간 문법 검사, 예시·저장된 쿼리, Ctrl+Enter 실행 */
export function QueryConsole({ initial, hours, saved, canSave, children }: { initial: string; hours: number; saved: SavedQuery[]; canSave: boolean; children?: React.ReactNode }) {
  const router = useRouter();
  const notify = useActionToast();
  const [q, setQ] = useState(initial);
  const [h, setH] = useState(hours);
  const [pending, start] = useTransition();
  const ta = useRef<HTMLTextAreaElement>(null);
  const parsed = useMemo(() => (q.trim() ? parseQuery(q) : null), [q]);

  // 커서 앞 단어로 필드 자동 완성
  const [caret, setCaret] = useState(0);
  const word = q.slice(0, caret).match(/([a-z_.]*)$/i)?.[1] ?? "";
  const suggestions = word.length >= 1 && !/\s(=|~|!|<|>)/.test(q.slice(Math.max(0, caret - word.length - 3), caret))
    ? FIELDS.filter((f) => f.key.startsWith(word.toLowerCase()) && f.key !== word.toLowerCase()).slice(0, 6) : [];

  const run = (query = q, hrs = h) => {
    if (!query.trim()) return;
    start(() => router.push(`/hunt?q=${encodeURIComponent(query.trim())}&h=${hrs}`));
  };
  const insert = (text: string) => {
    const before = q.slice(0, caret - word.length), after = q.slice(caret);
    const next = before + text + " " + after;
    setQ(next);
    requestAnimationFrame(() => { ta.current?.focus(); const p = before.length + text.length + 1; ta.current?.setSelectionRange(p, p); setCaret(p); });
  };

  return (
    <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_18rem]">
      <div className="min-w-0">
      <section className="rounded-lg border border-line bg-surface" aria-label="쿼리 편집기">
        <div className="relative">
          <textarea
            ref={ta}
            value={q}
            spellCheck={false}
            rows={3}
            aria-label="헌팅 쿼리"
            placeholder='process.name = powershell.exe and process.cmdline ~ "-enc"'
            onChange={(e) => { setQ(e.target.value); setCaret(e.target.selectionStart); }}
            onKeyUp={(e) => setCaret(e.currentTarget.selectionStart)}
            onClick={(e) => setCaret(e.currentTarget.selectionStart)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); }
              if (e.key === "Tab" && suggestions[0]) { e.preventDefault(); insert(suggestions[0].key); }
            }}
            className="block w-full resize-y rounded-t-lg bg-transparent px-4 py-3 font-mono text-[14px] leading-6 outline-none placeholder:text-muted"
          />
          {suggestions.length > 0 && (
            <ul className="absolute top-full left-3 z-10 -mt-1 w-80 overflow-hidden rounded-md border border-line bg-surface-2 shadow-xl" role="listbox" aria-label="필드 제안">
              {suggestions.map((f, i) => (
                <li key={f.key}>
                  <button type="button" onMouseDown={(e) => { e.preventDefault(); insert(f.key); }}
                    className={cn("flex w-full items-center justify-between gap-3 px-3 py-1.5 text-left text-[13px] hover:bg-accent-soft", i === 0 && "bg-surface-3")}>
                    <span className="font-mono">{f.key}</span><span className="text-xs text-muted">{f.label}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 border-t border-line px-3 py-2">
          <select value={h} onChange={(e) => setH(Number(e.target.value))} aria-label="기간" className="h-8 rounded-md border border-line-strong bg-surface px-2 text-[13px]">
            {RANGES.map((r) => <option key={r.v} value={r.v}>최근 {r.l}</option>)}
          </select>
          <span className={cn("min-w-0 flex-1 truncate text-[13px]", parsed && !parsed.ok ? "text-warn" : "text-ink-2")} role="status">
            {!parsed ? <>필드 이름을 입력하면 제안이 나옵니다. <Kbd>Tab</Kbd> 으로 완성</> : parsed.ok
              ? `${{ process: "프로세스", net: "네트워크 연결", event: "보안 이벤트", autorun: "자동 실행" }[parsed.query.dataset]} 기록에서 조건 ${parsed.query.terms.length}개로 찾습니다`
              : /(>=|<=|!=|!~|=|~|>|<)/.test(q) ? parsed.error : "값만 입력하면 프로세스 이름·IP·해시로 찾습니다"}
          </span>
          {canSave && <SaveDialog query={q} hours={h} disabled={!parsed?.ok} />}
          <Button variant="primary" disabled={pending || !q.trim()} onClick={() => run()}>
            <Play className="size-3.5" aria-hidden />{pending ? "찾는 중" : "실행"} <span className="hidden text-xs opacity-80 sm:inline">Ctrl+Enter</span>
          </Button>
        </div>
      </section>
      {children}
      </div>

      <aside className="space-y-4">
        <section className="rounded-lg border border-line bg-surface">
          <h2 className="border-b border-line px-3 py-2 text-[13px] font-semibold">저장된 쿼리</h2>
          {saved.length === 0 ? <p className="px-3 py-3 text-[13px] text-muted">아직 없습니다. 자주 쓰는 쿼리를 저장해 두세요.</p> : (
            <ul className="divide-y divide-line">
              {saved.map((s) => (
                <li key={s.id} className="group flex items-start gap-1 px-3 py-2">
                  <button className="min-w-0 flex-1 text-left" onClick={() => { setQ(s.query); setH(s.hours); run(s.query, s.hours); }}>
                    <div className="truncate text-[13px] font-medium group-hover:text-accent">{s.name}</div>
                    <div className="truncate font-mono text-[11.5px] text-muted">{s.query}</div>
                  </button>
                  {canSave && (
                    <button aria-label={`${s.name} 지우기`} className="rounded p-1 text-muted opacity-0 group-hover:opacity-100 hover:text-sev-high focus:opacity-100"
                      onClick={() => start(async () => { notify(await deleteQuery(s.id)); router.refresh(); })}><Trash2 className="size-3.5" /></button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="rounded-lg border border-line bg-surface">
          <h2 className="border-b border-line px-3 py-2 text-[13px] font-semibold">예시</h2>
          <ul className="divide-y divide-line">
            {EXAMPLE_QUERIES.map((e) => (
              <li key={e.name}>
                <button className="w-full px-3 py-2 text-left hover:bg-surface-2" onClick={() => { setQ(e.query); run(e.query); }}>
                  <div className="text-[13px] font-medium">{e.name}</div>
                  <div className="text-xs text-muted">{e.why}</div>
                </button>
              </li>
            ))}
          </ul>
        </section>
        <details className="rounded-lg border border-line bg-surface px-3 py-2 text-[13px]">
          <summary className="cursor-pointer font-semibold">쓸 수 있는 필드와 연산자</summary>
          <p className="mt-2 text-xs text-ink-2">= 같음, != 다름, ~ 포함, !~ 미포함, &gt; &lt; 크기 비교. 조건은 and 로 잇습니다. 글자 비교는 대소문자를 가리지 않습니다.</p>
          <ul className="mt-2 space-y-0.5">
            {FIELDS.map((f) => <li key={f.key} className="flex justify-between gap-2"><button className="font-mono text-[12px] text-accent hover:underline" onClick={() => setQ((x) => (x.trim() ? `${x.trim()} and ${f.key} ` : `${f.key} `))}>{f.key}</button><span className="text-xs text-muted">{f.label}</span></li>)}
          </ul>
        </details>
      </aside>
    </div>
  );
}

function SaveDialog({ query, hours, disabled }: { query: string; hours: number; disabled: boolean }) {
  const router = useRouter();
  const notify = useActionToast();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [pending, start] = useTransition();
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild><Button disabled={disabled}><BookmarkPlus className="size-3.5" aria-hidden />저장</Button></Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/50" />
        <Dialog.Content className="fixed top-1/3 left-1/2 z-50 w-[min(480px,92vw)] -translate-x-1/2 rounded-lg border border-line bg-surface p-5 shadow-2xl">
          <Dialog.Title className="text-[16px] font-semibold">쿼리 저장</Dialog.Title>
          <Dialog.Description className="mt-1 text-[13px] text-ink-2">같은 조직 구성원 모두가 볼 수 있습니다.</Dialog.Description>
          <pre className="mt-3 overflow-x-auto rounded-md bg-surface-2 p-2 font-mono text-xs">{query}</pre>
          <label className="mt-3 block text-[13px]"><span className="mb-1 block font-semibold">이름</span>
            <input value={name} onChange={(e) => setName(e.target.value)} autoFocus placeholder="예: 서버 인코딩 PowerShell" className="h-8 w-full rounded-md border border-line-strong bg-surface px-2 outline-none focus:border-accent" /></label>
          <div className="mt-4 flex justify-end gap-2">
            <Dialog.Close asChild><Button>취소</Button></Dialog.Close>
            <Button variant="primary" disabled={pending || !name.trim()} onClick={() => start(async () => { const r = await saveQuery({ name, query, hours }); notify(r); if (r.ok) { setOpen(false); setName(""); router.refresh(); } })}>저장</Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
