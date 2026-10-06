"use client";

import { useOptimistic, useState, useTransition } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Plus } from "lucide-react";
import { cn } from "@/lib/cn";
import {
  createIocs, createSoftwarePolicy, deleteIoc, deleteSoftwarePolicy, setIocEnabled, setPostureCheckEnabled, setSoftwarePolicyEnabled,
  type ActionResult,
} from "@/lib/actions";
import type { Severity } from "@/lib/data/types";
import { useActionToast } from "./shell";
import { Button } from "./ui";

// ---------------------------------------------------------------------------
// 켜기·끄기 스위치 (탐지 규칙 화면의 스위치와 같은 모양)
// ---------------------------------------------------------------------------
function Switch({ on, disabled, label, onToggle, onText = "사용", offText = "꺼짐" }: {
  on: boolean; disabled?: boolean; label: string; onToggle: (next: boolean) => Promise<ActionResult>; onText?: string; offText?: string;
}) {
  const [pending, start] = useTransition();
  const [value, setValue] = useOptimistic(on);
  const notify = useActionToast();
  return (
    <button
      role="switch"
      aria-checked={value}
      aria-label={`${label} ${value ? "끄기" : "켜기"}`}
      title={disabled ? "권한이 없어 바꿀 수 없습니다" : undefined}
      disabled={disabled || pending}
      onClick={() => start(async () => { setValue(!value); notify(await onToggle(!value)); })}
      className={cn("inline-flex h-6 w-[4.5rem] shrink-0 items-center justify-between gap-1 rounded-full border px-1 text-xs transition-colors disabled:cursor-not-allowed",
        value ? "border-accent bg-accent text-accent-ink" : "border-line-strong bg-surface-3 text-ink-2", disabled && "opacity-70")}
    >
      {value ? <><span className="pl-1.5">{onText}</span><span className="size-4 rounded-full bg-accent-ink" /></> : <><span className="size-4 rounded-full bg-surface" /><span className="pr-1.5">{offText}</span></>}
    </button>
  );
}

function DeleteButton({ confirmText, run, label = "지우기" }: { confirmText: string; run: () => Promise<ActionResult>; label?: string }) {
  const [pending, start] = useTransition();
  const notify = useActionToast();
  return (
    <button disabled={pending} onClick={() => { if (confirm(confirmText)) start(async () => notify(await run())); }}
      className="text-[13px] text-sev-high hover:underline disabled:opacity-50">
      {label}
    </button>
  );
}

const SEVERITIES: { value: Severity; label: string }[] = [
  { value: "critical", label: "긴급" }, { value: "high", label: "높음" }, { value: "medium", label: "보통" }, { value: "low", label: "낮음" },
];
const input = "h-8 w-full rounded-md border border-line-strong bg-surface px-2 text-[13px] outline-none focus:border-accent";
const labelCls = "mb-1 block text-[13px] font-semibold";

// ---------------------------------------------------------------------------
// 위협 지표
// ---------------------------------------------------------------------------
export function IocToggle({ id, enabled, disabled, value }: { id: number; enabled: boolean; disabled: boolean; value: string }) {
  return <Switch on={enabled} disabled={disabled} label={`지표 ${value}`} onToggle={(v) => setIocEnabled(id, v)} />;
}

export function IocDelete({ id, value }: { id: number; value: string }) {
  return <DeleteButton confirmText={`지표 ${value} 를 지울까요? 이미 만들어진 경보는 남습니다.`} run={() => deleteIoc(id)} />;
}

/** 지표 등록: 여러 개를 한 번에 붙여 넣을 수 있다(줄바꿈·쉼표·공백으로 구분) */
export function IocForm() {
  const [values, setValues] = useState("");
  const [severity, setSeverity] = useState<Severity>("high");
  const [description, setDescription] = useState("");
  const [source, setSource] = useState("");
  const [days, setDays] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();
  const notify = useActionToast();
  const count = new Set(values.split(/[\s,;]+/).filter(Boolean)).size;
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        start(async () => {
          const r = await createIocs({ values, severity, description, source, days: days ? Number(days) : null });
          if (r.ok) { notify(r); setValues(""); setDescription(""); } else setError(r.error);
        });
      }}
      className="grid gap-3"
    >
      <label>
        <span className={labelCls}>해시(SHA-256) 또는 IP·대역</span>
        <textarea
          required value={values} onChange={(e) => setValues(e.target.value)} rows={4} spellCheck={false}
          placeholder={"한 줄에 하나씩, 여러 개 붙여 넣기 가능\n예) 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b\n    45.155.205.99\n    185.220.101.0/24"}
          className="w-full rounded-md border border-line-strong bg-surface px-2 py-1.5 font-mono text-[12.5px] outline-none focus:border-accent"
        />
        <span className="mt-1 block text-xs text-muted">1.2.3[.]4 처럼 무력화한 표기도 받습니다. 대역은 IPv4 /16, IPv6 /48 보다 좁아야 합니다.</span>
      </label>
      <div className="grid gap-3 sm:grid-cols-[8rem_minmax(0,1fr)_minmax(0,12rem)_9rem]">
        <label><span className={labelCls}>심각도</span>
          <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className={input}>
            {SEVERITIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
        </label>
        <label><span className={labelCls}>설명</span>
          <input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} placeholder="예: 피싱 메일 첨부 드로퍼" className={input} />
        </label>
        <label><span className={labelCls}>출처</span>
          <input value={source} onChange={(e) => setSource(e.target.value)} maxLength={200} placeholder="예: KISA 보안 공지" className={input} />
        </label>
        <label><span className={labelCls}>만료</span>
          <select value={days} onChange={(e) => setDays(e.target.value)} className={input}>
            <option value="">기한 없음</option>
            <option value="30">30일 뒤</option>
            <option value="90">90일 뒤</option>
            <option value="180">180일 뒤</option>
            <option value="365">1년 뒤</option>
          </select>
        </label>
      </div>
      {error && <p className="text-[13px] text-sev-high" role="alert">{error}</p>}
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-ink-2">등록하면 최근 7일 기록을 바로 찾아보고, 이후 들어오는 기록은 1분마다 확인합니다.</p>
        <Button variant="primary" type="submit" disabled={pending || count === 0}>
          <Plus className="size-4" aria-hidden />{pending ? "등록 중" : count > 1 ? `${count}개 등록` : "등록"}
        </Button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// 소프트웨어 정책
// ---------------------------------------------------------------------------
export function PolicyToggle({ id, enabled, disabled, name }: { id: number; enabled: boolean; disabled: boolean; name: string }) {
  return <Switch on={enabled} disabled={disabled} label={`정책 ${name}`} onToggle={(v) => setSoftwarePolicyEnabled(id, v)} />;
}

export function PolicyDelete({ id, name }: { id: number; name: string }) {
  return <DeleteButton confirmText={`'${name}' 정책을 지울까요?`} run={() => deleteSoftwarePolicy(id)} />;
}

export function SoftwarePolicyDialog() {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<"vulnerable" | "prohibited">("prohibited");
  const [name, setName] = useState("");
  const [publisher, setPublisher] = useState("");
  const [fixed, setFixed] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [reference, setReference] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();
  const notify = useActionToast();
  const reset = () => { setName(""); setPublisher(""); setFixed(""); setReference(""); setReason(""); setError(null); };
  return (
    <Dialog.Root open={open} onOpenChange={(o) => { setOpen(o); if (!o) reset(); }}>
      <Dialog.Trigger asChild>
        <Button variant="primary"><Plus className="size-4" aria-hidden />정책 추가</Button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-[#0a111b]/40" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 max-h-[92dvh] w-[min(560px,94vw)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-line bg-surface p-5 shadow-2xl">
          <form onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            start(async () => {
              const r = await createSoftwarePolicy({ kind, name_pattern: name, publisher_pattern: publisher, fixed_version: kind === "vulnerable" ? fixed : "", severity, reference, reason });
              if (r.ok) { notify(r); setOpen(false); reset(); } else setError(r.error);
            });
          }}>
            <Dialog.Title className="text-[16px] font-semibold">소프트웨어 정책 추가</Dialog.Title>
            <Dialog.Description className="mt-1 text-[13px] text-ink-2">
              설치 프로그램 목록과 비교해 해당하는 PC 를 보여 줍니다. 프로그램을 지우거나 막지는 않습니다.
            </Dialog.Description>
            <fieldset className="mt-4">
              <legend className={labelCls}>종류</legend>
              <div className="grid grid-cols-2 gap-2 text-[13px]">
                {([["prohibited", "금지 소프트웨어", "설치되어 있으면 경보(EDR-SW-001)"], ["vulnerable", "취약 버전", "지정한 버전보다 낮으면 노출로 표시"]] as const).map(([v, t, d]) => (
                  <label key={v} className={cn("cursor-pointer rounded-md border p-2.5", kind === v ? "border-accent bg-accent-soft" : "border-line-strong")}>
                    <input type="radio" name="kind" value={v} checked={kind === v} onChange={() => setKind(v)} className="sr-only" />
                    <span className="block font-medium">{t}</span>
                    <span className="block text-xs text-ink-2">{d}</span>
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="mt-3 grid grid-cols-2 gap-3">
              <label className="col-span-2 sm:col-span-1"><span className={labelCls}>프로그램 이름에 들어간 글자</span>
                <input required minLength={2} value={name} onChange={(e) => setName(e.target.value)} placeholder="예: AnyDesk, *torrent" className={input} />
              </label>
              <label className="col-span-2 sm:col-span-1"><span className={labelCls}>게시자(선택)</span>
                <input value={publisher} onChange={(e) => setPublisher(e.target.value)} placeholder="예: win.rar" className={input} />
              </label>
              {kind === "vulnerable" && (
                <label className="col-span-2 sm:col-span-1"><span className={labelCls}>이 버전 미만이 취약</span>
                  <input value={fixed} onChange={(e) => setFixed(e.target.value)} placeholder="비우면 모든 버전(지원 종료 제품)" className={input} />
                </label>
              )}
              <label className="col-span-2 sm:col-span-1"><span className={labelCls}>심각도</span>
                <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className={input}>
                  {SEVERITIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                </select>
              </label>
              <label className="col-span-2"><span className={labelCls}>참고(CVE 번호·공지·사내 지침)</span>
                <input value={reference} onChange={(e) => setReference(e.target.value)} maxLength={300} placeholder="예: CVE-2023-38831" className={input} />
              </label>
              <label className="col-span-2"><span className={labelCls}>이유·조치 안내</span>
                <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} placeholder="예: 승인되지 않은 원격 제어 도구 — 삭제 요청" className={input} />
              </label>
            </div>
            <p className="mt-2 text-xs text-muted">이름·게시자는 대소문자를 가리지 않고 &lsquo;포함&rsquo;으로 찾습니다. <code className="font-mono">*</code> 는 아무 글자입니다.</p>
            {error && <p className="mt-3 text-[13px] text-sev-high" role="alert">{error}</p>}
            <div className="mt-5 flex justify-end gap-2">
              <Dialog.Close asChild><Button type="button">취소</Button></Dialog.Close>
              <Button variant="primary" type="submit" disabled={pending || name.trim().length < 2}>{pending ? "만드는 중" : "만들기"}</Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ---------------------------------------------------------------------------
// 보안 상태 점검 항목: 보안 점수에 넣을지
// ---------------------------------------------------------------------------
export function PostureCheckToggle({ checkId, enabled, disabled, title }: { checkId: string; enabled: boolean; disabled: boolean; title: string }) {
  return <Switch on={enabled} disabled={disabled} label={`${title} 점수 반영`} onText="반영" offText="제외" onToggle={(v) => setPostureCheckEnabled(checkId, v)} />;
}
