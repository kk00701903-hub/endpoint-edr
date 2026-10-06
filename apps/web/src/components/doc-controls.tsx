"use client";

import { useState, useTransition } from "react";
import { ScanSearch } from "lucide-react";
import { requestDocScan, saveDocPolicy } from "@/lib/actions";
import { cn } from "@/lib/cn";
import { DOC_EXT_GROUPS, DOC_FOLDERS, DOC_INTERVALS, PII_KINDS } from "@/lib/data/doc-defaults";
import type { DocPiiKind, DocScanPolicy } from "@/lib/data/types";
import { useActionToast } from "./shell";
import { Button } from "./ui";

// 문서 감사 화면의 쓰기 동작: "지금 검사" 요청, 정책 저장. 권한·검증은 서버 액션이 다시 확인한다.

const input = "h-8 w-full rounded-md border border-line-strong bg-surface px-2 text-[13px] outline-none focus:border-accent";
const labelCls = "mb-1 block text-[13px] font-semibold";
const lines = (s: string) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);

/** "지금 검사" — 장치 하나 또는 전체 */
export function DocScanRequestButton({ target, label = "지금 검사", disabled, size = "sm", variant = "secondary" }: {
  target: string[] | "all"; label?: string; disabled?: boolean; size?: "sm" | "md"; variant?: "primary" | "secondary";
}) {
  const [pending, start] = useTransition();
  const notify = useActionToast();
  return (
    <Button size={size} variant={variant} disabled={disabled || pending}
      onClick={() => {
        if (target === "all" && !confirm("켜져 있는 모든 PC 에 문서 검사를 요청할까요? 각 PC 는 낮은 속도로 읽으므로 업무에는 영향이 거의 없습니다.")) return;
        start(async () => notify(await requestDocScan(target)));
      }}>
      <ScanSearch className="size-4" aria-hidden />{pending ? "요청 중" : label}
    </Button>
  );
}

function Check({ checked, onChange, children, hint }: { checked: boolean; onChange: (v: boolean) => void; children: React.ReactNode; hint?: string }) {
  return (
    <label className="flex cursor-pointer items-start gap-2 text-[13px]">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="mt-0.5 size-4 accent-[var(--accent)]" />
      <span>{children}{hint && <span className="block text-xs text-muted">{hint}</span>}</span>
    </label>
  );
}

/** 정책 설정. 켜려면 직원 고지 확인이 필요하다(한 번 확인하면 기록이 남고 다시 묻지 않는다) */
export function DocPolicyForm({ policy }: { policy: DocScanPolicy }) {
  const [enabled, setEnabled] = useState(policy.enabled);
  const [interval, setIntervalHours] = useState(policy.interval_hours);
  const [folders, setFolders] = useState<string[]>(policy.folders);
  const [extraFolders, setExtraFolders] = useState(policy.folders.filter((f) => !DOC_FOLDERS.some((d) => d.value === f)).join("\n"));
  const [extraPaths, setExtraPaths] = useState(policy.extra_paths.join("\n"));
  const [exts, setExts] = useState<string[]>(policy.extensions);
  const [detect, setDetect] = useState<DocPiiKind[]>(policy.detect);
  const [keywords, setKeywords] = useState(policy.keywords.join("\n"));
  const [staleYears, setStaleYears] = useState(policy.stale_days ? String(Math.round((policy.stale_days / 365) * 10) / 10) : "0");
  const [maxMB, setMaxMB] = useState(policy.max_file_mb);
  const [notice, setNotice] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();
  const notify = useActionToast();
  const toggle = <T,>(xs: T[], x: T, on: boolean) => (on ? [...new Set([...xs, x])] : xs.filter((v) => v !== x));
  const needNotice = enabled && !policy.notice_confirmed_at;
  const kwCount = lines(keywords).length;

  return (
    <form
      className="grid gap-5"
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        const years = Number(staleYears);
        start(async () => {
          const r = await saveDocPolicy({
            enabled, interval_hours: interval,
            folders: [...folders.filter((f) => DOC_FOLDERS.some((d) => d.value === f)), ...lines(extraFolders)],
            extra_paths: lines(extraPaths), extensions: exts, detect, keywords: lines(keywords),
            stale_days: Number.isFinite(years) && years > 0 ? Math.round(years * 365) : 0, max_file_mb: maxMB, confirmNotice: notice,
          });
          if (r.ok) { notify(r); setNotice(false); } else setError(r.error);
        });
      }}
    >
      <fieldset className="grid gap-2">
        <legend className={labelCls}>사용</legend>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" role="switch" aria-checked={enabled} onClick={() => setEnabled(!enabled)}
            className={cn("inline-flex h-7 items-center gap-2 rounded-full border px-3 text-[13px]",
              enabled ? "border-accent bg-accent text-accent-ink" : "border-line-strong bg-surface-3 text-ink-2")}>
            {enabled ? "문서 감사 켜짐" : "문서 감사 꺼짐"}
          </button>
          {policy.notice_confirmed_at && (
            <span className="text-xs text-ink-2" suppressHydrationWarning>
              직원 고지 확인: {new Date(policy.notice_confirmed_at).toLocaleDateString("ko-KR")}{policy.notice_confirmed_by_email ? ` · ${policy.notice_confirmed_by_email}` : ""}
            </span>
          )}
        </div>
        {needNotice && (
          <div className="rounded-md border border-warn/50 bg-warn/10 p-3 text-[13px]">
            <Check checked={notice} onChange={setNotice}>
              직원에게 PC 문서 점검 사실(목적·대상 폴더·찾는 항목·서버에 남는 정보·보관 기간)을 알렸습니다.
            </Check>
            <p className="mt-1.5 pl-6 text-xs text-ink-2">사내 공지 예시는 docs/DOC_AUDIT_NOTICE.md 에 있습니다. 확인한 사람과 시각이 감사 기록에 남습니다.</p>
          </div>
        )}
      </fieldset>

      <div className="grid gap-5 lg:grid-cols-2">
        <fieldset className="grid gap-2">
          <legend className={labelCls}>찾을 개인정보</legend>
          {PII_KINDS.map((k) => (
            <Check key={k.value} checked={detect.includes(k.value)} onChange={(on) => setDetect(toggle(detect, k.value, on))} hint={k.hint}>{k.label}</Check>
          ))}
        </fieldset>

        <div className="grid content-start gap-4">
          <label>
            <span className={labelCls}>키워드 <span className="font-normal text-muted">({kwCount}/50, 한 줄에 하나)</span></span>
            <textarea value={keywords} onChange={(e) => setKeywords(e.target.value)} rows={4} placeholder={"예)\n대외비\n영업비밀"}
              className="w-full rounded-md border border-line-strong bg-surface px-2 py-1.5 text-[13px] outline-none focus:border-accent" />
            <span className="mt-1 block text-xs text-muted">대소문자를 가리지 않고 문서 안에 나온 횟수를 셉니다.</span>
          </label>
          <div className="grid gap-3 sm:grid-cols-2">
            <label>
              <span className={labelCls}>오래된 문서 기준</span>
              <select value={staleYears} onChange={(e) => setStaleYears(e.target.value)} className={input}>
                <option value="0">찾지 않음</option>
                {["1", "2", "3", "5", "10"].map((y) => <option key={y} value={y}>마지막 저장 {y}년 넘음</option>)}
                {!["0", "1", "2", "3", "5", "10"].includes(staleYears) && <option value={staleYears}>{staleYears}년 넘음</option>}
              </select>
            </label>
            <label>
              <span className={labelCls}>정기 검사</span>
              <select value={interval} onChange={(e) => setIntervalHours(Number(e.target.value))} className={input}>
                {DOC_INTERVALS.map((i) => <option key={i.value} value={i.value}>{i.label}</option>)}
                {!DOC_INTERVALS.some((i) => i.value === interval) && <option value={interval}>{interval}시간마다</option>}
              </select>
            </label>
          </div>
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <fieldset className="grid content-start gap-2">
          <legend className={labelCls}>검사할 폴더 (PC 의 모든 사용자)</legend>
          <div className="flex flex-wrap gap-x-5 gap-y-2">
            {DOC_FOLDERS.map((f) => (
              <Check key={f.value} checked={folders.includes(f.value)} onChange={(on) => setFolders(toggle(folders, f.value, on))}>{f.label}</Check>
            ))}
          </div>
          <label className="mt-1">
            <span className="mb-1 block text-xs text-ink-2">사용자 폴더 아래 다른 폴더 이름(한 줄에 하나, 예: 업무자료)</span>
            <textarea value={extraFolders} onChange={(e) => setExtraFolders(e.target.value)} rows={2}
              className="w-full rounded-md border border-line-strong bg-surface px-2 py-1.5 text-[13px] outline-none focus:border-accent" />
          </label>
          <label>
            <span className="mb-1 block text-xs text-ink-2">추가 경로(전체 경로, 한 줄에 하나, 예: D:\업무)</span>
            <textarea value={extraPaths} onChange={(e) => setExtraPaths(e.target.value)} rows={2} spellCheck={false}
              className="w-full rounded-md border border-line-strong bg-surface px-2 py-1.5 font-mono text-[12.5px] outline-none focus:border-accent" />
          </label>
          <p className="text-xs text-muted">OneDrive 로 옮겨진 바탕 화면·문서도 함께 봅니다. 내려받지 않은 클라우드 파일은 열지 않습니다.</p>
        </fieldset>

        <fieldset className="grid content-start gap-2">
          <legend className={labelCls}>문서 종류</legend>
          {DOC_EXT_GROUPS.map((g) => (
            <div key={g.label} className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
              <span className="w-14 text-xs text-muted">{g.label}</span>
              {g.exts.map((x) => <Check key={x} checked={exts.includes(x)} onChange={(on) => setExts(toggle(exts, x, on))}>.{x}</Check>)}
            </div>
          ))}
          <label className="mt-2 max-w-48">
            <span className={labelCls}>파일 크기 상한(MB)</span>
            <input type="number" min={1} max={100} value={maxMB} onChange={(e) => setMaxMB(Number(e.target.value) || 1)} className={input} />
            <span className="mt-1 block text-xs text-muted">이보다 큰 파일은 내용을 읽지 않습니다.</span>
          </label>
        </fieldset>
      </div>

      {error && <p className="text-[13px] text-sev-high" role="alert">{error}</p>}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4">
        <p className="max-w-2xl text-xs text-ink-2">
          에이전트는 문서를 읽기만 하고 고치거나 옮기지 않습니다. 서버에는 파일 위치·크기·저장 시각과 종류별 건수만 보내며, 문서 내용과 개인정보 값은 보내지 않습니다.
        </p>
        <Button variant="primary" type="submit" disabled={pending || (needNotice && !notice)}>{pending ? "저장 중" : "정책 저장"}</Button>
      </div>
    </form>
  );
}
