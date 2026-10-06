import Link from "next/link";
import type { ComponentProps, ReactNode } from "react";
import { cn } from "@/lib/cn";
import type { AlertStatus, PostureStatus, Resolution, Severity } from "@/lib/data/types";
import { LIVENESS_LABEL, RESOLUTION_LABEL, SEVERITY_LABEL, STATUS_LABEL, type Liveness } from "@/lib/format";

// ---------------------------------------------------------------------------
// 버튼
// ---------------------------------------------------------------------------
type Variant = "primary" | "secondary" | "ghost" | "danger";
const VARIANT: Record<Variant, string> = {
  primary: "bg-accent text-accent-ink hover:bg-accent-hover border border-transparent",
  secondary: "bg-surface text-ink border border-line-strong hover:bg-surface-2",
  ghost: "text-ink-2 hover:bg-surface-3 hover:text-ink border border-transparent",
  danger: "bg-surface text-sev-high border border-line-strong hover:border-sev-high",
};
const SIZE = { sm: "h-7 px-2.5 text-[13px] gap-1.5", md: "h-8 px-3 text-sm gap-2" } as const;

export function Button({ variant = "secondary", size = "md", className, ...p }: ComponentProps<"button"> & { variant?: Variant; size?: keyof typeof SIZE }) {
  return (
    <button
      {...p}
      className={cn("inline-flex items-center justify-center rounded-md font-medium whitespace-nowrap transition-colors disabled:opacity-50 disabled:pointer-events-none", VARIANT[variant], SIZE[size], className)}
    />
  );
}

export function ButtonLink({ variant = "secondary", size = "md", className, ...p }: ComponentProps<typeof Link> & { variant?: Variant; size?: keyof typeof SIZE }) {
  return <Link {...p} className={cn("inline-flex items-center justify-center rounded-md font-medium whitespace-nowrap transition-colors", VARIANT[variant], SIZE[size], className)} />;
}

// ---------------------------------------------------------------------------
// 심각도 — 색 막대 + 글자 라벨 (색만으로 의미를 전달하지 않는다)
// ---------------------------------------------------------------------------
export const SEV_BG: Record<Severity, string> = {
  critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low",
};

export function SeverityTag({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[13px] font-medium text-ink", className)}>
      <span aria-hidden className={cn("h-3 w-1.5 rounded-[2px]", SEV_BG[severity])} />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function StatusTag({ status, resolution }: { status: AlertStatus; resolution?: Resolution | null }) {
  const tone = status === "open" ? "border-line-strong text-ink" : status === "acknowledged" ? "border-accent/40 text-accent bg-accent-soft" : "border-transparent text-muted bg-surface-3";
  return (
    <span className={cn("inline-flex items-center rounded border px-1.5 py-px text-xs whitespace-nowrap", tone)}>
      {status === "closed" && resolution ? `종결 · ${RESOLUTION_LABEL[resolution]}` : STATUS_LABEL[status]}
    </span>
  );
}

const LIVE_DOT: Record<Liveness, string> = { online: "bg-ok", stale: "bg-warn", offline: "bg-off" };
export function LivenessTag({ state, withLabel = true }: { state: Liveness; withLabel?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[13px] text-ink-2 whitespace-nowrap">
      <span aria-hidden className={cn("size-2 rounded-full", LIVE_DOT[state])} />
      {withLabel ? LIVENESS_LABEL[state] : <span className="sr-only">{LIVENESS_LABEL[state]}</span>}
    </span>
  );
}

export function Verdict({ verdict }: { verdict: string | null | undefined }) {
  if (!verdict || verdict === "clean") return null;
  const map: Record<string, [string, string]> = {
    malicious: ["악성", "bg-sev-high text-surface"],
    suspicious: ["의심", "border border-sev-medium text-sev-high"],
    pending: ["조회 대기", "border border-line-strong text-muted"],
    unknown: ["평판 없음", "border border-line text-muted"],
    error: ["조회 실패", "border border-line text-muted"],
  };
  const [label, cls] = map[verdict] ?? [verdict, "border border-line text-muted"];
  return <span className={cn("inline-flex items-center rounded px-1.5 text-[11px] leading-[18px] font-medium whitespace-nowrap", cls)}>{label}</span>;
}

// ---------------------------------------------------------------------------
// 레이아웃 조각
// ---------------------------------------------------------------------------
export function PageHeader({ title, description, actions, children }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; children?: ReactNode }) {
  return (
    <header className="mb-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[22px] leading-8 font-semibold tracking-[-0.01em]">{title}</h1>
          {description && <p className="mt-0.5 text-ink-2">{description}</p>}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      {children}
    </header>
  );
}

export function Panel({ title, aside, children, className, bodyClassName, id }: { title?: ReactNode; aside?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string; id?: string }) {
  return (
    <section id={id} className={cn("rounded-lg border border-line bg-surface", className)}>
      {(title || aside) && (
        <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          {title && <h2 className="text-[15px] font-semibold">{title}</h2>}
          {aside && <div className="flex items-center gap-2 text-[13px] text-ink-2">{aside}</div>}
        </div>
      )}
      <div className={cn("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1.5 px-6 py-12 text-center">
      <p className="font-medium">{title}</p>
      {children && <p className="max-w-md text-[13px] text-ink-2">{children}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-line-strong bg-surface px-1 font-mono text-[11px] text-ink-2">{children}</kbd>;
}

export function Mono({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return <span title={title} className={cn("font-mono text-[12.5px]", className)}>{children}</span>;
}

export function Field({ label, children, suppressHydration }: { label: string; children: ReactNode; suppressHydration?: boolean }) {
  return (
    <div className="grid grid-cols-[7.5rem_1fr] gap-3 py-1.5 text-[13px]">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0" suppressHydrationWarning={suppressHydration}>{children}</dd>
    </div>
  );
}

export function Segmented<T extends string>({ items, value, hrefFor }: { items: { value: T; label: ReactNode }[]; value: T; hrefFor: (v: T) => string }) {
  return (
    <nav className="inline-flex rounded-md border border-line-strong bg-surface p-0.5">
      {items.map((it) => (
        <Link
          key={it.value}
          href={hrefFor(it.value)}
          scroll={false}
          aria-current={it.value === value ? "page" : undefined}
          className={cn("rounded px-2.5 py-1 text-[13px] whitespace-nowrap text-ink-2 hover:text-ink", it.value === value && "bg-accent-soft text-accent font-medium")}
        >
          {it.label}
        </Link>
      ))}
    </nav>
  );
}

/** 0~max 사이 값을 가로 막대로(표 안 미니 차트). 값 라벨은 항상 옆에 글자로 */
export function Meter({ value, max, warnAt, label }: { value: number | null | undefined; max: number; warnAt?: number; label: string }) {
  if (value == null) return <span className="text-muted">—</span>;
  const pct = Math.min(100, (value / max) * 100);
  const warn = warnAt != null && value >= warnAt;
  return (
    <span className="inline-flex items-center gap-2 tabular-nums">
      <span className="relative h-1.5 w-14 overflow-hidden rounded-full bg-surface-3" aria-hidden>
        <span className={cn("absolute inset-y-0 left-0 rounded-full", warn ? "bg-warn" : "bg-accent")} style={{ width: `${Math.max(pct, 3)}%` }} />
      </span>
      <span className={cn("text-[13px]", warn && "text-warn font-medium")}>{label}</span>
    </span>
  );
}

// ---------------------------------------------------------------------------
// 보안 상태 — 점검 결과(통과·주의·실패·확인 불가)와 보안 점수. 색 + 글자 라벨
// ---------------------------------------------------------------------------
export const POSTURE_LABEL: Record<PostureStatus, string> = { pass: "통과", warn: "주의", fail: "실패", unknown: "확인 불가" };
const POSTURE_DOT: Record<PostureStatus, string> = { pass: "bg-ok", warn: "bg-warn", fail: "bg-sev-high", unknown: "bg-off" };

export function PostureTag({ status, className }: { status: PostureStatus | null; className?: string }) {
  if (!status) return <span className={cn("text-[13px] text-muted", className)}>보고 전</span>;
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[13px] whitespace-nowrap", status === "fail" ? "font-medium text-ink" : "text-ink-2", className)}>
      <span aria-hidden className={cn("size-2 rounded-full", POSTURE_DOT[status])} />
      {POSTURE_LABEL[status]}
    </span>
  );
}

/** 보안 점수 0~100: 90 이상 양호 · 70 이상 보통 · 그 아래 취약 (라벨을 함께 보여 색에만 기대지 않는다) */
export function scoreBand(score: number | null | undefined): { label: string; tone: string; bar: string } {
  if (score == null) return { label: "판단 전", tone: "text-muted", bar: "bg-off" };
  if (score >= 90) return { label: "양호", tone: "text-ok", bar: "bg-ok" };
  if (score >= 70) return { label: "보통", tone: "text-warn", bar: "bg-warn" };
  return { label: "취약", tone: "text-sev-high", bar: "bg-sev-high" };
}

export function ScoreTag({ score, className }: { score: number | null | undefined; className?: string }) {
  const b = scoreBand(score);
  return (
    <span className={cn("inline-flex items-center gap-2 tabular-nums whitespace-nowrap", className)} title={`보안 점수 ${score ?? "—"} (${b.label})`}>
      <span className="relative h-1.5 w-12 overflow-hidden rounded-full bg-surface-3" aria-hidden>
        <span className={cn("absolute inset-y-0 left-0 rounded-full", b.bar)} style={{ width: `${Math.max(score ?? 0, 3)}%` }} />
      </span>
      <span className="text-[13px]"><span className="font-medium text-ink">{score ?? "—"}</span><span className={cn("ml-1 text-xs", b.tone)}>{b.label}</span></span>
    </span>
  );
}

/** 통과·주의·실패·확인 불가 개수를 한 줄 막대로 (2px 간격, 라벨은 옆 숫자로) */
export function PostureBar({ pass, warn, fail, unknown, className }: { pass: number; warn: number; fail: number; unknown: number; className?: string }) {
  const total = pass + warn + fail + unknown;
  if (!total) return <span className="text-[13px] text-muted">보고 전</span>;
  const seg = (n: number, cls: string, label: string) => n > 0 && (
    <span key={label} className={cn("h-full first:rounded-l-full last:rounded-r-full", cls)} style={{ width: `${(n / total) * 100}%`, minWidth: 3 }} title={`${label} ${n}대`} />
  );
  return (
    <span className={cn("flex h-2 w-full gap-[2px] overflow-hidden", className)} role="img" aria-label={`통과 ${pass}, 주의 ${warn}, 실패 ${fail}, 확인 불가 ${unknown}`}>
      {seg(pass, "bg-ok", "통과")}{seg(warn, "bg-warn", "주의")}{seg(fail, "bg-sev-high", "실패")}{seg(unknown, "bg-off", "확인 불가")}
    </span>
  );
}

/** 표 아래 페이지 넘김 */
export function Pager({ page, pages, hrefFor }: { page: number; pages: number; hrefFor: (p: number) => string }) {
  if (pages <= 1) return null;
  return (
    <div className="mt-3 flex items-center justify-end gap-1 text-[13px] text-ink-2">
      <Link href={hrefFor(page - 1)} aria-label="이전 페이지" className={cn("inline-flex h-7 items-center rounded-md px-2 hover:bg-surface-3", page <= 1 && "pointer-events-none opacity-40")}>이전</Link>
      <span className="tabular-nums">{page} / {pages}</span>
      <Link href={hrefFor(page + 1)} aria-label="다음 페이지" className={cn("inline-flex h-7 items-center rounded-md px-2 hover:bg-surface-3", page >= pages && "pointer-events-none opacity-40")}>다음</Link>
    </div>
  );
}

/** 위쪽 숫자 카드 줄 */
export function StatStrip({ items, label }: { items: { label: string; value: ReactNode; hint?: ReactNode; href?: string; tone?: "warn" | "bad" }[]; label: string }) {
  return (
    <section aria-label={label} className="mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-line bg-line sm:grid-cols-3 lg:grid-cols-6">
      {items.map((it) => {
        const body = (
          <>
            <div className="text-[12.5px] text-muted">{it.label}</div>
            <div className={cn("mt-0.5 text-[19px] font-semibold tabular-nums", it.tone === "warn" && "text-warn", it.tone === "bad" && "text-sev-high")}>{it.value}</div>
            {it.hint && <div className="truncate text-xs text-muted">{it.hint}</div>}
          </>
        );
        return it.href
          ? <Link key={it.label} href={it.href} className="bg-surface px-4 py-3 hover:bg-surface-2">{body}</Link>
          : <div key={it.label} className="bg-surface px-4 py-3">{body}</div>;
      })}
    </section>
  );
}
