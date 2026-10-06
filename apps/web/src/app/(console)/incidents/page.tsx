import Link from "next/link";
import { ChevronLeft, ChevronRight, Search } from "lucide-react";
import { KillChain } from "@/components/killchain";
import { Empty, PageHeader, SEV_BG, Segmented, SeverityTag, StatusTag } from "@/components/ui";
import { cn } from "@/lib/cn";
import { getContext } from "@/lib/context";
import type { IncidentFilter, Severity } from "@/lib/data/types";
import { SEVERITIES } from "@/lib/data/types";
import { SEVERITY_LABEL, ago, num, stamp } from "@/lib/format";
import { TACTIC_KO } from "@/lib/incident-summary";

export const metadata = { title: "인시던트" };

type SP = Promise<Record<string, string | undefined>>;

export default async function IncidentsPage({ searchParams }: { searchParams: SP }) {
  const sp = await searchParams;
  const f: IncidentFilter = {
    status: (["active", "open", "acknowledged", "closed", "all"].includes(sp.status ?? "") ? sp.status : "active") as IncidentFilter["status"],
    severity: (sp.severity ?? "").split(",").filter((s): s is Severity => SEVERITIES.includes(s as Severity)),
    q: sp.q?.trim() || undefined,
    days: Math.min(90, Math.max(1, Number(sp.days) || 30)),
    page: Math.max(1, Number(sp.page) || 1),
  };
  const { source, tenant } = await getContext();
  const [page, active] = await Promise.all([source.incidents(tenant, f), source.incidents(tenant, { status: "active", days: 90 })]);
  const bySev = SEVERITIES.map((s) => [s, active.rows.filter((i) => i.severity === s).length] as const);
  const qs = (patch: Record<string, string | null>) => {
    const p = new URLSearchParams(Object.entries({ status: f.status ?? "", severity: f.severity?.join(",") ?? "", q: f.q ?? "", days: String(f.days), page: String(f.page) }).filter(([, v]) => v));
    Object.entries(patch).forEach(([k, v]) => (v ? p.set(k, v) : p.delete(k)));
    return `/incidents?${p}`;
  };
  const pages = Math.max(1, Math.ceil(page.total / page.pageSize));
  const sevSet = new Set(f.severity);

  return (
    <>
      <PageHeader
        title="인시던트"
        description="관련 경보를 사건 단위로 자동으로 묶었습니다. 같은 PC 에서 2시간 안에 이어진 경보, 같은 IP·파일이 다른 PC 에서 다시 나온 경보가 한 사건이 됩니다."
      />

      <section className="mb-4 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-line bg-line sm:grid-cols-4" aria-label="미처리 인시던트">
        {bySev.map(([s, n]) => (
          <Link key={s} href={qs({ severity: sevSet.has(s) && sevSet.size === 1 ? null : s, page: null })}
            className={cn("bg-surface px-4 py-3 hover:bg-surface-2", sevSet.has(s) && "bg-accent-soft hover:bg-accent-soft")}>
            <div className="flex items-center gap-1.5 text-[13px] text-ink-2"><span aria-hidden className={cn("h-3 w-1.5 rounded-[2px]", SEV_BG[s])} />{SEVERITY_LABEL[s]} 미처리</div>
            <div className="mt-0.5 text-[26px] leading-9 font-semibold tabular-nums">{num(n)}</div>
          </Link>
        ))}
      </section>

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Segmented value={f.status ?? "active"} hrefFor={(v) => qs({ status: v === "active" ? null : v, page: null })}
          items={[{ value: "active", label: "미처리" }, { value: "open", label: "새 사건" }, { value: "acknowledged", label: "조사 중" }, { value: "closed", label: "종결" }, { value: "all", label: "전체" }]} />
        <form action="/incidents" className="flex h-8 min-w-60 items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2">
          <Search className="size-3.5 text-muted" aria-hidden />
          {f.status !== "active" && <input type="hidden" name="status" value={f.status} />}
          <input name="q" defaultValue={f.q} placeholder="제목·장치 검색" aria-label="인시던트 검색" className="w-full bg-transparent text-[13px] outline-none" />
        </form>
        <span className="ml-auto text-[13px] text-ink-2">{num(page.total)}건 · 최근 {f.days}일</span>
      </div>

      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        {page.rows.length === 0 ? (
          <Empty title="조건에 맞는 인시던트가 없습니다">{f.status === "active" ? "처리할 사건이 없습니다. 새 경보가 들어오면 자동으로 묶여 여기에 나타납니다." : "필터를 바꿔 보세요."}</Empty>
        ) : (
          <table className="w-full min-w-[1040px] text-left text-[14px]">
            <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
              <tr>
                <th className="w-[5.5rem] px-4 py-2 font-medium">심각도</th>
                <th className="px-3 py-2 font-medium">사건</th>
                <th className="px-3 py-2 font-medium">공격 단계</th>
                <th className="px-3 py-2 text-right font-medium">경보</th>
                <th className="px-3 py-2 font-medium">상태</th>
                <th className="px-4 py-2 text-right font-medium">마지막 활동</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {page.rows.map((i) => (
                <tr key={i.id} className={cn("group hover:bg-surface-2", i.severity === "critical" && i.status !== "closed" && "bg-sev-critical-wash/60")}>
                  <td className="relative px-4 py-3 align-top">
                    <span aria-hidden className={cn("absolute inset-y-0 left-0 w-[3px]", SEV_BG[i.severity], i.status === "closed" && "opacity-30")} />
                    <SeverityTag severity={i.severity} />
                  </td>
                  <td className="px-3 py-3 align-top">
                    <Link href={`/incidents/${i.id}`} className="font-medium group-hover:text-accent">{i.title}</Link>
                    <div className="mt-0.5 text-[13px] text-ink-2">
                      <span className="text-muted">INC-{i.id}</span>
                      <span className="ml-2">{(i.hostnames ?? []).slice(0, 3).join(", ")}{(i.hostnames?.length ?? 0) > 3 && ` 외 ${(i.hostnames?.length ?? 0) - 3}대`}</span>
                      {i.ips.length > 0 && <span className="ml-2 font-mono text-[12px]">{i.ips[0]}{i.ips.length > 1 && ` 외 ${i.ips.length - 1}`}</span>}
                    </div>
                  </td>
                  <td className="px-3 py-3 align-top">
                    <KillChain tactics={i.tactics} compact />
                    <div className="mt-1 max-w-[16rem] truncate text-xs text-muted">{i.tactics.map((t) => TACTIC_KO[t] ?? t).join(", ")}</div>
                  </td>
                  <td className="px-3 py-3 text-right align-top tabular-nums">{num(i.alert_count)}</td>
                  <td className="px-3 py-3 align-top"><StatusTag status={i.status} resolution={i.resolution} /></td>
                  <td className="px-4 py-3 text-right align-top text-[13px] whitespace-nowrap text-ink-2" title={`${stamp(i.first_seen_at)} 시작`}>{ago(i.last_seen_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {pages > 1 && (
        <div className="mt-3 flex items-center justify-end gap-1 text-[13px] text-ink-2">
          <Link href={qs({ page: String(f.page! - 1) })} aria-label="이전 페이지" className={cn("inline-flex size-7 items-center justify-center rounded-md hover:bg-surface-3", f.page! <= 1 && "pointer-events-none opacity-40")}><ChevronLeft className="size-4" /></Link>
          <span className="tabular-nums">{f.page} / {pages}</span>
          <Link href={qs({ page: String(f.page! + 1) })} aria-label="다음 페이지" className={cn("inline-flex size-7 items-center justify-center rounded-md hover:bg-surface-3", f.page! >= pages && "pointer-events-none opacity-40")}><ChevronRight className="size-4" /></Link>
        </div>
      )}
    </>
  );
}
