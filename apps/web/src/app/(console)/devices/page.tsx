import Link from "next/link";
import { ChevronLeft, ChevronRight, Search } from "lucide-react";
import { Empty, LivenessTag, Meter, Mono, PageHeader, Segmented } from "@/components/ui";
import { cn } from "@/lib/cn";
import { getContext } from "@/lib/context";
import type { DeviceSort, DeviceState } from "@/lib/data/source";
import { ago, liveness, num, stamp, winName } from "@/lib/format";

export const metadata = { title: "장치" };

type SP = Promise<Record<string, string | undefined>>;
const STATES: DeviceState[] = ["all", "online", "stale", "offline"];
const SORTS: { value: DeviceSort; label: string }[] = [
  { value: "hostname", label: "이름순" },
  { value: "alerts", label: "미처리 경보 많은 순" },
  { value: "cpu", label: "에이전트 CPU 높은 순" },
  { value: "memory", label: "에이전트 메모리 높은 순" },
  { value: "last_seen", label: "오래 응답 없는 순" },
];

export default async function DevicesPage({ searchParams }: { searchParams: SP }) {
  const sp = await searchParams;
  const state = (STATES.includes(sp.state as DeviceState) ? sp.state : "all") as DeviceState;
  const sort = (SORTS.some((s) => s.value === sp.sort) ? sp.sort : "hostname") as DeviceSort;
  const page = Math.max(1, Number(sp.page) || 1);
  const q = sp.q?.trim() || undefined;
  const { source, tenant } = await getContext();
  const [list, ov] = await Promise.all([source.devices(tenant, { q, state, sort, page }), source.overview(tenant)]);
  const latest = list.rows.map((d) => d.agent_version).filter(Boolean).sort().at(-1);
  const qs = (patch: Record<string, string | null>) => {
    const p = new URLSearchParams(Object.entries({ state, sort, q: q ?? "", page: String(page) }).filter(([, v]) => v));
    Object.entries(patch).forEach(([k, v]) => (v ? p.set(k, v) : p.delete(k)));
    return `/devices?${p}`;
  };
  const pages = Math.max(1, Math.ceil(list.total / list.pageSize));
  const d = ov.devices;

  return (
    <>
      <PageHeader title="장치" description="에이전트가 설치된 PC·서버와 에이전트 자신의 자원 사용량입니다.">
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <Segmented
            value={state}
            hrefFor={(v) => qs({ state: v === "all" ? null : v, page: null })}
            items={[
              { value: "all", label: `전체 ${num(d.total)}` },
              { value: "online", label: `연결됨 ${num(d.online)}` },
              { value: "stale", label: `응답 지연 ${num(d.stale)}` },
              { value: "offline", label: `연결 끊김 ${num(d.offline)}` },
            ]}
          />
          <form action="/devices" className="flex h-8 min-w-56 items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2">
            <Search className="size-3.5 text-muted" aria-hidden />
            {state !== "all" && <input type="hidden" name="state" value={state} />}
            <input type="hidden" name="sort" value={sort} />
            <input name="q" defaultValue={q} placeholder="이름·IP 검색" aria-label="장치 검색" className="w-full bg-transparent text-[13px] outline-none" />
          </form>
          <nav className="ml-auto flex flex-wrap gap-1 text-[13px]" aria-label="정렬">
            {SORTS.map((s) => (
              <Link key={s.value} href={qs({ sort: s.value, page: null })} aria-current={s.value === sort ? "true" : undefined}
                className={cn("rounded px-2 py-1 text-ink-2 hover:text-ink", s.value === sort && "bg-surface-3 font-medium text-ink")}>{s.label}</Link>
            ))}
          </nav>
        </div>
      </PageHeader>

      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        {list.rows.length === 0 ? (
          <Empty title={q ? `‘${q}’ 와 일치하는 장치가 없습니다` : "이 조건의 장치가 없습니다"}>
            새 PC 를 등록하려면 설정에서 등록키를 만들고 에이전트를 설치하세요.
          </Empty>
        ) : (
          <table className="w-full min-w-[960px] text-left text-[14px]">
            <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">장치</th>
                <th className="px-3 py-2 font-medium">상태</th>
                <th className="px-3 py-2 font-medium">IP</th>
                <th className="px-3 py-2 font-medium">운영체제</th>
                <th className="px-3 py-2 font-medium">에이전트</th>
                <th className="px-3 py-2 font-medium">에이전트 CPU</th>
                <th className="px-3 py-2 font-medium">에이전트 메모리</th>
                <th className="px-3 py-2 text-right font-medium">미처리 경보</th>
                <th className="px-4 py-2 text-right font-medium">마지막 수신</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {list.rows.map((dv) => {
                const h = dv.health;
                const spool = h && h.spool_files > 0;
                return (
                  <tr key={dv.id} className="hover:bg-surface-2">
                    <td className="px-4 py-2.5">
                      <Link href={`/devices/${dv.id}`} className="font-medium hover:text-accent">{dv.hostname}</Link>
                      {dv.tags.length > 0 && <span className="ml-2 text-xs text-muted">{dv.tags.join(", ")}</span>}
                    </td>
                    <td className="px-3 py-2.5"><LivenessTag state={liveness(dv.last_seen_at)} /></td>
                    <td className="px-3 py-2.5"><Mono>{dv.last_ip ?? "—"}</Mono></td>
                    <td className="px-3 py-2.5 text-ink-2">{winName(dv.os_version)}</td>
                    <td className="px-3 py-2.5">
                      <span className={cn("tabular-nums", latest && dv.agent_version !== latest && "text-warn")} title={latest && dv.agent_version !== latest ? `최신 ${latest} 아님` : undefined}>{dv.agent_version ?? "—"}</span>
                      {spool && <span className="ml-2 text-xs text-warn" title="서버로 못 보낸 배치가 쌓여 있음">전송 대기 {h!.spool_files}</span>}
                    </td>
                    <td className="px-3 py-2.5"><Meter value={h?.cpu_percent} max={3} warnAt={2} label={h ? `${h.cpu_percent}%` : "—"} /></td>
                    <td className="px-3 py-2.5"><Meter value={h?.working_set_mb} max={150} warnAt={120} label={h ? `${h.working_set_mb}MB` : "—"} /></td>
                    <td className="px-3 py-2.5 text-right tabular-nums">
                      {dv.open_alerts ? <Link href={`/alerts?device=${dv.id}`} className="font-medium hover:text-accent">{dv.open_alerts}</Link> : <span className="text-muted">0</span>}
                    </td>
                    <td className="px-4 py-2.5 text-right text-ink-2 whitespace-nowrap" title={stamp(dv.last_seen_at)}>{ago(dv.last_seen_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      {pages > 1 && (
        <div className="mt-3 flex items-center justify-end gap-1 text-[13px] text-ink-2">
          <Link href={qs({ page: String(page - 1) })} aria-label="이전 페이지" className={cn("inline-flex size-7 items-center justify-center rounded-md hover:bg-surface-3", page <= 1 && "pointer-events-none opacity-40")}><ChevronLeft className="size-4" /></Link>
          <span className="tabular-nums">{page} / {pages}</span>
          <Link href={qs({ page: String(page + 1) })} aria-label="다음 페이지" className={cn("inline-flex size-7 items-center justify-center rounded-md hover:bg-surface-3", page >= pages && "pointer-events-none opacity-40")}><ChevronRight className="size-4" /></Link>
        </div>
      )}
    </>
  );
}
