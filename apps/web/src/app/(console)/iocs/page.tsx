import Link from "next/link";
import { Download } from "lucide-react";
import { IocDelete, IocForm, IocToggle } from "@/components/asset-controls";
import { ButtonLink, Empty, Mono, PageHeader, Panel, Segmented, SeverityTag } from "@/components/ui";
import { cn } from "@/lib/cn";
import { canTriage, getContext } from "@/lib/context";
import type { Ioc } from "@/lib/data/types";
import { ago, fullDay, nowMs, num, stamp } from "@/lib/format";

export const metadata = { title: "위협 지표" };

type SP = Promise<Record<string, string | undefined>>;
type View = "active" | "all" | "hit";

export default async function IocsPage({ searchParams }: { searchParams: SP }) {
  const sp = await searchParams;
  const view = (["active", "all", "hit"].includes(sp.view ?? "") ? sp.view : "active") as View;
  const q = sp.q?.trim().toLowerCase() || "";
  const { source, viewer, tenant } = await getContext();
  const all = await source.iocs(tenant);
  const now = nowMs();
  const expired = (i: Ioc) => !!i.expires_at && Date.parse(i.expires_at) <= now;
  const live = (i: Ioc) => i.enabled && !expired(i);
  let rows = view === "active" ? all.filter(live) : view === "hit" ? all.filter((i) => i.hit_count > 0) : all;
  if (q) rows = rows.filter((i) => i.value.includes(q) || i.description.toLowerCase().includes(q) || (i.source ?? "").toLowerCase().includes(q));
  const triage = canTriage(viewer.tenant.role);
  // 해시·단일 IP 는 엔터티 프로필로, 대역은 그 지표의 경보 목록으로
  const alertsHref = (i: Ioc) => `/alerts?rule=${i.type === "sha256" ? "EDR-IOC-001" : "EDR-IOC-002"}&status=all&days=90${i.type === "ip" && !i.value.includes("/") ? `&q=${encodeURIComponent(i.value)}` : ""}`;
  const entityHref = (i: Ioc) => (i.type === "sha256" ? `/entities/hash/${i.value}` : i.value.includes("/") ? alertsHref(i) : `/entities/ip/${i.value}`);

  return (
    <>
      <PageHeader
        title="위협 지표"
        description="보안 공지·사내 분석에서 나온 악성 파일 해시와 공격 IP 를 등록하면, 모든 PC 의 실행 기록·통신·로그온 시도와 맞춰 봅니다."
        actions={<ButtonLink href="/api/export/iocs" prefetch={false}><Download className="size-4" aria-hidden />CSV 내려받기</ButtonLink>}
      >
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <Segmented value={view} hrefFor={(v) => `/iocs?view=${v}${q ? `&q=${encodeURIComponent(q)}` : ""}`} items={[
            { value: "active", label: `사용 중 ${num(all.filter(live).length)}` },
            { value: "hit", label: `발견된 지표 ${num(all.filter((i) => i.hit_count > 0).length)}` },
            { value: "all", label: `전체 ${num(all.length)}` },
          ]} />
          <form action="/iocs" className="ml-auto flex h-8 min-w-60 items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2">
            <input type="hidden" name="view" value={view} />
            <input name="q" defaultValue={q} placeholder="값·설명·출처 검색" aria-label="위협 지표 검색" className="w-full bg-transparent text-[13px] outline-none" />
          </form>
        </div>
      </PageHeader>

      {triage && (
        <Panel className="mb-5" title="지표 등록">
          <IocForm />
        </Panel>
      )}

      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        {rows.length === 0 ? (
          <Empty title={all.length === 0 ? "등록한 위협 지표가 없습니다" : "조건에 맞는 지표가 없습니다"}>
            {all.length === 0 ? "보안 공지(KISA 등)나 사고 분석에서 얻은 SHA-256 해시·IP 를 위에서 등록하세요." : undefined}
          </Empty>
        ) : (
          <table className="w-full min-w-[1000px] text-left text-[13.5px]">
            <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">지표</th>
                <th className="px-3 py-2 font-medium">심각도</th>
                <th className="px-3 py-2 font-medium">설명 · 출처</th>
                <th className="px-3 py-2 text-right font-medium">발견</th>
                <th className="px-3 py-2 font-medium">만료</th>
                <th className="px-3 py-2 font-medium">등록</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((i) => (
                <tr key={i.id} className={cn("hover:bg-surface-2", !live(i) && "text-ink-2")}>
                  <td className="max-w-[22rem] px-4 py-2.5">
                    <span className="mr-2 rounded bg-surface-3 px-1.5 text-[11px] text-ink-2">{i.type === "sha256" ? "해시" : i.value.includes("/") ? "대역" : "IP"}</span>
                    <Link href={entityHref(i)} className="hover:text-accent"><Mono className="break-all">{i.value}</Mono></Link>
                  </td>
                  <td className="px-3 py-2.5"><SeverityTag severity={i.severity} /></td>
                  <td className="px-3 py-2.5">
                    <div>{i.description || <span className="text-muted">—</span>}</div>
                    {i.source && <div className="text-xs text-muted">{i.source}</div>}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular-nums">
                    {i.hit_count > 0 ? (
                      <Link href={alertsHref(i)}
                        className="font-medium text-sev-high hover:underline" title={`마지막 발견 ${stamp(i.last_hit_at)}`}>
                        {num(i.hit_count)}건 · {ago(i.last_hit_at)}
                      </Link>
                    ) : <span className="text-muted">없음</span>}
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    {i.expires_at ? <span className={expired(i) ? "text-muted line-through" : ""} title={stamp(i.expires_at)}>{fullDay(i.expires_at)}</span> : <span className="text-muted">기한 없음</span>}
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap text-ink-2"><span title={stamp(i.created_at)}>{ago(i.created_at)}</span>{i.created_by_email && <div className="text-xs text-muted">{i.created_by_email}</div>}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center justify-end gap-3">
                      <IocToggle id={i.id} enabled={i.enabled} disabled={!triage} value={i.value} />
                      {triage && <IocDelete id={i.id} value={i.value} />}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <p className="mt-3 text-xs text-muted">
        해시는 실행된 프로그램·자동 실행 항목과, IP·대역은 PC 의 통신 상대·로그온 시도 출발지와 맞춥니다. 맞으면 경보(EDR-IOC-001·002)가 생기고 인시던트로 묶입니다.
        에이전트는 차단하지 않습니다 — 차단은 방화벽·백신에서 하세요.
      </p>
    </>
  );
}
