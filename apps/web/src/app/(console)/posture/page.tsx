import Link from "next/link";
import { BellRing, Download, X } from "lucide-react";
import { PostureCheckToggle } from "@/components/asset-controls";
import { ButtonLink, Empty, PageHeader, Pager, Panel, POSTURE_LABEL, PostureBar, PostureTag, ScoreTag, Segmented, scoreBand } from "@/components/ui";
import { cn } from "@/lib/cn";
import { canAdmin, getContext } from "@/lib/context";
import type { PostureStatus } from "@/lib/data/types";
import { ago, num, stamp } from "@/lib/format";

export const metadata = { title: "보안 상태" };

type SP = Promise<Record<string, string | undefined>>;
const STATUSES: PostureStatus[] = ["fail", "warn", "unknown", "pass"];
const BUCKETS = [
  { label: "취약", range: "50점 미만", bar: "bg-sev-high" },
  { label: "보통 이하", range: "50~69점", bar: "bg-sev-medium" },
  { label: "보통", range: "70~89점", bar: "bg-warn" },
  { label: "양호", range: "90점 이상", bar: "bg-ok" },
];

export default async function PosturePage({ searchParams }: { searchParams: SP }) {
  const sp = await searchParams;
  const { source, viewer, tenant } = await getContext();
  const ov = await source.postureOverview(tenant);
  const admin = canAdmin(viewer.tenant.role);
  const check = ov.checks.find((c) => c.check_id === sp.check);
  const status = (STATUSES.includes(sp.status as PostureStatus) ? sp.status : "fail") as PostureStatus;
  const page = Math.max(1, Number(sp.page) || 1);
  const list = check ? await source.postureDevices(tenant, { check: check.check_id, status, page }) : null;
  const band = scoreBand(ov.score);
  const enabledCount = ov.checks.filter((c) => c.enabled).length;
  const maxBucket = Math.max(1, ...ov.buckets);
  const categories = [...new Set(ov.checks.map((c) => c.category))];

  return (
    <>
      <PageHeader
        title="보안 상태"
        description="PC 마다 보안 설정을 점검해 점수로 보여 줍니다. 에이전트는 설정을 읽기만 하고 바꾸지 않습니다. 고치는 방법은 항목마다 안내합니다."
        actions={<ButtonLink href="/api/export/posture" prefetch={false}><Download className="size-4" aria-hidden />CSV 내려받기</ButtonLink>}
      />

      <section className="mb-5 grid gap-4 lg:grid-cols-[minmax(0,15rem)_minmax(0,1fr)_minmax(0,1.2fr)]" aria-label="보안 점수 요약">
        <div className="rounded-lg border border-line bg-surface p-4">
          <div className="text-[13px] text-muted">전체 보안 점수</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-[44px] leading-none font-semibold tabular-nums">{ov.score ?? "—"}</span>
            <span className={cn("text-[15px] font-medium", band.tone)}>{band.label}</span>
          </div>
          <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface-3" aria-hidden>
            <div className={cn("h-full rounded-full", band.bar)} style={{ width: `${ov.score ?? 0}%` }} />
          </div>
          <p className="mt-3 text-xs text-ink-2">
            장치 {num(ov.scored)} / {num(ov.devices)}대 평균. 점수에 넣은 {enabledCount}개 항목의 가중치 중 통과한 비율입니다.
          </p>
        </div>

        <Panel title="점수 분포" bodyClassName="px-4 py-3">
          <ul className="space-y-2.5">
            {BUCKETS.map((b, i) => (
              <li key={b.label} className="grid grid-cols-[5.5rem_minmax(0,1fr)_3rem] items-center gap-3 text-[13px]">
                <span><span className="font-medium">{b.label}</span><span className="block text-xs text-muted">{b.range}</span></span>
                <span className="h-2.5 overflow-hidden rounded-full bg-surface-3" aria-hidden>
                  <span className={cn("block h-full rounded-full", b.bar)} style={{ width: `${(ov.buckets[i]! / maxBucket) * 100}%` }} />
                </span>
                <span className="text-right tabular-nums">{num(ov.buckets[i])}대</span>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="점수가 낮은 장치" bodyClassName="p-0">
          {ov.worst.length === 0 ? <Empty title="점검 결과가 아직 없습니다">에이전트가 처음 점검 결과를 보내면(설치 후 1분 안팎) 표시됩니다.</Empty> : (
            <ul className="divide-y divide-line">
              {ov.worst.slice(0, 5).map((w) => (
                <li key={w.device_id} className="grid grid-cols-[minmax(0,8rem)_auto_minmax(0,1fr)] items-center gap-3 px-4 py-2 text-[13px]">
                  <Link href={`/devices/${w.device_id}?tab=posture`} className="truncate font-medium hover:text-accent">{w.hostname}</Link>
                  <ScoreTag score={w.score} />
                  <span className="truncate text-xs text-ink-2" title={w.fails.join(", ")}>{w.fails.join(" · ") || "실패 항목 없음"}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </section>

      {check && list && (
        <Panel className="mb-5" bodyClassName="p-0" id="devices"
          title={<span>{check.title} <span className="ml-1 text-[13px] font-normal text-muted">{POSTURE_LABEL[status]} {num(list.total)}대</span></span>}
          aside={<Link href="/posture" className="inline-flex items-center gap-1 hover:text-ink"><X className="size-3.5" aria-hidden />닫기</Link>}>
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
            <Segmented value={status} hrefFor={(v) => `/posture?check=${check.check_id}&status=${v}#devices`} items={STATUSES.map((s) => ({
              value: s, label: `${POSTURE_LABEL[s]} ${num(check[s])}`,
            }))} />
            <p className="max-w-2xl text-[13px] text-ink-2 [overflow-wrap:anywhere]"><span className="font-medium text-ink">고치는 방법</span> {check.remediation}</p>
          </div>
          {list.rows.length === 0 ? <Empty title={`${POSTURE_LABEL[status]} 상태인 장치가 없습니다`} /> : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-[13.5px]">
                <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
                  <tr><th className="px-4 py-2 font-medium">장치</th><th className="px-3 py-2 font-medium">보안 점수</th><th className="px-3 py-2 font-medium">점검 내용</th><th className="px-4 py-2 text-right font-medium">확인</th></tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {list.rows.map((r) => (
                    <tr key={r.device_id} className="hover:bg-surface-2">
                      <td className="px-4 py-2"><Link href={`/devices/${r.device_id}?tab=posture`} className="font-medium hover:text-accent">{r.hostname}</Link></td>
                      <td className="px-3 py-2"><ScoreTag score={r.score} /></td>
                      <td className="px-3 py-2 text-ink-2">{r.detail ?? "—"}</td>
                      <td className="px-4 py-2 text-right whitespace-nowrap text-ink-2" title={stamp(r.checked_at)}>{ago(r.checked_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="px-4 pb-3"><Pager page={page} pages={Math.max(1, Math.ceil(list.total / list.pageSize))} hrefFor={(p) => `/posture?check=${check.check_id}&status=${status}&page=${p}#devices`} /></div>
        </Panel>
      )}

      <div className="space-y-4">
        {categories.map((cat) => (
          <Panel key={cat} title={cat} bodyClassName="p-0"
            aside={cat === categories[0] ? <span className="hidden sm:inline">항목을 누르면 해당 장치 목록 · 점수 반영은 관리자가 정합니다</span> : undefined}>
            <ul className="divide-y divide-line">
              {ov.checks.filter((c) => c.category === cat).map((c) => {
                const total = c.pass + c.warn + c.fail + c.unknown;
                return (
                  <li key={c.check_id} className={cn("grid items-center gap-x-5 gap-y-2 px-4 py-3 md:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)_auto]", !c.enabled && "opacity-70")}>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Link href={`/posture?check=${c.check_id}&status=${c.fail ? "fail" : c.warn ? "warn" : "pass"}#devices`} className="font-medium hover:text-accent">{c.title}</Link>
                        <span className="text-xs text-muted">가중치 {c.weight}</span>
                        {c.drift_alert && <span className="inline-flex items-center gap-1 text-xs text-ink-2" title="통과하던 PC 에서 실패로 바뀌면 경보(EDR-POS-001)"><BellRing className="size-3" aria-hidden />꺼지면 경보</span>}
                        {c.source === "server" && <span className="text-xs text-muted">서버 판단</span>}
                      </div>
                      <p className="text-[13px] text-ink-2">{c.description}</p>
                    </div>
                    <div className="min-w-0">
                      <PostureBar pass={c.pass} warn={c.warn} fail={c.fail} unknown={c.unknown} />
                      <div className="mt-1 flex flex-wrap gap-x-3 text-xs text-ink-2 tabular-nums">
                        {total === 0 ? <span className="text-muted">보고 전</span> : (
                          <>
                            {c.fail > 0 && <Link href={`/posture?check=${c.check_id}&status=fail#devices`} className="font-medium text-ink hover:text-accent">실패 {num(c.fail)}대</Link>}
                            {c.warn > 0 && <Link href={`/posture?check=${c.check_id}&status=warn#devices`} className="hover:text-accent">주의 {num(c.warn)}</Link>}
                            <span>통과 {num(c.pass)}</span>
                            {c.unknown > 0 && <Link href={`/posture?check=${c.check_id}&status=unknown#devices`} className="hover:text-accent">확인 불가 {num(c.unknown)}</Link>}
                          </>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-3 md:justify-end">
                      <PostureTag status={total === 0 ? null : c.fail > 0 ? "fail" : c.warn > 0 ? "warn" : c.pass > 0 ? "pass" : "unknown"} className="md:hidden" />
                      <PostureCheckToggle checkId={c.check_id} enabled={c.enabled} disabled={!admin} title={c.title} />
                    </div>
                  </li>
                );
              })}
            </ul>
          </Panel>
        ))}
      </div>
    </>
  );
}
