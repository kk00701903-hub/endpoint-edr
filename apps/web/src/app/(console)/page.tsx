import Link from "next/link";
import { CpuHistogram } from "@/components/charts/static";
import { Swimlane } from "@/components/charts/swimlane";
import { AlertTrend, LogonFailures } from "@/components/charts/trend";
import { KillChain, STAGES } from "@/components/killchain";
import { Empty, Panel, PostureBar, SEV_BG, SeverityTag, StatusTag, scoreBand } from "@/components/ui";
import { cn } from "@/lib/cn";
import { getContext } from "@/lib/context";
import { SEVERITIES } from "@/lib/data/types";
import { SEVERITY_LABEL, ago, nowMs, num } from "@/lib/format";
import { TACTIC_KO } from "@/lib/incident-summary";

export const metadata = { title: "현황" };

export default async function OverviewPage() {
  const { source, tenant, viewer } = await getContext();
  const [ov, lane, trend, logons, incs, matrix, posture, assets, exposure] = await Promise.all([
    source.overview(tenant),
    source.alertsSince(tenant, 24),
    source.alertTrend(tenant, 14),
    source.logonFailures(tenant, 24),
    source.incidents(tenant, { status: "active", days: 90 }),
    source.attackMatrix(tenant, 30),
    source.postureOverview(tenant),
    source.assetOverview(tenant),
    source.softwareExposure(tenant),
  ]);
  const band = scoreBand(posture.score);
  const topFails = posture.checks.filter((c) => c.enabled && c.fail > 0).sort((a, b) => b.fail * b.weight - a.fail * a.weight).slice(0, 3);
  const vulnDevices = new Set(exposure.filter((e) => e.enabled && e.kind === "vulnerable").flatMap((e) => e.device_ids)).size;
  const bannedDevices = new Set(exposure.filter((e) => e.enabled && e.kind === "prohibited").flatMap((e) => e.device_ids)).size;
  const d = ov.devices;
  const rank = (s: string) => SEVERITIES.indexOf(s as (typeof SEVERITIES)[number]);
  const queue = [...incs.rows].sort((a, b) => rank(a.severity) - rank(b.severity) || b.last_seen_at.localeCompare(a.last_seen_at)).slice(0, 6);
  const incBySev = SEVERITIES.map((s) => [s, incs.rows.filter((i) => i.severity === s).length] as const);
  const highAlerts = (ov.open_alerts.critical ?? 0) + (ov.open_alerts.high ?? 0);
  const tacticHits = STAGES.map((t) => [t, matrix.filter((m) => m.tactic === t).reduce((s, m) => s + Number(m.hits), 0)] as const);
  const tMax = Math.max(1, ...tacticHits.map(([, n]) => n));
  const onlinePct = d.total ? Math.round((d.online / d.total) * 100) : 0;
  const critical = incBySev[0]![1];

  return (
    <>
      <header className="mb-5">
        <p className="text-[13px] text-ink-2">{viewer.tenant.name} 보안 현황</p>
        <h1 className="mt-0.5 text-[24px] leading-8 font-semibold tracking-[-0.01em]">
          {incs.total === 0 ? "처리할 인시던트가 없습니다" : `처리할 인시던트 ${num(incs.total)}건`}
          {critical > 0 && `, 그중 긴급 ${critical}건`}
        </h1>
      </header>

      <section className="mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-line bg-line lg:grid-cols-5" aria-label="핵심 지표">
        <Link href="/incidents" className="col-span-2 bg-surface px-4 py-3 hover:bg-surface-2 lg:col-span-1">
          <div className="text-[13px] text-ink-2">미처리 인시던트</div>
          <div className="mt-0.5 text-[28px] leading-9 font-semibold tabular-nums">{num(incs.total)}</div>
          <div className="mt-1 flex h-1.5 gap-[2px] overflow-hidden rounded-full bg-surface-3" aria-hidden>
            {incs.total > 0 && incBySev.map(([s, n]) => n > 0 && <span key={s} className={SEV_BG[s]} style={{ width: `${(n / incs.total) * 100}%` }} />)}
          </div>
          <div className="mt-1 text-xs text-muted">{incBySev.filter(([, n]) => n).map(([s, n]) => `${SEVERITY_LABEL[s]} ${n}`).join(", ") || "없음"}</div>
        </Link>
        <Kpi href="/alerts?severity=critical,high" label="긴급·높음 경보" value={num(highAlerts)} hint={`24시간 새 경보 ${num(ov.alerts_24h)}건 (전날 ${num(ov.alerts_prev_24h)})`} tone={highAlerts > 0 ? "alert" : undefined} />
        <Kpi href="/incidents?status=closed" label="평균 처리 시간" value={ov.mttr_minutes != null ? `${num(ov.mttr_minutes)}분` : "—"} hint="최근 30일 종결 경보 기준" />
        <Kpi href="/devices" label="장치 연결" value={`${onlinePct}%`} hint={`${num(d.online)} / ${num(d.total)}대, 끊김 ${num(d.offline)}`} tone={onlinePct < 90 ? "warn" : undefined} />
        <Kpi href="/devices?sort=cpu" label="에이전트 평균 CPU" value={d.avg_cpu != null ? `${d.avg_cpu}%` : "—"} hint={`최대 ${d.max_cpu ?? "—"}%, 평균 메모리 ${d.avg_mem ?? "—"}MB`} tone={(d.avg_cpu ?? 0) >= 1 ? "warn" : undefined} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <Panel title="우선 처리할 인시던트" bodyClassName="p-0" aside={<Link href="/incidents" className="text-accent hover:underline">전체 보기</Link>}>
          {queue.length === 0 ? <Empty title="처리할 인시던트가 없습니다">새 경보가 들어오면 관련 경보끼리 묶여 여기에 나타납니다.</Empty> : (
            <ul className="divide-y divide-line">
              {queue.map((i) => (
                <li key={i.id}>
                  <Link href={`/incidents/${i.id}`} className={cn("relative grid grid-cols-[4.75rem_minmax(0,1fr)_auto] items-center gap-3 py-3 pr-4 pl-4 hover:bg-surface-2", i.severity === "critical" && "bg-sev-critical-wash/60")}>
                    <span aria-hidden className={cn("absolute inset-y-0 left-0 w-[3px]", SEV_BG[i.severity])} />
                    <SeverityTag severity={i.severity} />
                    <span className="min-w-0">
                      <span className="block truncate font-medium">{i.title}</span>
                      <span className="mt-0.5 flex items-center gap-3 text-[13px] text-ink-2">
                        <KillChain tactics={i.tactics} compact />
                        <span className="truncate">{(i.hostnames ?? []).slice(0, 2).join(", ")}{(i.hostnames?.length ?? 0) > 2 && ` 외 ${(i.hostnames?.length ?? 0) - 2}대`}, 경보 {i.alert_count}건</span>
                      </span>
                    </span>
                    <span className="flex flex-col items-end gap-1">
                      <span className="text-xs whitespace-nowrap text-muted">{ago(i.last_seen_at)}</span>
                      <StatusTag status={i.status} resolution={i.resolution} />
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="관측된 공격 단계" aside={<Link href="/attack" className="text-accent hover:underline">ATT&CK 매트릭스</Link>}>
          <ol className="space-y-1.5" aria-label="최근 30일 전술별 경보 수">
            {tacticHits.map(([t, n]) => (
              <li key={t} className="grid grid-cols-[6.5rem_1fr_2.5rem] items-center gap-3 text-[13px]">
                <span className={n ? "text-ink" : "text-muted"}>{TACTIC_KO[t]}</span>
                <span className="h-2.5 rounded-sm bg-surface-2">
                  {n > 0 && <span className="block h-full rounded-sm bg-heat-3" style={{ width: `${Math.max(4, (n / tMax) * 100)}%` }} />}
                </span>
                <span className="text-right tabular-nums text-ink-2">{n || ""}</span>
              </li>
            ))}
          </ol>
          <p className="mt-3 text-xs text-muted">최근 30일 경보를 MITRE ATT&CK 전술로 나눈 수</p>
        </Panel>
      </div>

      <Panel className="mt-5" title="지난 24시간 관제 레인" aside={<span>점 하나가 경보 하나, 눌러서 열기</span>}>
        {lane.length ? <Swimlane now={nowMs()} points={lane.map(({ id, created_at, severity, title, hostname }) => ({ id, created_at, severity, title, hostname: hostname ?? null }))} /> :
          <Empty title="지난 24시간 동안 경보가 없습니다" />}
      </Panel>

      <Panel className="mt-5" title="보안 위생" bodyClassName="p-0" aside={<span>경보가 되기 전에 고칠 것</span>}>
        <div className="grid gap-px bg-line sm:grid-cols-2 xl:grid-cols-[minmax(0,1.4fr)_repeat(3,minmax(0,1fr))]">
          <Link href="/posture" className="bg-surface px-4 py-3 hover:bg-surface-2">
            <div className="text-[13px] text-ink-2">보안 점수</div>
            <div className="mt-0.5 flex items-baseline gap-2"><span className="text-[28px] leading-9 font-semibold tabular-nums">{posture.score ?? "—"}</span><span className={cn("text-[13px] font-medium", band.tone)}>{band.label}</span></div>
            <ul className="mt-1 space-y-1">
              {topFails.length === 0 ? <li className="text-xs text-muted">점수에 넣은 항목 모두 통과</li> : topFails.map((c) => (
                <li key={c.check_id} className="grid grid-cols-[minmax(0,1fr)_5rem_3.5rem] items-center gap-2 text-xs">
                  <span className="truncate text-ink-2">{c.title}</span>
                  <PostureBar pass={c.pass} warn={c.warn} fail={c.fail} unknown={c.unknown} />
                  <span className="text-right tabular-nums">실패 {num(c.fail)}</span>
                </li>
              ))}
            </ul>
          </Link>
          <HygieneCell href="/assets?tab=devices&filter=unsupported" label="지원 종료 Windows" value={assets.unsupported} hint={assets.ending_90d ? `90일 안에 ${num(assets.ending_90d)}대 더` : "보안 업데이트 없는 PC"} />
          <HygieneCell href="/assets?tab=exposure" label="취약 소프트웨어가 있는 PC" value={vulnDevices} hint="알려진 취약 버전·지원 종료 제품" />
          <HygieneCell href="/assets?tab=exposure" label="금지 소프트웨어가 있는 PC" value={bannedDevices} hint="회사 지침 위반" />
        </div>
      </Panel>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Panel title="경보 추이" aside={<span>최근 14일</span>}><AlertTrend points={trend} days={14} /></Panel>
        <Panel title="로그온 실패" aside={<span>최근 24시간, 합계 {num(ov.failed_logons_24h)}회</span>}><LogonFailures points={logons} /></Panel>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Panel title="에이전트 부하" aside={<span>PC 별 에이전트 CPU 분포</span>}>
          <CpuHistogram counts={d.cpu_buckets} />
          <p className="mt-3 text-xs text-muted">기존 보안 솔루션과 함께 돌면서 자원을 얼마나 쓰는지 보여 줍니다. 2% 이상인 PC 는 장치 화면에서 원인을 확인하세요.</p>
        </Panel>
        <Panel title="경보가 몰린 장치" bodyClassName="p-0" aside={<span>최근 7일, 미처리</span>}>
          {ov.top_devices.length === 0 ? <Empty title="미처리 경보가 있는 장치가 없습니다" /> : (
            <ol className="divide-y divide-line">
              {ov.top_devices.map((r) => {
                const max = Math.max(...ov.top_devices.map((x) => x.n));
                return (
                  <li key={r.id}>
                    <Link href={`/devices/${r.id}`} className="grid grid-cols-[minmax(0,1fr)_7rem_2.5rem] items-center gap-3 px-4 py-2.5 hover:bg-surface-2">
                      <span className="min-w-0"><span className="block truncate font-medium">{r.hostname}</span><span className="block text-[13px] text-ink-2">{r.high ? `긴급·높음 ${r.high}건 포함` : "보통·낮음만"}</span></span>
                      <span className="h-1.5 rounded-full bg-surface-3" aria-hidden><span className="block h-full rounded-full bg-accent" style={{ width: `${(r.n / max) * 100}%` }} /></span>
                      <span className="text-right tabular-nums">{num(r.n)}</span>
                    </Link>
                  </li>
                );
              })}
            </ol>
          )}
        </Panel>
      </div>
    </>
  );
}

function Kpi({ href, label, value, hint, tone }: { href: string; label: string; value: string; hint: string; tone?: "alert" | "warn" }) {
  return (
    <Link href={href} className="bg-surface px-4 py-3 hover:bg-surface-2">
      <div className="text-[13px] text-ink-2">{label}</div>
      <div className={cn("mt-0.5 text-[28px] leading-9 font-semibold tabular-nums", tone === "alert" && "text-sev-high", tone === "warn" && "text-warn")}>{value}</div>
      <div className="mt-1 truncate text-xs text-muted">{hint}</div>
    </Link>
  );
}

function HygieneCell({ href, label, value, hint }: { href: string; label: string; value: number; hint: string }) {
  return (
    <Link href={href} className="bg-surface px-4 py-3 hover:bg-surface-2">
      <div className="text-[13px] text-ink-2">{label}</div>
      <div className={cn("mt-0.5 text-[28px] leading-9 font-semibold tabular-nums", value > 0 && "text-sev-high")}>{num(value)}<span className="ml-1 text-[13px] font-normal text-ink-2">대</span></div>
      <div className="mt-1 truncate text-xs text-muted">{hint}</div>
    </Link>
  );
}
