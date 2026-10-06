import Link from "next/link";
import { notFound } from "next/navigation";
import { Crosshair, Fingerprint, KeyRound, Network } from "lucide-react";
import { KillChain } from "@/components/killchain";
import { Empty, Mono, Panel, Segmented, SeverityTag, StatusTag, Verdict } from "@/components/ui";
import { getContext } from "@/lib/context";
import type { EntityKind } from "@/lib/data/types";
import { ago, num, stamp } from "@/lib/format";

const META: Record<EntityKind, { label: string; icon: typeof Network }> = {
  ip: { label: "IP 주소", icon: Network },
  hash: { label: "파일 (SHA-256)", icon: Fingerprint },
  user: { label: "계정", icon: KeyRound },
};

export async function generateMetadata({ params }: { params: Promise<{ kind: string; value: string }> }) {
  const { kind, value } = await params;
  return { title: `${META[kind as EntityKind]?.label ?? "엔터티"} ${decodeURIComponent(value).slice(0, 20)}` };
}

export default async function EntityPage({ params, searchParams }: { params: Promise<{ kind: string; value: string }>; searchParams: Promise<Record<string, string | undefined>> }) {
  const [{ kind: k, value: raw }, sp] = await Promise.all([params, searchParams]);
  if (!["ip", "hash", "user"].includes(k)) notFound();
  const kind = k as EntityKind;
  const value = decodeURIComponent(raw).trim().slice(0, 200);
  if (kind === "hash" && !/^[0-9a-f]{64}$/i.test(value)) notFound();
  if (kind === "ip" && !/^[0-9a-f.:]+$/i.test(value)) notFound();
  const days = [7, 30, 90].includes(Number(sp.days)) ? Number(sp.days) : 30;
  const { source, tenant } = await getContext();
  const e = await source.entity(tenant, kind, value, days);
  const f = e.facts;
  const Icon = META[kind].icon;
  const rep = (f.reputation ?? null) as { verdict?: string; vt_malicious?: number; vt_total?: number; checked_at?: string } | null;
  const hunts = kind === "ip"
    ? [`net.remote_ip = ${value}`, `event.src_ip = ${value}`]
    : kind === "hash" ? [`process.sha256 = ${value}`] : [`event.user = ${value}`, `process.user ~ ${value}`];

  return (
    <>
      <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[13px] text-ink-2"><Icon className="size-4" aria-hidden />{META[kind].label} 프로필</div>
          <h1 className="mt-1 flex flex-wrap items-center gap-3 break-all font-mono text-[20px] leading-8 font-medium">
            {value}
            {kind === "hash" && <Verdict verdict={rep?.verdict} />}
            {kind === "ip" && f.is_public != null && <span className="font-sans text-[13px] font-normal text-ink-2">{f.is_public ? "공인 IP(외부)" : "사내·사설 IP"}</span>}
          </h1>
        </div>
        <Segmented value={String(days)} hrefFor={(v) => `/entities/${kind}/${encodeURIComponent(value)}?days=${v}`} items={[{ value: "7", label: "7일" }, { value: "30", label: "30일" }, { value: "90", label: "90일" }]} />
      </header>

      <section className="mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-line bg-line lg:grid-cols-5" aria-label="요약">
        <Stat label="처음 본 시각" value={e.first_seen ? ago(e.first_seen) : "기록 없음"} hint={stamp(e.first_seen)} />
        <Stat label="마지막 본 시각" value={e.last_seen ? ago(e.last_seen) : "기록 없음"} hint={stamp(e.last_seen)} />
        <Stat label="관련 장치" value={`${num(e.devices.length)}대`} hint={`관측 ${num(e.observations)}회`} />
        {kind === "hash" ? (
          <>
            <Stat label="평판" value={rep?.vt_total ? `${rep.vt_malicious ?? 0} / ${rep.vt_total}` : "조회 전"} hint={rep?.vt_total ? "악성으로 판정한 백신 엔진 수" : "enricher 가 조회 대기 중"} warn={(rep?.vt_malicious ?? 0) > 0} />
            <Stat label="지금 실행 중" value={`${num(Number(f.running_now ?? 0))}곳`} hint={`자동 실행 등록 ${num(Number(f.autoruns ?? 0))}곳`} warn={Number(f.running_now ?? 0) > 0 && (rep?.vt_malicious ?? 0) > 0} />
          </>
        ) : (
          <>
            <Stat label="로그온 실패" value={`${num(Number(f.logon_failures ?? 0))}회`} hint="이벤트 4625" warn={Number(f.logon_failures ?? 0) >= 10} />
            <Stat label="로그온 성공" value={`${num(Number(f.logon_success ?? 0))}회`} hint="이벤트 4624" warn={kind === "ip" && !!f.is_public && Number(f.logon_success ?? 0) > 0} />
          </>
        )}
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-5">
          <Panel title="관련 인시던트" bodyClassName="p-0" aside={<span>{e.incidents.length}건</span>}>
            {e.incidents.length === 0 ? <Empty title="이 값이 포함된 인시던트가 없습니다" /> : (
              <ul className="divide-y divide-line">
                {e.incidents.map((i) => (
                  <li key={i.id}>
                    <Link href={`/incidents/${i.id}`} className="grid grid-cols-[4.75rem_minmax(0,1fr)_auto_6rem] items-center gap-3 px-4 py-2.5 hover:bg-surface-2">
                      <SeverityTag severity={i.severity} />
                      <span className="min-w-0"><span className="block truncate font-medium">{i.title}</span><span className="text-xs text-muted">INC-{i.id}, 경보 {i.alert_count}건</span></span>
                      <KillChain tactics={i.tactics} compact />
                      <span className="text-right text-[13px] text-ink-2">{ago(i.last_seen_at)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel title="관련 장치" bodyClassName="p-0" aside={<span>최근 {days}일</span>}>
            {e.devices.length === 0 ? <Empty title="최근 기간에 이 값을 본 장치가 없습니다" /> : (
              <table className="w-full text-left text-[13px]">
                <thead className="border-b border-line bg-surface-2 text-xs text-muted"><tr><th className="px-4 py-2 font-medium">장치</th><th className="px-3 py-2 text-right font-medium">관측</th><th className="px-4 py-2 text-right font-medium">마지막</th></tr></thead>
                <tbody className="divide-y divide-line">
                  {e.devices.map((d) => (
                    <tr key={d.id} className="hover:bg-surface-2">
                      <td className="px-4 py-2"><Link href={`/devices/${d.id}?tab=${kind === "hash" ? "processes" : "timeline"}`} className="font-medium hover:text-accent">{d.hostname}</Link></td>
                      <td className="px-3 py-2 text-right tabular-nums">{num(d.n)}회</td>
                      <td className="px-4 py-2 text-right text-ink-2" title={stamp(d.last)}>{ago(d.last)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
          <Panel title="관련 경보" bodyClassName="p-0" aside={<span>{e.alerts.length}건</span>}>
            {e.alerts.length === 0 ? <Empty title="이 값이 들어간 경보가 없습니다" /> : (
              <ul className="divide-y divide-line">
                {e.alerts.map((a) => (
                  <li key={a.id}>
                    <Link href={`/alerts?id=${a.id}&status=all`} className="grid grid-cols-[4.75rem_minmax(0,1fr)_auto_6rem] items-center gap-3 px-4 py-2.5 hover:bg-surface-2">
                      <SeverityTag severity={a.severity} />
                      <span className="min-w-0"><span className="block truncate">{a.title}</span><span className="text-xs text-muted">{a.hostname}</span></span>
                      <StatusTag status={a.status} resolution={a.resolution} />
                      <span className="text-right text-[13px] text-ink-2">{ago(a.created_at)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>

        <aside className="space-y-5">
          {kind === "hash" && (
            <Panel title="파일 정보">
              <dl className="space-y-2 text-[13px]">
                <div><dt className="text-xs text-muted">알려진 이름</dt><dd>{(f.names as string[] | undefined)?.join(", ") || "—"}</dd></div>
                <div><dt className="text-xs text-muted">발견된 경로</dt><dd className="space-y-1">{((f.paths as string[] | undefined) ?? []).slice(0, 6).map((p) => <Mono key={p} className="block break-mono">{p}</Mono>)}{!(f.paths as string[] | undefined)?.length && "—"}</dd></div>
                <div><dt className="text-xs text-muted">평판 조회</dt><dd>{rep?.checked_at ? `${ago(rep.checked_at)} 확인` : "아직 조회 전"}</dd></div>
              </dl>
              <a href={`https://www.virustotal.com/gui/file/${value}`} target="_blank" rel="noreferrer" className="mt-3 inline-block text-[13px] text-accent hover:underline">VirusTotal 에서 보기(해시만 전달)</a>
            </Panel>
          )}
          {kind !== "hash" && Array.isArray(f.source_ips) && (
            <Panel title="로그온 출발지">
              <ul className="space-y-1 text-[13px]">{(f.source_ips as string[]).map((ip) => <li key={ip}><Link href={`/entities/ip/${encodeURIComponent(ip)}`} className="hover:text-accent"><Mono>{ip}</Mono></Link></li>)}</ul>
              {(f.source_ips as string[]).length === 0 && <p className="text-[13px] text-muted">기록 없음</p>}
            </Panel>
          )}
          <Panel title="이 값으로 더 찾기">
            <ul className="space-y-2">
              {hunts.map((q) => (
                <li key={q}>
                  <Link href={`/hunt?q=${encodeURIComponent(q)}&h=${days * 24}`} className="flex items-start gap-2 rounded-md border border-line-strong px-2.5 py-2 text-[12.5px] hover:border-accent">
                    <Crosshair className="mt-0.5 size-3.5 shrink-0 text-accent" aria-hidden /><Mono className="break-mono">{q}</Mono>
                  </Link>
                </li>
              ))}
            </ul>
          </Panel>
        </aside>
      </div>
    </>
  );
}

function Stat({ label, value, hint, warn }: { label: string; value: string; hint?: string; warn?: boolean }) {
  return (
    <div className="bg-surface px-4 py-3">
      <div className="text-[12.5px] text-muted">{label}</div>
      <div className={warn ? "mt-0.5 text-[18px] font-semibold text-sev-high tabular-nums" : "mt-0.5 text-[18px] font-semibold tabular-nums"}>{value}</div>
      {hint && <div className="truncate text-xs text-muted" suppressHydrationWarning>{hint}</div>}
    </div>
  );
}
