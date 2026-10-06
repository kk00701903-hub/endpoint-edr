import Link from "next/link";
import { notFound } from "next/navigation";
import { ChevronLeft, ExternalLink, Fingerprint, KeyRound, Monitor, Network } from "lucide-react";
import { AttackGraphView } from "@/components/attack-graph-view";
import { IncidentTriage } from "@/components/incident-triage";
import { KillChain } from "@/components/killchain";
import { LivenessTag, Mono, Panel, Segmented, SeverityTag } from "@/components/ui";
import { buildGraph } from "@/lib/attack-graph";
import { canTriage, getContext } from "@/lib/context";
import { ago, liveness, stamp } from "@/lib/format";
import { TACTIC_KO, summarize } from "@/lib/incident-summary";

type Tab = "story" | "alerts" | "evidence";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  return { title: `INC-${(await params).id}` };
}

export default async function IncidentPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | undefined>> }) {
  const [{ id }, sp] = await Promise.all([params, searchParams]);
  const tab = (["story", "alerts", "evidence"].includes(sp.tab ?? "") ? sp.tab : "story") as Tab;
  const { source, viewer, tenant } = await getContext();
  const d = await source.incident(tenant, Number(id));
  if (!d) notFound();
  const inc = d.incident;
  const hostnames = Object.fromEntries(d.devices.map((x) => [x.id, x.hostname]));
  const sum = summarize(inc, d.alerts, hostnames);
  const ruleBy = new Map(d.rules.map((r) => [r.rule_id, r]));

  return (
    <>
      <Link href="/incidents" className="mb-3 inline-flex items-center gap-1 text-[13px] text-ink-2 hover:text-ink"><ChevronLeft className="size-4" aria-hidden />인시던트 목록</Link>
      <header className="mb-4">
        <div className="flex flex-wrap items-center gap-3 text-[13px] text-ink-2">
          <span className="text-muted">INC-{inc.id}</span>
          <SeverityTag severity={inc.severity} />
          <span title={stamp(inc.first_seen_at)}>{stamp(inc.first_seen_at)} 시작</span>
          <span>마지막 활동 {ago(inc.last_seen_at)}</span>
        </div>
        <h1 className="mt-1 text-[24px] leading-8 font-semibold tracking-[-0.01em]">{inc.title}</h1>
        <p className="mt-1 text-ink-2">{sum.headline}</p>
      </header>

      <KillChain tactics={inc.tactics} className="mb-5" />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-5">
          <div className="flex items-center justify-between">
            <Segmented value={tab} hrefFor={(v) => `/incidents/${inc.id}?tab=${v}`}
              items={[{ value: "story", label: "사건 흐름" }, { value: "alerts", label: `경보 ${inc.alert_count}` }, { value: "evidence", label: "증거·엔터티" }]} />
          </div>

          {tab === "story" && (
            <>
              <Panel title="자동 요약" aside={<span>규칙 기반 생성, 외부 전송 없음</span>}>
                <p className="text-[15px] leading-relaxed">{sum.assessment}</p>
                <ol className="mt-4 space-y-0">
                  {sum.narrative.map((s, i) => (
                    <li key={i} className="relative grid grid-cols-[1.75rem_1fr] gap-2 pb-3 last:pb-0">
                      <span className="z-10 flex size-6 items-center justify-center rounded-full border border-line-strong bg-surface text-xs tabular-nums text-ink-2">{i + 1}</span>
                      {i < sum.narrative.length - 1 && <span aria-hidden className="absolute top-6 bottom-0 left-3 w-px bg-line-strong" />}
                      <span className="pt-0.5 text-[14px]">{s}</span>
                    </li>
                  ))}
                </ol>
                <div className="mt-5 rounded-md border border-line bg-surface-2 p-3">
                  <h3 className="text-[13px] font-semibold">권장 확인·조치 <span className="font-normal text-muted">— 이 시스템은 차단하지 않으므로 담당자가 직접 진행</span></h3>
                  <ul className="mt-2 list-disc space-y-1 pl-5 text-[13px]">
                    {sum.recommendations.map((r) => <li key={r}>{r}</li>)}
                  </ul>
                </div>
              </Panel>
            </>
          )}

          {tab === "alerts" && (
            <Panel title="포함된 경보" bodyClassName="p-0" aside={<span>시간순</span>}>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-left text-[13px]">
                  <thead className="border-b border-line bg-surface-2 text-xs text-muted">
                    <tr><th className="px-4 py-2 font-medium">시각</th><th className="px-3 py-2 font-medium">심각도</th><th className="px-3 py-2 font-medium">경보</th><th className="px-3 py-2 font-medium">ATT&CK</th><th className="px-4 py-2 font-medium">장치</th></tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {d.alerts.map((a) => {
                      const r = ruleBy.get(a.rule_id);
                      return (
                        <tr key={a.id} className="hover:bg-surface-2">
                          <td className="px-4 py-2 font-mono text-xs whitespace-nowrap text-ink-2">{stamp(a.created_at)}</td>
                          <td className="px-3 py-2"><SeverityTag severity={a.severity} /></td>
                          <td className="px-3 py-2"><Link href={`/alerts?id=${a.id}&status=all`} className="font-medium hover:text-accent">{a.title}</Link></td>
                          <td className="px-3 py-2 text-ink-2">{r ? `${TACTIC_KO[r.mitre_tactic] ?? r.mitre_tactic}, ${r.mitre_technique}` : a.rule_id}</td>
                          <td className="px-4 py-2">{a.device_id ? <Link href={`/devices/${a.device_id}`} className="hover:text-accent">{hostnames[a.device_id] ?? a.hostname}</Link> : "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}

          {tab === "evidence" && (
            <div className="grid gap-4 lg:grid-cols-2">
              <Panel title="장치" bodyClassName="p-0">
                <ul className="divide-y divide-line">
                  {d.devices.map((dv) => (
                    <li key={dv.id} className="flex items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
                      <Link href={`/devices/${dv.id}?tab=timeline`} className="flex items-center gap-2 font-medium hover:text-accent"><Monitor className="size-4 text-muted" aria-hidden />{dv.hostname}</Link>
                      <span className="flex items-center gap-3"><Mono>{dv.last_ip}</Mono><LivenessTag state={liveness(dv.last_seen_at)} /></span>
                    </li>
                  ))}
                </ul>
              </Panel>
              <EntityList title="IP 주소" icon={Network} kind="ip" values={inc.ips} />
              <EntityList title="계정" icon={KeyRound} kind="user" values={inc.users} />
              <EntityList title="파일 해시" icon={Fingerprint} kind="hash" values={inc.hashes} />
              <Panel title="ATT&CK 기법" bodyClassName="p-0">
                <ul className="divide-y divide-line">
                  {d.rules.map((r) => (
                    <li key={r.rule_id} className="flex items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
                      <span>{r.title} <span className="text-muted">{TACTIC_KO[r.mitre_tactic]}</span></span>
                      <a href={`https://attack.mitre.org/techniques/${r.mitre_technique.replace(".", "/")}/`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">{r.mitre_technique}<ExternalLink className="size-3" aria-hidden /></a>
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>
          )}
        </div>

        <aside className="space-y-5 xl:sticky xl:top-20 xl:self-start">
          <div className="rounded-lg border border-line bg-surface p-4">
            <IncidentTriage id={inc.id} status={inc.status} resolution={inc.resolution} assignedToMe={inc.assigned_to === viewer.userId}
              assigned={!!inc.assigned_to} canTriage={canTriage(viewer.tenant.role)} comments={d.comments} />
          </div>
          <div className="rounded-lg border border-line bg-surface p-4">
            <h2 className="mb-2 text-[13px] font-semibold text-ink-2">핵심 엔터티</h2>
            <div className="flex flex-wrap gap-1.5">
              {inc.ips.map((v) => <Chip key={v} href={`/entities/ip/${encodeURIComponent(v)}`} icon={Network} mono>{v}</Chip>)}
              {inc.users.map((v) => <Chip key={v} href={`/entities/user/${encodeURIComponent(v)}`} icon={KeyRound}>{v}</Chip>)}
              {inc.hashes.map((v) => <Chip key={v} href={`/entities/hash/${v}`} icon={Fingerprint} mono>{v.slice(0, 12)}…</Chip>)}
              {d.devices.map((dv) => <Chip key={dv.id} href={`/devices/${dv.id}`} icon={Monitor}>{dv.hostname}</Chip>)}
            </div>
          </div>
        </aside>
      </div>

      {tab === "story" && (
        <Panel className="mt-5" title="공격 그래프" bodyClassName="p-0" aside={<span>노드를 눌러 상세 보기</span>}>
          <AttackGraphView graph={buildGraph(d.alerts, d.devices, d.processes, d.connections)} />
        </Panel>
      )}
    </>
  );
}

function Chip({ href, icon: Icon, children, mono }: { href: string; icon: typeof Network; children: React.ReactNode; mono?: boolean }) {
  return (
    <Link href={href} className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-line-strong bg-surface-2 px-2 py-1 text-[12.5px] hover:border-accent hover:text-accent">
      <Icon className="size-3.5 shrink-0 text-muted" aria-hidden /><span className={mono ? "truncate font-mono text-[12px]" : "truncate"}>{children}</span>
    </Link>
  );
}

function EntityList({ title, icon: Icon, kind, values }: { title: string; icon: typeof Network; kind: "ip" | "user" | "hash"; values: string[] }) {
  return (
    <Panel title={title} bodyClassName="p-0">
      {values.length === 0 ? <p className="px-4 py-4 text-[13px] text-muted">없음</p> : (
        <ul className="divide-y divide-line">
          {values.map((v) => (
            <li key={v} className="flex items-center justify-between gap-3 px-4 py-2.5 text-[13px]">
              <span className="flex min-w-0 items-center gap-2"><Icon className="size-4 shrink-0 text-muted" aria-hidden /><Mono className="truncate">{v}</Mono></span>
              <Link href={`/entities/${kind}/${encodeURIComponent(v)}`} className="shrink-0 text-accent hover:underline">프로필</Link>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
