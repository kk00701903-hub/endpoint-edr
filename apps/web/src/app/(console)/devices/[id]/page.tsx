import Link from "next/link";
import { notFound } from "next/navigation";
import { ChevronLeft } from "lucide-react";
import { ProcessTree } from "@/components/process-tree";
import { Empty, Field, LivenessTag, Mono, Panel, PostureTag, ScoreTag, Segmented, SeverityTag, StatusTag } from "@/components/ui";
import { cn } from "@/lib/cn";
import { getContext } from "@/lib/context";
import type { TimelineItem } from "@/lib/data/types";
import { ago, bytes, day, duration, fullDay, liveness, nowMs, num, stamp, winName } from "@/lib/format";
import { policyMatches } from "@/lib/software-policy";

type Tab = "timeline" | "processes" | "network" | "autoruns" | "asset" | "posture" | "alerts";
const TABS: { value: Tab; label: string }[] = [
  { value: "timeline", label: "타임라인" },
  { value: "processes", label: "프로세스" },
  { value: "network", label: "네트워크" },
  { value: "autoruns", label: "자동 실행" },
  { value: "asset", label: "자산" },
  { value: "posture", label: "보안 상태" },
  { value: "alerts", label: "경보" },
];

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { source, tenant } = await getContext();
  const d = await source.device(tenant, id);
  return { title: d?.hostname ?? "장치" };
}

export default async function DevicePage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | undefined>> }) {
  const [{ id }, sp] = await Promise.all([params, searchParams]);
  const tab = (TABS.some((t) => t.value === sp.tab) ? sp.tab : "timeline") as Tab;
  const { source, tenant } = await getContext();
  const device = await source.device(tenant, id);
  if (!device) notFound();
  const h = device.health;
  const state = liveness(device.last_seen_at);

  return (
    <>
      <Link href="/devices" className="mb-3 inline-flex items-center gap-1 text-[13px] text-ink-2 hover:text-ink"><ChevronLeft className="size-4" aria-hidden />장치 목록</Link>
      <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-[22px] leading-8 font-semibold">{device.hostname}</h1>
            <LivenessTag state={state} />
          </div>
          <p className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-[13px] text-ink-2">
            <span><Mono>{device.last_ip ?? "IP 없음"}</Mono></span>
            <span>{winName(device.os_version)}</span>
            <span>에이전트 {device.agent_version ?? "—"}</span>
            <span title={stamp(device.last_seen_at)}>마지막 수신 {ago(device.last_seen_at)}</span>
            <span>등록 {day(device.enrolled_at)}</span>
          </p>
        </div>
        <div className="max-w-full overflow-x-auto"><Segmented value={tab} hrefFor={(v) => `/devices/${id}?tab=${v}`} items={TABS} /></div>
      </header>

      {/* 에이전트 상태: "가볍게, 충돌 없이" 돌고 있는지 */}
      <section className="mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-line bg-line sm:grid-cols-3 lg:grid-cols-6" aria-label="에이전트 상태">
        <Stat label="에이전트 CPU" value={h ? `${h.cpu_percent}%` : "—"} warn={!!h && h.cpu_percent >= 2} hint="전체 코어 대비 평균" />
        <Stat label="에이전트 메모리" value={h ? `${h.working_set_mb} MB` : "—"} warn={!!h && h.working_set_mb >= 120} hint="상한 150MB" />
        <Stat label="실행 시간" value={h ? duration(h.uptime_sec) : "—"} />
        <Stat label="전송 대기" value={h ? (h.spool_files ? `${h.spool_files}건 · ${bytes(h.spool_bytes)}` : "없음") : "—"} warn={!!h && h.spool_files > 0} hint="서버로 못 보낸 배치" />
        <Stat label="수집 소요" value={h ? `${num(h.scan_ms.process ?? 0)}ms` : "—"} hint={h ? `네트워크 ${h.scan_ms.network ?? 0}ms · 이벤트 ${h.scan_ms.eventlog ?? 0}ms` : undefined} />
        <Stat label="상태 보고" value={ago(device.health_at)} hint={h?.last_errors?.length ? `최근 오류 ${h.last_errors.length}건` : "최근 오류 없음"} warn={!!h?.last_errors?.length} />
      </section>
      {h?.last_errors && h.last_errors.length > 0 && (
        <details className="-mt-3 mb-5 text-[13px]">
          <summary className="cursor-pointer text-warn">에이전트 최근 오류 {h.last_errors.length}건 보기</summary>
          <ul className="mt-2 space-y-1 rounded-md bg-surface-2 p-3 font-mono text-xs">{h.last_errors.map((e) => <li key={e}>{e}</li>)}</ul>
        </details>
      )}

      {tab === "timeline" && <TimelineTab tenant={tenant} id={id} />}
      {tab === "processes" && <ProcessTab tenant={tenant} id={id} />}
      {tab === "network" && <NetworkTab tenant={tenant} id={id} all={sp.all === "1"} />}
      {tab === "autoruns" && <AutorunTab tenant={tenant} id={id} />}
      {tab === "asset" && <AssetTab tenant={tenant} id={id} />}
      {tab === "posture" && <PostureTab tenant={tenant} id={id} />}
      {tab === "alerts" && <AlertsTab tenant={tenant} id={id} />}
    </>
  );
}

function Stat({ label, value, hint, warn }: { label: string; value: string; hint?: string; warn?: boolean }) {
  return (
    <div className="bg-surface px-4 py-3">
      <div className="text-[12.5px] text-muted">{label}</div>
      <div className={cn("mt-0.5 text-[17px] font-semibold tabular-nums", warn && "text-warn")}>{value}</div>
      {hint && <div className="truncate text-xs text-muted">{hint}</div>}
    </div>
  );
}

// ---------------- 타임라인 ----------------
const KIND: Record<TimelineItem["kind"], string> = { alert: "경보", event: "보안 이벤트", autorun: "자동 실행", process: "새 프로세스", software: "설치 프로그램" };

async function TimelineTab({ tenant, id }: { tenant: string; id: string }) {
  const { source } = await getContext();
  const items = await source.deviceTimeline(tenant, id, 72);
  if (!items.length) return <Panel><Empty title="최근 72시간 기록이 없습니다">경보·보안 이벤트·자동 실행 변경·새 프로세스가 생기면 시간순으로 쌓입니다.</Empty></Panel>;
  const days = new Map<string, TimelineItem[]>();
  items.forEach((it) => {
    const k = new Intl.DateTimeFormat("ko-KR", { month: "long", day: "numeric", weekday: "short", timeZone: "Asia/Seoul" }).format(new Date(it.ts));
    days.set(k, [...(days.get(k) ?? []), it]);
  });
  return (
    <div className="space-y-5">
      {[...days].map(([dayLabel, list]) => (
        <section key={dayLabel}>
          <h2 className="mb-2 text-[13px] font-semibold text-ink-2">{dayLabel}</h2>
          <ol className="relative ml-[5.25rem] border-l border-line-strong">
            {list.map((it, i) => {
              const sev = it.severity;
              const dot = sev === "info" ? "bg-surface border border-line-strong" : sev === "critical" ? "bg-sev-critical" : sev === "high" ? "bg-sev-high" : sev === "medium" ? "bg-sev-medium" : "bg-sev-low";
              const t = new Intl.DateTimeFormat("ko-KR", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: "Asia/Seoul" }).format(new Date(it.ts));
              const alertId = it.kind === "alert" ? Number(it.detail.alert_id) : null;
              return (
                <li key={i} className="relative py-1.5 pl-5">
                  <span className="absolute top-2.5 -left-[5.25rem] w-[4.5rem] text-right font-mono text-xs text-muted tabular-nums">{t}</span>
                  <span aria-hidden className={cn("absolute top-[0.7rem] -left-[5px] size-[9px] rounded-full", dot)} />
                  <div className={cn("rounded-md px-3 py-1.5", it.kind === "alert" ? "bg-surface border border-line" : "")}>
                    <div className="flex flex-wrap items-center gap-x-2 text-[13px]">
                      <span className="text-xs text-muted">{KIND[it.kind]}</span>
                      {it.kind === "alert" && sev !== "info" && <SeverityTag severity={sev} />}
                      {alertId ? <Link href={`/alerts?id=${alertId}&status=all`} className="font-medium hover:text-accent">{it.title}</Link> : <span className={it.kind === "process" ? "font-mono text-[12.5px]" : ""}>{it.title}</span>}
                    </div>
                    {it.kind === "process" && typeof it.detail.command_line === "string" && (
                      <div className="mt-0.5 truncate font-mono text-xs text-ink-2" title={it.detail.command_line}>{it.detail.command_line}</div>
                    )}
                  </div>
                </li>
              );
            })}
          </ol>
        </section>
      ))}
    </div>
  );
}

async function ProcessTab({ tenant, id }: { tenant: string; id: string }) {
  const { source } = await getContext();
  const rows = await source.deviceProcesses(tenant, id);
  if (!rows.length) return <Panel><Empty title="프로세스 정보가 아직 없습니다">에이전트가 처음 전체 목록을 보내면(설치 후 1분 안팎) 표시됩니다.</Empty></Panel>;
  return <ProcessTree rows={rows} />;
}

async function NetworkTab({ tenant, id, all }: { tenant: string; id: string; all: boolean }) {
  const { source } = await getContext();
  const rows = await source.deviceConnections(tenant, id, { externalOnly: !all, hours: 24 });
  return (
    <Panel bodyClassName="p-0" title={all ? "모든 연결 (24시간)" : "외부 통신 (24시간)"}
      aside={<Link href={`/devices/${id}?tab=network${all ? "" : "&all=1"}`} className="text-accent hover:underline">{all ? "외부 통신만 보기" : "내부·대기 포트 포함"}</Link>}>
      {rows.length === 0 ? <Empty title={all ? "기록된 연결이 없습니다" : "외부 IP 와의 통신이 없습니다"} /> : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-[13px]">
            <thead className="border-b border-line bg-surface-2 text-xs text-muted">
              <tr><th className="px-4 py-2 font-medium">프로세스</th><th className="px-3 py-2 font-medium">방향</th><th className="px-3 py-2 font-medium">원격지</th><th className="px-3 py-2 font-medium">로컬 포트</th><th className="px-3 py-2 font-medium">상태</th><th className="px-4 py-2 text-right font-medium">관측</th></tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((c, i) => (
                <tr key={i} className="hover:bg-surface-2">
                  <td className="px-4 py-2">{c.process_name ?? "—"} <span className="text-xs text-muted">{c.pid}</span></td>
                  <td className="px-3 py-2">{{ inbound: "들어옴", outbound: "나감", listen: "대기", bound: "UDP" }[c.direction] ?? c.direction}</td>
                  <td className="px-3 py-2">
                    {c.remote_ip ? <Link href={`/hunt?q=${c.remote_ip}`} className="hover:text-accent"><Mono>{c.remote_ip}:{c.remote_port}</Mono></Link> : <span className="text-muted">—</span>}
                    {c.is_external && <span className="ml-2 text-xs text-ink-2">외부</span>}
                  </td>
                  <td className="px-3 py-2"><Mono>{c.local_port}</Mono></td>
                  <td className="px-3 py-2 text-ink-2">{c.state}</td>
                  <td className="px-4 py-2 text-right text-ink-2" title={stamp(c.observed_at)}>{ago(c.observed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

async function AutorunTab({ tenant, id }: { tenant: string; id: string }) {
  const { source } = await getContext();
  const rows = await source.deviceAutoruns(tenant, id);
  const now = nowMs();
  const recent = (r: { first_seen_at: string }) => now - Date.parse(r.first_seen_at) < 7 * 86_400_000;
  const groups = new Map<string, typeof rows>();
  rows.forEach((r) => {
    const g = r.location.startsWith("Service") ? "서비스" : r.location.startsWith("ScheduledTask") ? "예약 작업" : r.location.startsWith("StartupFolder") ? "시작프로그램 폴더" : "레지스트리";
    groups.set(g, [...(groups.get(g) ?? []), r]);
  });
  if (!rows.length) return <Panel><Empty title="자동 실행 항목 정보가 아직 없습니다">에이전트가 처음 기준선을 보내면(설치 후 10분 안팎) 표시됩니다.</Empty></Panel>;
  return (
    <div className="space-y-4">
      {[...groups].map(([g, list]) => (
        <Panel key={g} title={g} aside={<span>{list.length}개</span>} bodyClassName="p-0">
          <ul className="divide-y divide-line">
            {list.map((r) => (
              <li key={r.location + r.entry_name} className={cn("grid gap-1 px-4 py-2.5 text-[13px] md:grid-cols-[minmax(0,14rem)_minmax(0,1fr)_7rem]", r.removed_at && "opacity-50 line-through")}>
                <span className="min-w-0 truncate font-medium" title={r.entry_name}>{r.entry_name}</span>
                <Mono className="min-w-0 truncate text-ink-2" title={r.command ?? ""}>{r.command}</Mono>
                <span className="text-right text-xs text-muted">
                  {recent(r) && !r.removed_at ? <span className="font-medium text-sev-high">{ago(r.first_seen_at)} 추가</span> : r.removed_at ? `${ago(r.removed_at)} 삭제` : `${ago(r.first_seen_at)}부터`}
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      ))}
    </div>
  );
}

async function AlertsTab({ tenant, id }: { tenant: string; id: string }) {
  const { source } = await getContext();
  const page = await source.alerts(tenant, { device: id, status: "all", days: 90 });
  return (
    <Panel bodyClassName="p-0" title="이 장치의 경보" aside={<Link href={`/alerts?device=${id}&status=all&days=90`} className="text-accent hover:underline">경보 화면에서 처리</Link>}>
      {page.rows.length === 0 ? <Empty title="최근 90일 동안 경보가 없습니다" /> : (
        <ul className="divide-y divide-line">
          {page.rows.map((a) => (
            <li key={a.id}>
              <Link href={`/alerts?id=${a.id}&status=all`} className="grid grid-cols-[4.5rem_minmax(0,1fr)_auto_6rem] items-center gap-3 px-4 py-2.5 hover:bg-surface-2">
                <SeverityTag severity={a.severity} />
                <span className="truncate">{a.title}</span>
                <StatusTag status={a.status} resolution={a.resolution} />
                <span className="text-right text-[13px] text-muted">{ago(a.created_at)}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

// ---------------- 자산 ----------------
async function AssetTab({ tenant, id }: { tenant: string; id: string }) {
  const { source } = await getContext();
  const [inv, software, changes, exposure] = await Promise.all([
    source.deviceInventory(tenant, id), source.deviceSoftware(tenant, id),
    source.softwareChanges(tenant, { device: id, days: 90 }), source.softwareExposure(tenant),
  ]);
  if (!inv) return <Panel><Empty title="자산 정보가 아직 없습니다">이번 버전 에이전트로 업데이트하면, 처음 자산 정보를 보낸 뒤(1분 안팎) 표시됩니다.</Empty></Panel>;
  const today = new Date(nowMs()).toISOString().slice(0, 10);
  const ended = !!inv.os_end_of_support && inv.os_end_of_support < today;
  // 이 장치의 설치 프로그램이 어느 정책에 걸리는지(정책 규칙은 DB 와 같음)
  const flags = (s: { name: string; version: string; publisher: string | null }) => exposure.filter((p) => policyMatches(p, s));
  const flagged = software.filter((s) => flags(s).length > 0);
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
      <div className="space-y-4">
        <Panel title="장치 정보" aside={<span title={stamp(inv.collected_at)}>{ago(inv.collected_at)} 확인</span>}>
          <dl>
            <Field label="Windows">
              {inv.os_name ?? "—"} {inv.os_display_version}
              <div className="text-xs text-muted">빌드 {inv.os_build}{inv.os_ubr ? `.${inv.os_ubr}` : ""} · {inv.os_edition} · {inv.os_arch}</div>
            </Field>
            <Field label="지원 종료">
              {inv.os_end_of_support
                ? <span className={ended ? "font-medium text-sev-high" : ""}>{fullDay(inv.os_end_of_support)}{ended ? " (종료됨)" : ""}</span>
                : <span className="text-muted">수명 주기 정보 없음</span>}
            </Field>
            <Field label="제조사·모델">{[inv.manufacturer, inv.model].filter(Boolean).join(" ") || "—"}</Field>
            <Field label="일련번호"><Mono>{inv.serial_number ?? "—"}</Mono></Field>
            <Field label="BIOS">{inv.bios_version ?? "—"}</Field>
            <Field label="CPU">{inv.cpu ?? "—"}{inv.cpu_cores ? <span className="text-muted"> · {inv.cpu_cores}스레드</span> : null}</Field>
            <Field label="메모리">{inv.memory_mb ? `${Math.round(inv.memory_mb / 1024)} GB` : "—"}</Field>
            <Field label="시스템 디스크">
              {inv.disk_total_gb != null ? <span className={cn(inv.disk_free_gb != null && inv.disk_free_gb < 10 && "font-medium text-warn")}>{inv.disk_free_gb} GB 남음 / {inv.disk_total_gb} GB</span> : "—"}
            </Field>
            <Field label="도메인">{inv.domain ? `${inv.domain}${inv.domain_joined ? "" : " (작업 그룹)"}` : "—"}</Field>
            <Field label="마지막 로그온">{inv.last_user ?? "—"}</Field>
            <Field label="Windows 설치일">{inv.os_installed_at ? fullDay(inv.os_installed_at) : "—"}</Field>
          </dl>
        </Panel>
        <Panel title="네트워크 어댑터" bodyClassName="p-0">
          {inv.adapters.length === 0 ? <Empty title="연결된 어댑터 정보 없음" /> : (
            <ul className="divide-y divide-line text-[13px]">
              {inv.adapters.map((a) => (
                <li key={a.name + a.mac} className="px-4 py-2">
                  <div className="font-medium">{a.name}</div>
                  <div className="text-xs text-ink-2"><Mono>{a.mac ?? "MAC 없음"}</Mono>{a.ips?.length ? <> · {a.ips.map((ip) => <Mono key={ip} className="mr-1">{ip}</Mono>)}</> : null}</div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
      <div className="min-w-0 space-y-4">
        {flagged.length > 0 && (
          <Panel title="정책에 걸린 프로그램" bodyClassName="p-0" aside={<Link href="/assets?tab=exposure" className="text-accent hover:underline">정책 보기</Link>}>
            <ul className="divide-y divide-line text-[13px]">
              {flagged.map((s) => flags(s).map((p) => (
                <li key={s.name + s.version + p.policy_id} className="grid grid-cols-[4.75rem_minmax(0,1fr)] gap-3 px-4 py-2">
                  <SeverityTag severity={p.severity} />
                  <div className="min-w-0">
                    <div><span className="font-medium">{s.name}</span> <Mono className="text-ink-2">{s.version}</Mono> <span className="ml-1 text-xs text-ink-2">{p.kind === "prohibited" ? "금지 소프트웨어" : p.fixed_version ? `${p.fixed_version} 미만 취약` : "지원 종료"}</span></div>
                    {p.reason && <div className="text-xs text-ink-2">{p.reason}</div>}
                  </div>
                </li>
              )))}
            </ul>
          </Panel>
        )}
        <Panel title={`설치 프로그램 ${num(software.length)}개`} bodyClassName="p-0">
          {software.length === 0 ? <Empty title="설치 프로그램 정보가 없습니다" /> : (
            <div className="max-h-[32rem] overflow-auto">
              <table className="w-full min-w-[640px] text-left text-[13px]">
                <thead className="sticky top-0 border-b border-line bg-surface-2 text-xs text-muted">
                  <tr><th className="px-4 py-2 font-medium">프로그램</th><th className="px-3 py-2 font-medium">버전</th><th className="px-3 py-2 font-medium">게시자</th><th className="px-4 py-2 text-right font-medium">설치</th></tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {software.map((s) => {
                    const f = flags(s);
                    return (
                      <tr key={s.name + s.version} className={cn("hover:bg-surface-2", f.length > 0 && "bg-sev-critical-wash")}>
                        <td className="px-4 py-1.5">
                          <Link href={`/assets?tab=software&name=${encodeURIComponent(s.name)}`} className="hover:text-accent">{s.name}</Link>
                          {s.scope === "user" && <span className="ml-1.5 text-xs text-muted">사용자별</span>}
                          {f.length > 0 && <span className="ml-1.5 text-xs font-medium text-sev-high">{f[0]!.kind === "prohibited" ? "금지" : "취약"}</span>}
                        </td>
                        <td className="px-3 py-1.5"><Mono>{s.version || "—"}</Mono></td>
                        <td className="px-3 py-1.5 text-ink-2">{s.publisher ?? "—"}</td>
                        <td className="px-4 py-1.5 text-right whitespace-nowrap text-ink-2">{s.install_date ? `${s.install_date.slice(0, 4)}-${s.install_date.slice(4, 6)}-${s.install_date.slice(6)}` : ago(s.first_seen_at)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <Panel title="최근 90일 설치 이력" bodyClassName="p-0">
          {changes.rows.length === 0 ? <Empty title="바뀐 프로그램이 없습니다" /> : (
            <ul className="divide-y divide-line text-[13px]">
              {changes.rows.slice(0, 30).map((c) => (
                <li key={c.id} className="grid grid-cols-[5.5rem_4.5rem_minmax(0,1fr)] gap-3 px-4 py-1.5">
                  <span className="text-ink-2" title={stamp(c.observed_at)}>{ago(c.observed_at)}</span>
                  <span className={c.change === "installed" ? "font-medium" : "text-ink-2"}>{{ installed: "설치", removed: "삭제", updated: "업데이트" }[c.change]}</span>
                  <span className="truncate">{c.name} <Mono className="text-ink-2">{c.prev_version ? `${c.prev_version} → ${c.version}` : c.version}</Mono></span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}

// ---------------- 보안 상태 ----------------
async function PostureTab({ tenant, id }: { tenant: string; id: string }) {
  const { source } = await getContext();
  const { score, items } = await source.devicePosture(tenant, id);
  if (items.every((i) => !i.status)) return <Panel><Empty title="보안 점검 결과가 아직 없습니다">이번 버전 에이전트로 업데이트하면, 처음 점검 결과를 보낸 뒤(1분 안팎) 표시됩니다.</Empty></Panel>;
  const order = { fail: 0, warn: 1, unknown: 2, pass: 3 } as const;
  const sorted = [...items].sort((a, b) => (a.status ? order[a.status] : 4) - (b.status ? order[b.status] : 4) || Number(b.enabled) - Number(a.enabled));
  const fails = items.filter((i) => i.status === "fail" && i.enabled).length;
  return (
    <Panel bodyClassName="p-0"
      title={<span className="flex items-center gap-3 whitespace-nowrap">보안 점수 <ScoreTag score={score} /></span>}
      aside={<span>{fails ? `점수에 넣은 항목 중 실패 ${fails}개` : "점수에 넣은 항목 모두 통과"} · <Link href="/posture" className="text-accent hover:underline">전체 보안 상태</Link></span>}>
      <ul className="divide-y divide-line">
        {sorted.map((i) => (
          <li key={i.check_id} className={cn("grid gap-x-4 gap-y-1 px-4 py-3 md:grid-cols-[6rem_minmax(0,1fr)_9rem]", !i.enabled && "opacity-70")}>
            <PostureTag status={i.status} />
            <div className="min-w-0">
              <div className="font-medium">
                {i.title}
                <span className="ml-2 text-xs font-normal text-muted">{i.category} · 가중치 {i.weight}{i.enabled ? "" : " · 점수 제외"}</span>
              </div>
              <p className="text-[13px] text-ink-2">{i.detail ?? i.description}</p>
              {(i.status === "fail" || i.status === "warn") && <p className="mt-1 text-[13px] [overflow-wrap:anywhere]"><span className="font-medium">고치는 방법</span> <span className="text-ink-2">{i.remediation}</span></p>}
            </div>
            <div className="text-right text-xs text-muted md:pt-0.5">
              {i.status === "fail" && i.failing_since ? <span className="text-ink-2" title={stamp(i.failing_since)}>{ago(i.failing_since)}부터 실패</span>
                : i.checked_at ? <span title={stamp(i.checked_at)}>{ago(i.checked_at)} 확인</span> : "보고 전"}
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
