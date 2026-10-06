import Link from "next/link";
import { Download, ExternalLink, Search, X } from "lucide-react";
import { PolicyDelete, PolicyToggle, SoftwarePolicyDialog } from "@/components/asset-controls";
import { ButtonLink, Empty, Mono, PageHeader, Pager, Panel, Segmented, SeverityTag, StatStrip } from "@/components/ui";
import { cn } from "@/lib/cn";
import { canAdmin, getContext } from "@/lib/context";
import type { AssetFilter, AssetOverview, SoftwareExposure } from "@/lib/data/types";
import { ago, fullDay, nowMs, num, stamp } from "@/lib/format";

export const metadata = { title: "자산" };

type Tab = "devices" | "software" | "exposure" | "changes";
type SP = Promise<Record<string, string | undefined>>;
const TABS: Tab[] = ["devices", "software", "exposure", "changes"];
const FILTERS: { value: AssetFilter; label: string }[] = [
  { value: "all", label: "전체" },
  { value: "unsupported", label: "지원 종료 Windows" },
  { value: "ending", label: "90일 안에 지원 종료" },
  { value: "low_disk", label: "디스크 10GB 미만" },
];
const CHANGE_LABEL = { installed: "설치", removed: "삭제", updated: "업데이트" } as const;

export default async function AssetsPage({ searchParams }: { searchParams: SP }) {
  const sp = await searchParams;
  const tab = (TABS.includes(sp.tab as Tab) ? sp.tab : "devices") as Tab;
  const { source, tenant } = await getContext();
  const ov = await source.assetOverview(tenant);
  const coverage = ov.devices ? Math.round((ov.inventoried / ov.devices) * 100) : 0;

  return (
    <>
      <PageHeader
        title="자산"
        description="PC·서버의 하드웨어, Windows 버전, 설치 프로그램입니다. 에이전트가 6시간마다 확인해 바뀐 것만 보냅니다."
        actions={tab !== "exposure" && (
          <ButtonLink href={`/api/export/${tab === "devices" ? "assets" : tab === "software" ? "software" : "software-changes"}`} prefetch={false}>
            <Download className="size-4" aria-hidden />CSV 내려받기
          </ButtonLink>
        )}
      >
        <div className="mt-4 max-w-full overflow-x-auto">
          <Segmented value={tab} hrefFor={(v) => `/assets?tab=${v}`} items={[
            { value: "devices", label: `장치 ${num(ov.inventoried)}` },
            { value: "software", label: `소프트웨어 ${num(ov.software_titles)}종` },
            { value: "exposure", label: "취약·금지 소프트웨어" },
            { value: "changes", label: "설치 이력" },
          ]} />
        </div>
      </PageHeader>

      <StatStrip label="자산 요약" items={[
        { label: "자산 정보 수집", value: `${num(ov.inventoried)} / ${num(ov.devices)}`, hint: coverage < 100 ? `${100 - coverage}% 는 에이전트 업데이트 필요` : "모든 장치", tone: coverage < 90 ? "warn" : undefined },
        { label: "지원 종료 Windows", value: num(ov.unsupported), hint: "보안 업데이트 없음", href: "/assets?tab=devices&filter=unsupported", tone: ov.unsupported ? "bad" : undefined },
        { label: "90일 안에 지원 종료", value: num(ov.ending_90d), hint: "업그레이드 계획 필요", href: "/assets?tab=devices&filter=ending", tone: ov.ending_90d ? "warn" : undefined },
        { label: "설치 프로그램", value: `${num(ov.software_titles)}종`, hint: "이름 기준", href: "/assets?tab=software" },
        { label: "최근 7일 새로 설치", value: num(ov.installs_7d), hint: "설치 이력 보기", href: "/assets?tab=changes" },
        { label: "디스크 10GB 미만", value: num(ov.low_disk), hint: "시스템 드라이브", href: "/assets?tab=devices&filter=low_disk", tone: ov.low_disk ? "warn" : undefined },
      ]} />

      {tab === "devices" && <DevicesTab sp={sp} tenant={tenant} ov={ov} />}
      {tab === "software" && <SoftwareTab sp={sp} tenant={tenant} />}
      {tab === "exposure" && <ExposureTab tenant={tenant} />}
      {tab === "changes" && <ChangesTab sp={sp} tenant={tenant} />}
    </>
  );
}

// ---------------- 장치 ----------------
async function DevicesTab({ sp, tenant, ov }: { sp: Record<string, string | undefined>; tenant: string; ov: AssetOverview }) {
  const { source } = await getContext();
  const filter = (FILTERS.some((f) => f.value === sp.filter) ? sp.filter : "all") as AssetFilter;
  const page = Math.max(1, Number(sp.page) || 1);
  const q = sp.q?.trim() || undefined;
  const list = await source.assets(tenant, { q, filter, page });
  const qs = (patch: Record<string, string | null>) => {
    const p = new URLSearchParams(Object.entries({ tab: "devices", filter: filter === "all" ? "" : filter, q: q ?? "", page: String(page) }).filter(([, v]) => v));
    Object.entries(patch).forEach(([k, v]) => (v ? p.set(k, v) : p.delete(k)));
    return `/assets?${p}`;
  };
  const maxOs = Math.max(1, ...ov.os.map((o) => o.n));
  const today = new Date(nowMs()).toISOString().slice(0, 10);

  return (
    <>
      <div className="mb-5 grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Panel title="Windows 버전" aside={<span>Microsoft 수명 주기 기준</span>}>
          {ov.os.length === 0 ? <p className="text-[13px] text-ink-2">아직 자산 정보가 없습니다.</p> : (
            <ul className="space-y-2">
              {ov.os.map((o) => {
                const ended = !!o.end_of_support && o.end_of_support < today;
                return (
                  <li key={o.label + o.end_of_support} className="grid grid-cols-[minmax(0,11rem)_minmax(0,1fr)_3rem] items-center gap-3 text-[13px]">
                    <span className="truncate" title={o.label}>{o.label}</span>
                    <span className="flex items-center gap-2">
                      <span className="h-2 rounded-full bg-heat-3" style={{ width: `${Math.max((o.n / maxOs) * 100, 2)}%` }} aria-hidden />
                      {o.end_of_support && (
                        <span className={cn("shrink-0 text-xs whitespace-nowrap", ended ? "font-medium text-sev-high" : "text-muted")}>
                          {ended ? "지원 종료" : `${fullDay(o.end_of_support)}까지`}
                        </span>
                      )}
                    </span>
                    <span className="text-right tabular-nums">{num(o.n)}대</span>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>
        <Panel title="제조사" aside={<span>도메인 가입 {num(ov.domain_joined)}대</span>}>
          {ov.manufacturers.length === 0 ? <p className="text-[13px] text-ink-2">—</p> : (
            <ul className="divide-y divide-line text-[13px]">
              {ov.manufacturers.map((m) => (
                <li key={m.label} className="flex items-center justify-between py-1.5">
                  <Link href={qs({ q: m.label, page: null })} className="truncate hover:text-accent">{m.label}</Link>
                  <span className="tabular-nums text-ink-2">{num(m.n)}대</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <nav className="flex flex-wrap gap-1 text-[13px]" aria-label="자산 거르기">
          {FILTERS.map((f) => (
            <Link key={f.value} href={qs({ filter: f.value === "all" ? null : f.value, page: null })} aria-current={f.value === filter ? "true" : undefined}
              className={cn("rounded px-2 py-1 text-ink-2 hover:text-ink", f.value === filter && "bg-surface-3 font-medium text-ink")}>{f.label}</Link>
          ))}
        </nav>
        <form action="/assets" className="ml-auto flex h-8 min-w-60 items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2">
          <Search className="size-3.5 text-muted" aria-hidden />
          <input type="hidden" name="tab" value="devices" />
          {filter !== "all" && <input type="hidden" name="filter" value={filter} />}
          <input name="q" defaultValue={q} placeholder="이름·일련번호·모델·사용자" aria-label="자산 검색" className="w-full bg-transparent text-[13px] outline-none" />
        </form>
      </div>

      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        {list.rows.length === 0 ? (
          <Empty title={q ? `‘${q}’ 와 일치하는 장치가 없습니다` : "이 조건의 장치가 없습니다"}>
            {filter === "all" ? "에이전트가 자산 정보를 처음 보내면(설치 후 1분 안팎) 표시됩니다." : "조건에 맞는 장치가 없습니다."}
          </Empty>
        ) : (
          <table className="w-full min-w-[1080px] text-left text-[13.5px]">
            <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">장치</th>
                <th className="px-3 py-2 font-medium">Windows</th>
                <th className="px-3 py-2 font-medium">제조사·모델</th>
                <th className="px-3 py-2 font-medium">일련번호</th>
                <th className="px-3 py-2 font-medium">CPU·메모리</th>
                <th className="px-3 py-2 font-medium">디스크 남은 공간</th>
                <th className="px-3 py-2 text-right font-medium">프로그램</th>
                <th className="px-4 py-2 text-right font-medium">확인</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {list.rows.map((a) => {
                const ended = !!a.os_end_of_support && a.os_end_of_support < today;
                const lowDisk = a.disk_free_gb != null && a.disk_free_gb < 10;
                return (
                  <tr key={a.device_id} className="hover:bg-surface-2">
                    <td className="px-4 py-2.5">
                      <Link href={`/devices/${a.device_id}?tab=asset`} className="font-medium whitespace-nowrap hover:text-accent">{a.hostname}</Link>
                      <div className="text-xs whitespace-nowrap text-muted">{a.last_user ?? (a.collected_at ? "로그온 기록 없음" : "")}{a.domain && !a.domain_joined ? ` · 작업 그룹 ${a.domain}` : ""}</div>
                    </td>
                    <td className="px-3 py-2.5">
                      {a.collected_at ? (
                        <>
                          <div>{a.os_label ?? a.os_name ?? "—"}<span className="ml-1 text-xs text-muted">{a.os_edition}</span></div>
                          <div className={cn("text-xs whitespace-nowrap", ended ? "font-medium text-sev-high" : "text-muted")} title={a.os_end_of_support ? `지원 종료일 ${fullDay(a.os_end_of_support)}` : undefined}>
                            빌드 {a.os_build}{a.os_ubr ? `.${a.os_ubr}` : ""}{a.os_end_of_support ? ` · ${ended ? "지원 종료" : `${a.os_end_of_support}까지`}` : ""}
                          </div>
                        </>
                      ) : <span className="text-muted">자산 정보 없음</span>}
                    </td>
                    <td className="px-3 py-2.5"><div className="truncate">{a.manufacturer ?? "—"}</div><div className="text-xs text-muted">{a.model}</div></td>
                    <td className="px-3 py-2.5"><Mono>{a.serial_number ?? "—"}</Mono></td>
                    <td className="px-3 py-2.5 tabular-nums">
                      <div className="max-w-56 truncate" title={a.cpu ?? ""}>{a.cpu ? a.cpu.replace(/\(R\)|\(TM\)|CPU|@.*$/g, "").replace(/\s+/g, " ").trim() : "—"}</div>
                      <div className="text-xs text-muted">{a.cpu_cores ? `${a.cpu_cores}스레드` : ""}{a.memory_mb ? ` · ${Math.round(a.memory_mb / 1024)}GB` : ""}</div>
                    </td>
                    <td className={cn("px-3 py-2.5 whitespace-nowrap tabular-nums", lowDisk && "font-medium text-warn")}>
                      {a.disk_free_gb != null ? `${a.disk_free_gb} / ${a.disk_total_gb} GB` : "—"}
                    </td>
                    <td className="px-3 py-2.5 text-right tabular-nums">{a.collected_at ? num(a.software_count) : "—"}</td>
                    <td className="px-4 py-2.5 text-right whitespace-nowrap text-ink-2" title={stamp(a.collected_at)}>{a.collected_at ? ago(a.collected_at) : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      <Pager page={page} pages={Math.max(1, Math.ceil(list.total / list.pageSize))} hrefFor={(p) => qs({ page: String(p) })} />
    </>
  );
}

// ---------------- 소프트웨어 ----------------
async function SoftwareTab({ sp, tenant }: { sp: Record<string, string | undefined>; tenant: string }) {
  const { source } = await getContext();
  const page = Math.max(1, Number(sp.page) || 1);
  const q = sp.q?.trim() || undefined;
  const name = sp.name;
  const [list, installs] = await Promise.all([
    source.softwareCatalog(tenant, { q, page }),
    name ? source.softwareInstalls(tenant, name) : Promise.resolve(null),
  ]);
  const qs = (patch: Record<string, string | null>) => {
    const p = new URLSearchParams(Object.entries({ tab: "software", q: q ?? "", page: String(page) }).filter(([, v]) => v));
    Object.entries(patch).forEach(([k, v]) => (v ? p.set(k, v) : p.delete(k)));
    return `/assets?${p}`;
  };
  return (
    <>
      {installs && (
        <Panel className="mb-4" bodyClassName="p-0" title={<span>{name} <span className="ml-1 text-[13px] font-normal text-muted">설치된 장치 {num(installs.length)}대</span></span>}
          aside={<Link href={qs({ name: null })} className="inline-flex items-center gap-1 hover:text-ink"><X className="size-3.5" aria-hidden />닫기</Link>}>
          {installs.length === 0 ? <Empty title="지금 설치된 장치가 없습니다" /> : (
            <div className="max-h-80 overflow-y-auto">
              <table className="w-full text-left text-[13px]">
                <thead className="sticky top-0 border-b border-line bg-surface-2 text-xs text-muted">
                  <tr><th className="px-4 py-2 font-medium">장치</th><th className="px-3 py-2 font-medium">버전</th><th className="px-3 py-2 font-medium">설치 범위</th><th className="px-3 py-2 font-medium">설치일</th><th className="px-4 py-2 text-right font-medium">처음 본 때</th></tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {installs.map((i) => (
                    <tr key={i.device_id + i.version}>
                      <td className="px-4 py-2"><Link href={`/devices/${i.device_id}?tab=asset`} className="font-medium hover:text-accent">{i.hostname}</Link></td>
                      <td className="px-3 py-2"><Mono>{i.version || "—"}</Mono></td>
                      <td className="px-3 py-2 text-ink-2">{i.scope === "user" ? "사용자별 설치" : "PC 전체"}</td>
                      <td className="px-3 py-2 text-ink-2">{i.install_date ?? "—"}</td>
                      <td className="px-4 py-2 text-right text-ink-2" title={stamp(i.first_seen_at)}>{ago(i.first_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <p className="text-[13px] text-ink-2">제어판 &lsquo;프로그램 제거&rsquo; 목록과 같은 출처입니다. Windows 업데이트(KB)와 숨은 구성 요소는 뺐습니다.</p>
        <form action="/assets" className="ml-auto flex h-8 min-w-60 items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2">
          <Search className="size-3.5 text-muted" aria-hidden />
          <input type="hidden" name="tab" value="software" />
          <input name="q" defaultValue={q} placeholder="프로그램·게시자 검색" aria-label="소프트웨어 검색" className="w-full bg-transparent text-[13px] outline-none" />
        </form>
      </div>
      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        {list.rows.length === 0 ? <Empty title={q ? `‘${q}’ 와 일치하는 프로그램이 없습니다` : "설치 프로그램 정보가 아직 없습니다"} /> : (
          <table className="w-full min-w-[820px] text-left text-[13.5px]">
            <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
              <tr><th className="px-4 py-2 font-medium">프로그램</th><th className="px-3 py-2 font-medium">게시자</th><th className="px-3 py-2 font-medium">버전</th><th className="px-3 py-2 text-right font-medium">설치 장치</th><th className="px-4 py-2 text-right font-medium">처음 본 때</th></tr>
            </thead>
            <tbody className="divide-y divide-line">
              {list.rows.map((s) => (
                <tr key={s.name} className={cn("hover:bg-surface-2", s.name === name && "bg-accent-soft")}>
                  <td className="px-4 py-2.5"><Link href={qs({ name: s.name })} scroll={false} className="font-medium hover:text-accent">{s.name}</Link></td>
                  <td className="px-3 py-2.5 text-ink-2">{s.publisher ?? "—"}</td>
                  <td className="px-3 py-2.5">
                    <span className="flex flex-wrap gap-1">
                      {s.versions.slice(0, 3).map((v) => <Mono key={v} className="rounded bg-surface-3 px-1.5 text-xs">{v || "버전 없음"}</Mono>)}
                      {s.versions.length > 3 && <span className="text-xs text-muted">외 {s.versions.length - 3}개</span>}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 text-right tabular-nums"><Link href={qs({ name: s.name })} scroll={false} className="hover:text-accent">{num(s.devices)}대</Link></td>
                  <td className="px-4 py-2.5 text-right whitespace-nowrap text-ink-2" title={stamp(s.first_seen_at)}>{ago(s.first_seen_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <Pager page={page} pages={Math.max(1, Math.ceil(list.total / list.pageSize))} hrefFor={(p) => qs({ page: String(p) })} />
    </>
  );
}

// ---------------- 취약·금지 소프트웨어 ----------------
function Reference({ value }: { value: string | null }) {
  if (!value) return null;
  const cve = /^CVE-\d{4}-\d{4,}$/i.test(value);
  const href = cve ? `https://nvd.nist.gov/vuln/detail/${value.toUpperCase()}` : /^https?:\/\//.test(value) ? value : null;
  if (!href) return <span className="text-xs text-ink-2">{value}</span>;
  return (
    <a href={href} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
      {cve ? value.toUpperCase() : "공지 보기"}<ExternalLink className="size-3" aria-hidden />
    </a>
  );
}

async function ExposureTab({ tenant }: { tenant: string }) {
  const { source, viewer } = await getContext();
  const rows = await source.softwareExposure(tenant);
  const admin = canAdmin(viewer.tenant.role);
  const section = (kind: SoftwareExposure["kind"]) => rows.filter((r) => r.kind === kind);
  const exposed = rows.filter((r) => r.enabled && r.devices > 0);

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-[13px] text-ink-2">
          {exposed.length ? `지금 ${exposed.length}개 정책에 해당하는 PC 가 있습니다. ` : "지금 해당하는 PC 가 없습니다. "}
          설치 프로그램 목록과 비교만 하고, 프로그램을 지우거나 막지는 않습니다. 금지 소프트웨어가 새로 보이면 경보(EDR-SW-001)를 만듭니다.
        </p>
        {admin && <SoftwarePolicyDialog />}
      </div>
      <div className="space-y-4">
        {(["prohibited", "vulnerable"] as const).map((kind) => (
          <Panel key={kind} bodyClassName="p-0"
            title={kind === "prohibited" ? "금지 소프트웨어" : "취약 버전 · 지원 종료 제품"}
            aside={<span>{kind === "prohibited" ? "회사 지침으로 쓰지 않기로 한 프로그램" : "알려진 취약점이 고쳐진 버전보다 낮거나 지원이 끝난 제품"}</span>}>
            {section(kind).length === 0 ? (
              <Empty title="정책이 없습니다">{admin ? "오른쪽 위 ‘정책 추가’로 만드세요." : "관리자가 정책을 만들면 여기에 보입니다."}</Empty>
            ) : (
              <ul className="divide-y divide-line">
                {section(kind).map((p) => (
                  <li key={p.policy_id} className={cn("grid gap-x-4 gap-y-2 px-4 py-3 md:grid-cols-[4.75rem_minmax(0,1.4fr)_minmax(0,1.6fr)_auto]", !p.enabled && "opacity-60")}>
                    <SeverityTag severity={p.severity} />
                    <div className="min-w-0">
                      <div className="font-medium">
                        {p.name_pattern}
                        {p.publisher_pattern && <span className="ml-1 text-xs font-normal text-muted">게시자 {p.publisher_pattern}</span>}
                        {p.builtin && <span className="ml-2 rounded border border-line-strong px-1.5 text-[11px] font-normal text-ink-2">기본 제공</span>}
                      </div>
                      <div className="text-[13px] text-ink-2">
                        {p.kind === "prohibited" ? "설치되어 있으면 해당" : p.fixed_version ? `${p.fixed_version} 미만 버전` : "모든 버전"}
                        {p.reason && <> — {p.reason}</>}
                      </div>
                      <Reference value={p.reference} />
                    </div>
                    <div className="min-w-0 text-[13px]">
                      {p.devices === 0 ? <span className="text-muted">{p.enabled ? "해당하는 PC 없음" : "꺼져 있음"}</span> : (
                        <>
                          <div className="font-medium text-sev-high tabular-nums">{num(p.devices)}대에 설치됨</div>
                          <div className="mt-0.5 flex flex-wrap gap-x-2 gap-y-0.5">
                            {(p.hostnames ?? []).map((h, i) => <Link key={h} href={`/devices/${p.device_ids[i]}?tab=asset`} className="hover:text-accent">{h}</Link>)}
                            {p.devices > (p.hostnames?.length ?? 0) && <span className="text-muted">외 {p.devices - (p.hostnames?.length ?? 0)}대</span>}
                          </div>
                          <div className="mt-0.5 truncate text-xs text-muted" title={p.software.join(", ")}>
                            {p.software.slice(0, 2).map((n) => <Link key={n} href={`/assets?tab=software&name=${encodeURIComponent(n)}`} className="mr-2 hover:text-accent">{n}</Link>)}
                            {p.versions.length > 0 && <>버전 {p.versions.slice(0, 4).join(", ")}</>}
                          </div>
                        </>
                      )}
                    </div>
                    <div className="flex items-center gap-3 md:justify-end">
                      <PolicyToggle id={p.policy_id} enabled={p.enabled} disabled={!admin} name={p.name_pattern} />
                      {admin && <PolicyDelete id={p.policy_id} name={p.name_pattern} />}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        ))}
      </div>
    </>
  );
}

// ---------------- 설치 이력 ----------------
async function ChangesTab({ sp, tenant }: { sp: Record<string, string | undefined>; tenant: string }) {
  const { source } = await getContext();
  const page = Math.max(1, Number(sp.page) || 1);
  const list = await source.softwareChanges(tenant, { days: 30, page });
  return (
    <>
      <p className="mb-3 text-[13px] text-ink-2">최근 30일 동안 설치·삭제·업데이트된 프로그램입니다. 에이전트를 처음 설치했을 때 이미 있던 프로그램은 이력에 넣지 않습니다.</p>
      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        {list.rows.length === 0 ? <Empty title="최근 30일 동안 바뀐 프로그램이 없습니다" /> : (
          <table className="w-full min-w-[860px] text-left text-[13.5px]">
            <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
              <tr><th className="px-4 py-2 font-medium">시각</th><th className="px-3 py-2 font-medium">장치</th><th className="px-3 py-2 font-medium">변화</th><th className="px-3 py-2 font-medium">프로그램</th><th className="px-3 py-2 font-medium">버전</th><th className="px-4 py-2 font-medium">게시자</th></tr>
            </thead>
            <tbody className="divide-y divide-line">
              {list.rows.map((c) => (
                <tr key={c.id} className="hover:bg-surface-2">
                  <td className="px-4 py-2 whitespace-nowrap text-ink-2" title={stamp(c.observed_at)}>{ago(c.observed_at)}</td>
                  <td className="px-3 py-2"><Link href={`/devices/${c.device_id}?tab=asset`} className="font-medium hover:text-accent">{c.hostname ?? c.device_id.slice(0, 8)}</Link></td>
                  <td className={cn("px-3 py-2", c.change === "installed" && "font-medium")}>{CHANGE_LABEL[c.change]}</td>
                  <td className="px-3 py-2"><Link href={`/assets?tab=software&name=${encodeURIComponent(c.name)}`} className="hover:text-accent">{c.name}</Link></td>
                  <td className="px-3 py-2"><Mono>{c.prev_version ? `${c.prev_version} → ${c.version}` : c.version ?? "—"}</Mono></td>
                  <td className="px-4 py-2 text-ink-2">{c.publisher ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <Pager page={page} pages={Math.max(1, Math.ceil(list.total / list.pageSize))} hrefFor={(p) => `/assets?tab=changes&page=${p}`} />
    </>
  );
}
