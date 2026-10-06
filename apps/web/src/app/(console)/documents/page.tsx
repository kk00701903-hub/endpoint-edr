import Link from "next/link";
import { Download, X } from "lucide-react";
import { DocPolicyForm, DocScanRequestButton } from "@/components/doc-controls";
import { ButtonLink, Empty, PageHeader, Pager, Panel, Segmented, StatStrip } from "@/components/ui";
import { cn } from "@/lib/cn";
import { canAdmin, getContext } from "@/lib/context";
import { PII_KINDS, PII_LABEL } from "@/lib/data/doc-defaults";
import type { DocDeviceRow, DocFindingKind, DocFindingRow, DocPiiKind } from "@/lib/data/types";
import { ago, bytes, fullDay, nowMs, num, stamp } from "@/lib/format";

export const metadata = { title: "문서 감사" };

type SP = Promise<Record<string, string | undefined>>;
type Tab = DocFindingKind | "devices" | "policy";
const TABS: Tab[] = ["pii", "keyword", "stale", "devices", "policy"];
const YEAR = 365 * 86_400_000;

export default async function DocumentsPage({ searchParams }: { searchParams: SP }) {
  const sp = await searchParams;
  const { source, viewer, tenant } = await getContext();

  if (!canAdmin(viewer.tenant.role)) {
    return (
      <>
        <PageHeader title="문서 감사" />
        <div className="rounded-lg border border-line bg-surface">
          <Empty title="소유자·관리자만 볼 수 있습니다">문서 감사 결과에는 개인정보가 든 파일의 위치가 있어 권한을 좁혀 두었습니다. 필요하면 조직 관리자에게 요청하세요.</Empty>
        </div>
      </>
    );
  }

  const tab = (TABS.includes(sp.tab as Tab) ? sp.tab : "pii") as Tab;
  const q = sp.q?.trim() || "";
  const device = sp.device || "";
  const keyword = sp.keyword || "";
  const page = Math.max(1, Number(sp.page) || 1);
  const [policy, ov] = await Promise.all([source.docPolicy(tenant), source.docOverview(tenant)]);
  const isFindings = tab === "pii" || tab === "keyword" || tab === "stale";
  const [list, devices] = await Promise.all([
    isFindings ? source.docFindings(tenant, { kind: tab, q, device, keyword: tab === "keyword" ? keyword : undefined, page }) : null,
    tab === "devices" || device ? source.docDevices(tenant) : null,
  ]);
  const deviceName = device ? devices?.find((d) => d.device_id === device)?.hostname ?? "선택한 장치" : null;
  const href = (p: Record<string, string | number | undefined>) => {
    const u = new URLSearchParams();
    for (const [k, v] of Object.entries({ tab, q, device, keyword: tab === "keyword" ? keyword : undefined, ...p })) if (v !== undefined && v !== "" && !(k === "page" && String(v) === "1")) u.set(k, String(v));
    return `/documents?${u}`;
  };
  const exportHref = isFindings ? `/api/export/documents-${tab}?${new URLSearchParams(Object.entries({ q, device, keyword: tab === "keyword" ? keyword : "" }).filter(([, v]) => v))}` : null;

  return (
    <>
      <PageHeader
        title="문서 감사"
        description="PC 에 남아 있는 개인정보 문서, 지정한 단어가 든 문서, 오래 손대지 않은 문서를 찾습니다. 에이전트는 문서를 읽기만 하고, 서버에는 파일 위치와 종류별 건수만 보냅니다."
        actions={
          <div className="flex flex-wrap gap-2">
            {exportHref && <ButtonLink href={exportHref} prefetch={false}><Download className="size-4" aria-hidden />CSV 내려받기</ButtonLink>}
            {policy.enabled && <DocScanRequestButton target="all" label="모든 PC 지금 검사" size="md" />}
          </div>
        }
      >
        <div className="mt-4 overflow-x-auto">
          <Segmented value={tab} hrefFor={(v) => `/documents?tab=${v}`} items={[
            { value: "pii", label: `개인정보 ${num(ov.pii_files)}` },
            { value: "keyword", label: `키워드 ${num(ov.keyword_files)}` },
            { value: "stale", label: `오래된 문서 ${num(ov.stale_files)}` },
            { value: "devices", label: "검사 현황" },
            { value: "policy", label: "설정" },
          ]} />
        </div>
      </PageHeader>

      {!policy.enabled && tab !== "policy" && (
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-warn/50 bg-surface px-4 py-3 text-[13px]">
          <span><span className="font-semibold text-warn">문서 감사가 꺼져 있습니다.</span> 직원에게 알린 뒤 설정에서 켜면 PC 들이 정책을 받아 검사를 시작합니다.</span>
          <ButtonLink href="/documents?tab=policy" size="sm">설정 열기</ButtonLink>
        </div>
      )}

      {tab !== "policy" && (
        <StatStrip label="문서 감사 요약" items={[
          { label: "개인정보 문서", value: num(ov.pii_files), hint: `장치 ${num(ov.pii_devices)}대`, href: "/documents?tab=pii", tone: ov.pii_files ? "bad" : undefined },
          { label: "키워드 문서", value: num(ov.keyword_files), hint: Object.keys(ov.keywords_by_word).slice(0, 3).join(" · ") || "키워드 없음", href: "/documents?tab=keyword" },
          { label: "오래된 문서", value: num(ov.stale_files), hint: bytes(ov.stale_bytes), href: "/documents?tab=stale", tone: ov.stale_files ? "warn" : undefined },
          { label: "검사한 장치", value: `${num(ov.devices_scanned)} / ${num(ov.devices)}`, href: "/documents?tab=devices" },
          { label: "마지막 검사", value: <span suppressHydrationWarning>{ov.last_scan_at ? ago(ov.last_scan_at) : "—"}</span>, hint: ov.last_scan_at ? stamp(ov.last_scan_at) : "검사 결과 없음" },
          { label: "대기·진행", value: `${num(ov.pending_requests)} · ${num(ov.running)}`, hint: "요청 대기 · 검사 중", href: "/documents?tab=devices" },
        ]} />
      )}

      {isFindings && list && (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            {tab === "pii" && PII_KINDS.filter((k) => ov.pii_by_kind[k.value]).map((k) => (
              <span key={k.value} className="rounded-md border border-line bg-surface px-2 py-1 text-[12.5px]">
                {k.label} <span className="font-semibold tabular-nums">{num(ov.pii_by_kind[k.value])}</span>건
              </span>
            ))}
            {tab === "keyword" && Object.entries(ov.keywords_by_word).sort((a, b) => b[1] - a[1]).map(([w, n]) => (
              <Link key={w} href={keyword === w ? href({ keyword: undefined, page: 1 }) : href({ keyword: w, page: 1 })}
                className={cn("rounded-md border px-2 py-1 text-[12.5px]", keyword === w ? "border-accent bg-accent-soft" : "border-line bg-surface hover:bg-surface-2")}>
                {w} <span className="text-muted tabular-nums">문서 {num(n)}</span>
              </Link>
            ))}
            {deviceName && (
              <Link href={href({ device: undefined, page: 1 })} className="inline-flex items-center gap-1 rounded-md border border-accent bg-accent-soft px-2 py-1 text-[12.5px]">
                장치: {deviceName}<X className="size-3.5" aria-label="장치 조건 지우기" />
              </Link>
            )}
            <form action="/documents" className="ml-auto flex h-8 min-w-60 items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2">
              <input type="hidden" name="tab" value={tab} />
              {device && <input type="hidden" name="device" value={device} />}
              {tab === "keyword" && keyword && <input type="hidden" name="keyword" value={keyword} />}
              <input name="q" defaultValue={q} placeholder="파일 경로·장치 이름 검색" aria-label="문서 검색" className="w-full bg-transparent text-[13px] outline-none" />
            </form>
          </div>
          <FindingTable kind={tab as DocFindingKind} rows={list.rows} empty={!policy.enabled ? "문서 감사가 꺼져 있어 결과가 없습니다" : q || device || keyword ? "조건에 맞는 문서가 없습니다" : EMPTY[tab as DocFindingKind]} />
          <Pager page={page} pages={Math.max(1, Math.ceil(list.total / list.pageSize))} hrefFor={(p) => href({ page: p })} />
        </>
      )}

      {tab === "devices" && devices && <DeviceTable rows={devices} enabled={policy.enabled} />}

      {tab === "policy" && (
        <Panel title="문서 감사 정책" aside={policy.updated_at ? <span suppressHydrationWarning>마지막 변경 {ago(policy.updated_at)}</span> : "아직 저장한 적 없음"}>
          <DocPolicyForm policy={policy} />
        </Panel>
      )}

      <p className="mt-4 text-xs text-muted">
        결과는 소유자·관리자만 볼 수 있고, 조회·내보내기·정책 변경·검사 요청은 모두 감사 기록(설정 → 감사 기록)에 남습니다.
        에이전트는 문서를 지우거나 옮기지 않습니다 — 정리는 담당자에게 요청하세요. 검사 결과는 다음 검사에서 다시 보이지 않으면 사라집니다.
      </p>
    </>
  );
}

const EMPTY: Record<DocFindingKind, string> = {
  pii: "개인정보가 든 문서를 찾지 못했습니다",
  keyword: "키워드가 든 문서를 찾지 못했습니다",
  stale: "오래된 문서를 찾지 못했습니다",
};

function splitPath(p: string) {
  const i = p.lastIndexOf("\\");
  return i < 0 ? { dir: "", name: p } : { dir: p.slice(0, i), name: p.slice(i + 1) };
}

function FindingTable({ kind, rows, empty }: { kind: DocFindingKind; rows: DocFindingRow[]; empty: string }) {
  const now = nowMs();
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface">
      {rows.length === 0 ? <Empty title={empty} /> : (
        <table className="w-full min-w-[900px] text-left text-[13.5px]">
          <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
            <tr>
              <th className="px-4 py-2 font-medium">장치</th>
              <th className="px-3 py-2 font-medium">문서</th>
              <th className="px-3 py-2 font-medium">{kind === "pii" ? "찾은 개인정보" : kind === "keyword" ? "찾은 키워드" : "상태"}</th>
              <th className="px-3 py-2 font-medium">마지막 저장</th>
              <th className="px-3 py-2 text-right font-medium">크기</th>
              <th className="px-4 py-2 font-medium">확인</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((r) => {
              const { dir, name } = splitPath(r.path);
              return (
                <tr key={`${r.device_id}|${r.path}`} className="align-top hover:bg-surface-2">
                  <td className="px-4 py-2.5 whitespace-nowrap">
                    <Link href={`/devices/${r.device_id}`} className="font-medium hover:text-accent">{r.hostname}</Link>
                  </td>
                  <td className="max-w-[30rem] px-3 py-2.5" title={r.path}>
                    <div className="font-medium [overflow-wrap:anywhere]">{name}</div>
                    <div className="text-xs text-muted [overflow-wrap:anywhere]">{dir}</div>
                  </td>
                  <td className="px-3 py-2.5">
                    {kind === "pii" && <Counts entries={Object.entries(r.pii).map(([k, n]) => [PII_LABEL[k as DocPiiKind] ?? k, n ?? 0])} />}
                    {kind === "keyword" && <Counts entries={Object.entries(r.keywords)} unit="회" />}
                    {kind === "stale" && (r.unreadable ? <span className="text-ink-2">{r.unreadable}</span> : <span className="text-muted">—</span>)}
                    {kind !== "pii" && r.pii_total > 0 && <div className="mt-1 text-xs text-sev-high">개인정보 {num(r.pii_total)}건 함께 있음</div>}
                  </td>
                  <td className="px-3 py-2.5 whitespace-nowrap">
                    {r.modified_at ? <span title={stamp(r.modified_at)}>{fullDay(r.modified_at)}</span> : "—"}
                    {kind === "stale" && r.modified_at && <div className="text-xs text-muted" suppressHydrationWarning>{Math.floor((now - Date.parse(r.modified_at)) / YEAR)}년 전</div>}
                  </td>
                  <td className="px-3 py-2.5 text-right whitespace-nowrap tabular-nums">{r.size == null ? "—" : bytes(r.size)}</td>
                  <td className="px-4 py-2.5 whitespace-nowrap text-ink-2"><span title={stamp(r.last_seen_at)} suppressHydrationWarning>{ago(r.last_seen_at)}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Counts({ entries, unit = "건" }: { entries: [string, number][]; unit?: string }) {
  return (
    <ul className="flex flex-wrap gap-1.5">
      {entries.sort((a, b) => b[1] - a[1]).map(([k, n]) => (
        <li key={k} className="rounded bg-surface-3 px-1.5 py-0.5 text-[12.5px] whitespace-nowrap">{k} <span className="font-semibold tabular-nums">{num(n)}</span>{unit}</li>
      ))}
    </ul>
  );
}

function DeviceTable({ rows, enabled }: { rows: DocDeviceRow[]; enabled: boolean }) {
  if (rows.length === 0) return <div className="rounded-lg border border-line bg-surface"><Empty title="등록된 장치가 없습니다" /></div>;
  const link = (id: string, tab: DocFindingKind, n: number) =>
    n > 0 ? <Link href={`/documents?tab=${tab}&device=${id}`} className="font-medium hover:text-accent hover:underline">{num(n)}</Link> : <span className="text-muted">0</span>;
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="w-full min-w-[900px] text-left text-[13.5px]">
        <thead className="border-b border-line bg-surface-2 text-[12.5px] text-muted">
          <tr>
            <th className="px-4 py-2 font-medium">장치</th>
            <th className="px-3 py-2 font-medium">마지막 검사</th>
            <th className="px-3 py-2 text-right font-medium">본 문서</th>
            <th className="px-3 py-2 text-right font-medium">개인정보</th>
            <th className="px-3 py-2 text-right font-medium">키워드</th>
            <th className="px-3 py-2 text-right font-medium">오래된</th>
            <th className="px-3 py-2 font-medium">요청</th>
            <th className="px-4 py-2" />
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {rows.map((d) => (
            <tr key={d.device_id} className="hover:bg-surface-2">
              <td className="px-4 py-2.5 whitespace-nowrap"><Link href={`/devices/${d.device_id}`} className="font-medium hover:text-accent">{d.hostname}</Link></td>
              <td className="px-3 py-2.5 whitespace-nowrap">
                {d.last_status === "running" ? <span className="text-accent">검사 중</span>
                  : d.last_scan_at ? <span title={stamp(d.last_scan_at)} suppressHydrationWarning>{ago(d.last_scan_at)}</span>
                    : <span className="text-muted">검사 전</span>}
              </td>
              <td className="px-3 py-2.5 text-right tabular-nums" title={d.files_skipped ? `건너뜀 ${num(d.files_skipped)}개(크기 초과·암호·클라우드 전용 등)` : undefined}>
                {num(d.files_scanned)}{d.files_skipped ? <span className="text-xs text-muted"> +{num(d.files_skipped)}</span> : null}
              </td>
              <td className="px-3 py-2.5 text-right tabular-nums">{link(d.device_id, "pii", d.pii_files)}</td>
              <td className="px-3 py-2.5 text-right tabular-nums">{link(d.device_id, "keyword", d.keyword_files)}</td>
              <td className="px-3 py-2.5 text-right tabular-nums">{link(d.device_id, "stale", d.stale_files)}</td>
              <td className="px-3 py-2.5 whitespace-nowrap text-ink-2">
                {d.pending_request_at ? <span suppressHydrationWarning>{d.request_picked ? "PC 가 받음" : "대기 중"} · {ago(d.pending_request_at)}</span> : "—"}
              </td>
              <td className="px-4 py-2.5 text-right">
                <DocScanRequestButton target={[d.device_id]} disabled={!enabled || !!d.pending_request_at} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
