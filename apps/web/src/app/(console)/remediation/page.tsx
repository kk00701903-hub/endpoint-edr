import Link from "next/link";
import { Download, X } from "lucide-react";
import { RemediationTable } from "@/components/remediation-table";
import { REMEDIATION_KIND } from "@/lib/remediation-labels";
import { ButtonLink, Empty, PageHeader, Pager, Segmented, StatStrip } from "@/components/ui";
import { cn } from "@/lib/cn";
import { canAdmin, canTriage, getContext } from "@/lib/context";
import type { RemediationView } from "@/lib/data/types";
import { nowMs, num } from "@/lib/format";

export const metadata = { title: "PC 조치 목록" };

type SP = Promise<Record<string, string | undefined>>;
const VIEWS: RemediationView[] = ["active", "open", "in_progress", "done", "exception", "resolved"];
const KINDS = ["posture", "software", "docs"] as const;
type KindFilter = (typeof KINDS)[number];

export default async function RemediationPage({ searchParams }: { searchParams: SP }) {
  const sp = await searchParams;
  const { source, viewer, tenant } = await getContext();
  const view = (VIEWS.includes(sp.view as RemediationView) ? sp.view : "active") as RemediationView;
  const kind = (KINDS.includes(sp.kind as KindFilter) ? sp.kind : undefined) as KindFilter | undefined;
  const mine = sp.mine === "1";
  const q = sp.q?.trim() || "";
  const device = sp.device || "";
  const page = Math.max(1, Number(sp.page) || 1);
  const [ov, list, members] = await Promise.all([
    source.remediationOverview(tenant),
    source.remediation(tenant, { kind, view, device, assignee: mine ? viewer.userId : undefined, q, page }),
    source.members(tenant),
  ]);
  const href = (p: Record<string, string | number | undefined>) => {
    const u = new URLSearchParams();
    for (const [k, v] of Object.entries({ view, kind, mine: mine ? "1" : undefined, q, device, ...p }))
      if (v !== undefined && v !== "" && !(k === "page" && String(v) === "1") && !(k === "view" && v === "active")) u.set(k, String(v));
    const s = u.toString();
    return s ? `/remediation?${s}` : "/remediation";
  };
  const deviceName = device ? list.rows.find((r) => r.device_id === device)?.hostname ?? "선택한 장치" : null;
  const today = new Date(nowMs()).toISOString().slice(0, 10);
  const docCount = (ov.by_kind.doc_pii ?? 0) + (ov.by_kind.doc_stale ?? 0);
  const exportQs = new URLSearchParams(Object.entries({ view, kind: kind ?? "", mine: mine ? "1" : "", q, device }).filter(([, v]) => v)).toString();

  return (
    <>
      <PageHeader
        title="PC 조치 목록"
        description="보안 점검 실패, 업데이트가 필요한 프로그램, 정리할 문서처럼 PC 마다 고쳐야 할 일을 모았습니다. 고쳐지면 다음 수집·검사에서 저절로 목록에서 빠집니다."
        actions={<ButtonLink href={`/api/export/remediation${exportQs ? `?${exportQs}` : ""}`} prefetch={false}><Download className="size-4" aria-hidden />CSV 내려받기</ButtonLink>}
      >
        <div className="mt-4 overflow-x-auto">
          <Segmented value={view} hrefFor={(v) => href({ view: v, page: 1 })} items={[
            { value: "active", label: `조치 필요 ${num(ov.items)}` },
            { value: "open", label: `대기 ${num(ov.by_status.open ?? 0)}` },
            { value: "in_progress", label: `진행 중 ${num(ov.by_status.in_progress ?? 0)}` },
            { value: "done", label: `완료 표시 ${num(ov.by_status.done ?? 0)}` },
            { value: "exception", label: `예외 ${num(ov.by_status.exception ?? 0)}` },
            { value: "resolved", label: "해결 확인됨" },
          ]} />
        </div>
      </PageHeader>

      <StatStrip label="조치 요약" items={[
        { label: "조치 필요", value: num(ov.items), hint: `PC ${num(ov.devices)}대`, href: href({ view: "active", page: 1 }) },
        { label: "높음 이상", value: num(ov.high), hint: "먼저 처리", tone: ov.high ? "bad" : undefined },
        { label: "담당자 없음", value: num(ov.unassigned), tone: ov.unassigned ? "warn" : undefined },
        { label: "기한 지남", value: num(ov.overdue), tone: ov.overdue ? "bad" : undefined },
        { label: "진행 중", value: num(ov.by_status.in_progress ?? 0), href: href({ view: "in_progress", page: 1 }) },
        { label: "최근 30일 해결", value: num(ov.resolved_30d), href: href({ view: "resolved", page: 1 }) },
      ]} />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Chip on={!kind} href={href({ kind: undefined, page: 1 })}>전체</Chip>
        <Chip on={kind === "posture"} href={href({ kind: "posture", page: 1 })}>{REMEDIATION_KIND.posture} {num(ov.by_kind.posture ?? 0)}</Chip>
        <Chip on={kind === "software"} href={href({ kind: "software", page: 1 })}>{REMEDIATION_KIND.software} {num(ov.by_kind.software ?? 0)}</Chip>
        {ov.docs && <Chip on={kind === "docs"} href={href({ kind: "docs", page: 1 })}>문서 정리 {num(docCount)}</Chip>}
        <span className="mx-1 h-5 w-px bg-line" aria-hidden />
        <Chip on={mine} href={href({ mine: mine ? undefined : "1", page: 1 })}>내 담당</Chip>
        {deviceName && (
          <Link href={href({ device: undefined, page: 1 })} className="inline-flex items-center gap-1 rounded-md border border-accent bg-accent-soft px-2 py-1 text-[12.5px]">
            장치: {deviceName}<X className="size-3.5" aria-label="장치 조건 지우기" />
          </Link>
        )}
        <form action="/remediation" className="ml-auto flex h-8 min-w-60 items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2">
          {view !== "active" && <input type="hidden" name="view" value={view} />}
          {kind && <input type="hidden" name="kind" value={kind} />}
          {mine && <input type="hidden" name="mine" value="1" />}
          {device && <input type="hidden" name="device" value={device} />}
          <input name="q" defaultValue={q} placeholder="장치 이름·할 일 검색" aria-label="조치 항목 검색" className="w-full bg-transparent text-[13px] outline-none" />
        </form>
      </div>

      {list.rows.length === 0 ? (
        <div className="rounded-lg border border-line bg-surface">
          <Empty title={view === "resolved" ? "최근 90일 동안 해결 확인된 항목이 없습니다" : q || kind || mine || device ? "조건에 맞는 조치 항목이 없습니다" : "지금 조치할 항목이 없습니다"}>
            {view === "active" && !q && !kind && !mine && !device ? "보안 점검·소프트웨어 정책·문서 감사에서 새로 걸리는 것이 생기면 여기에 나옵니다." : undefined}
          </Empty>
        </div>
      ) : (
        <RemediationTable rows={list.rows} members={members.map((m) => ({ user_id: m.user_id, email: m.email }))}
          canEdit={canTriage(viewer.tenant.role)} canEditDocs={canAdmin(viewer.tenant.role)} today={today} />
      )}
      <Pager page={page} pages={Math.max(1, Math.ceil(list.total / list.pageSize))} hrefFor={(p) => href({ page: p })} />

      <p className="mt-4 text-xs text-muted">
        &quot;완료 표시&quot;는 처리했다는 기록이고, 실제로 고쳐졌는지는 다음 수집(보안 점검 1시간·프로그램 6시간)이나 문서 검사에서 확인해 목록에서 뺍니다.
        예외로 둔 항목은 조치 필요 목록에 나오지 않습니다. 상태·담당자·기한·메모를 바꾸면 감사 기록에 남습니다.
        {!ov.docs && " 문서 정리 항목은 소유자·관리자에게만 보입니다."}
      </p>
    </>
  );
}

function Chip({ on, href, children }: { on: boolean; href: string; children: React.ReactNode }) {
  return (
    <Link href={href} aria-current={on ? "true" : undefined}
      className={cn("rounded-md border px-2 py-1 text-[12.5px] whitespace-nowrap", on ? "border-accent bg-accent-soft text-ink" : "border-line bg-surface hover:bg-surface-2")}>
      {children}
    </Link>
  );
}
