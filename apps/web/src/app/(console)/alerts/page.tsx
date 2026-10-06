import { AlertWorkbench } from "@/components/alert-workbench";
import { PageHeader } from "@/components/ui";
import { canTriage, getContext } from "@/lib/context";
import type { AlertFilter, Severity } from "@/lib/data/types";
import { SEVERITIES } from "@/lib/data/types";
import { num } from "@/lib/format";

export const metadata = { title: "경보" };

type SP = Promise<Record<string, string | string[] | undefined>>;
const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

export default async function AlertsPage({ searchParams }: { searchParams: SP }) {
  const sp = await searchParams;
  const { source, viewer, tenant } = await getContext();

  const filter: AlertFilter = {
    severity: (one(sp.severity) ?? "").split(",").filter((s): s is Severity => SEVERITIES.includes(s as Severity)),
    status: (["active", "open", "acknowledged", "closed", "all"].includes(one(sp.status) ?? "") ? one(sp.status) : "active") as AlertFilter["status"],
    rule: one(sp.rule) || undefined,
    device: one(sp.device) || undefined,
    source: (["edr", "wazuh"].includes(one(sp.source) ?? "") ? one(sp.source) : undefined) as AlertFilter["source"],
    q: one(sp.q) || undefined,
    days: Math.min(90, Math.max(1, Number(one(sp.days)) || 30)),
    page: Math.max(1, Number(one(sp.page)) || 1),
  };
  const id = Number(one(sp.id)) || null;

  const [page, detail, rules] = await Promise.all([
    source.alerts(tenant, filter),
    id ? source.alert(tenant, id) : Promise.resolve(null),
    source.rules(tenant),
  ]);

  return (
    <>
      <PageHeader
        title="경보"
        description={`조건에 맞는 경보 ${num(page.total)}건. 위아래 화살표나 J·K 로 이동하고, A 로 조사 시작합니다.`}
      />
      <AlertWorkbench
        page={page}
        filter={filter}
        selectedId={id}
        detail={detail}
        rules={rules.map((r) => ({ rule_id: r.rule_id, title: r.title }))}
        canTriage={canTriage(viewer.tenant.role)}
        me={viewer.userId}
      />
    </>
  );
}
