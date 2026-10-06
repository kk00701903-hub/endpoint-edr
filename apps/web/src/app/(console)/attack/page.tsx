import Link from "next/link";
import { PageHeader, Segmented } from "@/components/ui";
import { STAGES } from "@/components/killchain";
import { cn } from "@/lib/cn";
import { CATALOG } from "@/lib/attack-catalog";
import { getContext } from "@/lib/context";
import { ago, num } from "@/lib/format";
import { TACTIC_KO } from "@/lib/incident-summary";

export const metadata = { title: "ATT&CK 매트릭스" };

const HEAT = ["bg-heat-1", "bg-heat-2", "bg-heat-3", "bg-heat-4"];

export default async function AttackPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const days = [7, 30, 90].includes(Number(sp.days)) ? Number(sp.days) : 30;
  const { source, tenant } = await getContext();
  const [cells, rules] = await Promise.all([source.attackMatrix(tenant, days), source.rules(tenant)]);
  const hits = new Map<string, { hits: number; last: string | null }>();
  cells.forEach((c) => {
    const cur = hits.get(c.technique) ?? { hits: 0, last: null };
    cur.hits += Number(c.hits);
    if (c.last_seen && (!cur.last || c.last_seen > cur.last)) cur.last = c.last_seen;
    hits.set(c.technique, cur);
  });
  const ruleByTech = new Map<string, typeof rules>();
  rules.filter((r) => r.enabled).forEach((r) => ruleByTech.set(r.mitre_technique, [...(ruleByTech.get(r.mitre_technique) ?? []), r]));
  const max = Math.max(1, ...[...hits.values()].map((h) => h.hits));
  const level = (n: number) => (n <= 0 ? -1 : Math.min(3, Math.floor((n / max) * 4 - 1e-9)));

  const covered = CATALOG.filter((t) => ruleByTech.has(t.id)).length;
  const huntable = CATALOG.filter((t) => !ruleByTech.has(t.id) && t.visibility === "huntable").length;
  const gap = CATALOG.length - covered - huntable;
  const observed = CATALOG.filter((t) => (hits.get(t.id)?.hits ?? 0) > 0).length;

  return (
    <>
      <PageHeader
        title="ATT&CK 매트릭스"
        description="공격 단계(열)별로 이 시스템이 무엇을 자동 탐지하고, 무엇을 헌팅으로 확인할 수 있고, 무엇을 볼 수 없는지 한 화면에 보여줍니다."
        actions={<Segmented value={String(days)} hrefFor={(v) => `/attack?days=${v}`} items={[{ value: "7", label: "7일" }, { value: "30", label: "30일" }, { value: "90", label: "90일" }]} />}
      />

      <section className="mb-4 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-line bg-line lg:grid-cols-4" aria-label="탐지 범위 요약">
        <Stat label="자동 탐지 규칙 있음" value={`${covered}개`} hint={`목록 ${CATALOG.length}개 기법 중 ${Math.round((covered / CATALOG.length) * 100)}%`} />
        <Stat label="헌팅으로 확인 가능" value={`${huntable}개`} hint="수집 데이터에 쿼리 실행" />
        <Stat label="수동형으로는 볼 수 없음" value={`${gap}개`} hint="기존 보안 솔루션·Sysmon 영역" />
        <Stat label={`최근 ${days}일 관측된 기법`} value={`${observed}개`} hint="경보가 1건 이상" />
      </section>

      <div className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-[13px] text-ink-2" aria-label="범례">
        <span className="flex items-center gap-2"><span className="flex gap-0.5">{HEAT.map((h) => <span key={h} className={cn("h-3 w-4 rounded-sm", h)} />)}</span>경보 적은 → 많은 기법</span>
        <span className="flex items-center gap-2"><span className="h-3 w-4 rounded-sm border border-accent bg-surface" />탐지 규칙 있음(경보 없음)</span>
        <span className="flex items-center gap-2"><span className="h-3 w-4 rounded-sm border border-line-strong bg-surface" />헌팅으로 확인</span>
        <span className="flex items-center gap-2"><span className="h-3 w-4 rounded-sm border border-dashed border-line-strong" />볼 수 없음</span>
      </div>

      <div className="overflow-x-auto rounded-lg border border-line bg-surface">
        <div className="grid min-w-[1320px] grid-cols-12 divide-x divide-line">
          {STAGES.map((tactic) => {
            const techs = CATALOG.filter((t) => t.tactic === tactic);
            const tHits = techs.reduce((s, t) => s + (hits.get(t.id)?.hits ?? 0), 0);
            return (
              <section key={tactic} aria-label={TACTIC_KO[tactic]}>
                <header className="border-b border-line bg-surface-2 px-2 py-2">
                  <div className="text-[13px] font-semibold">{TACTIC_KO[tactic]}</div>
                  <div className="text-[11px] text-muted">{tactic}</div>
                  <div className="mt-1 text-xs tabular-nums text-ink-2">{tHits ? `경보 ${num(tHits)}` : "경보 없음"}</div>
                </header>
                <ul className="space-y-1 p-1.5">
                  {techs.map((t) => {
                    const h = hits.get(t.id)?.hits ?? 0;
                    const lv = level(h);
                    const rs = ruleByTech.get(t.id);
                    const href = rs ? `/alerts?rule=${rs[0]!.rule_id}&status=all&days=${days}` : t.query ? `/hunt?q=${encodeURIComponent(t.query)}` : undefined;
                    const body = (
                      <>
                        <div className="text-[11px] opacity-80">{t.id}</div>
                        <div className="text-[12.5px] leading-snug font-medium">{t.ko}</div>
                        <div className="mt-1 text-[11px] leading-snug opacity-80">
                          {rs ? (h ? `경보 ${num(h)}건, ${ago(hits.get(t.id)!.last)}` : "규칙 있음, 경보 없음") : t.visibility === "huntable" ? "헌팅으로 확인" : "볼 수 없음"}
                        </div>
                      </>
                    );
                    const cls = cn("block rounded-md px-2 py-1.5",
                      lv >= 0 ? cn(HEAT[lv], lv >= 2 ? "text-accent-ink" : "text-ink") :
                      rs ? "border border-accent bg-surface text-ink" :
                      t.visibility === "huntable" ? "border border-line-strong bg-surface text-ink-2 hover:border-accent" :
                      "border border-dashed border-line-strong text-muted");
                    return (
                      <li key={t.id} title={`${t.id} ${t.name}${t.note ? `\n${t.note}` : ""}`}>
                        {href ? <Link href={href} className={cn(cls, "hover:ring-1 hover:ring-accent")}>{body}</Link> : <div className={cls}>{body}</div>}
                      </li>
                    );
                  })}
                </ul>
              </section>
            );
          })}
        </div>
      </div>
      <p className="mt-3 text-[13px] text-ink-2">
        칸을 누르면 탐지 규칙이 있는 기법은 해당 경보로, 헌팅 가능한 기법은 미리 채운 쿼리로 이동합니다. 이 목록은 Windows PC 에서 자주 쓰이는 기법 {CATALOG.length}개이며 ATT&CK 전체가 아닙니다.
      </p>
    </>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="bg-surface px-4 py-3">
      <div className="text-[13px] text-ink-2">{label}</div>
      <div className="mt-0.5 text-[24px] leading-8 font-semibold tabular-nums">{value}</div>
      <div className="text-xs text-muted">{hint}</div>
    </div>
  );
}
