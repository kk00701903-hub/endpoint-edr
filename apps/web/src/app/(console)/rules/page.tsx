import Link from "next/link";
import { ExternalLink } from "lucide-react";
import { RuleToggle, SuppressionDelete } from "@/components/rule-controls";
import { Empty, PageHeader, Panel, SeverityTag } from "@/components/ui";
import { canAdmin, getContext } from "@/lib/context";
import { ago, num, stamp } from "@/lib/format";

export const metadata = { title: "탐지 규칙" };

// ATT&CK 전술은 공격이 진행되는 순서대로 보여준다
const TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Credential Access", "Lateral Movement", "Command and Control"];
const TACTIC_KO: Record<string, string> = {
  "Initial Access": "초기 침투", Execution: "실행", Persistence: "지속성 확보", "Defense Evasion": "방어 회피",
  "Credential Access": "자격 증명 탈취", "Lateral Movement": "내부 확산", "Command and Control": "원격 제어(C2)",
};

export default async function RulesPage() {
  const { source, viewer, tenant } = await getContext();
  const [rules, supp] = await Promise.all([source.rules(tenant), source.suppressions(tenant)]);
  const admin = canAdmin(viewer.tenant.role);
  const order = (t: string) => (TACTIC_ORDER.includes(t) ? TACTIC_ORDER.indexOf(t) : 99);
  const tactics = [...new Set(rules.map((r) => r.mitre_tactic))].sort((a, b) => order(a) - order(b));
  const enabled = rules.filter((r) => r.enabled).length;

  return (
    <>
      <PageHeader
        title="탐지 규칙"
        description={`규칙 ${rules.length}개 중 ${enabled}개 사용 중. 규칙은 서버에서 1분마다 실행되며, 끄면 그 규칙의 새 경보가 만들어지지 않습니다.`}
      />

      <div className="space-y-4">
        {tactics.map((t) => (
          <Panel key={t} bodyClassName="p-0"
            title={<span>{TACTIC_KO[t] ?? t} <span className="ml-1 text-[13px] font-normal text-muted">{t}</span></span>}
            aside={<span>{rules.filter((r) => r.mitre_tactic === t).length}개</span>}>
            <ul className="divide-y divide-line">
              {rules.filter((r) => r.mitre_tactic === t).map((r) => (
                <li key={r.rule_id} className={`grid items-center gap-x-4 gap-y-1 px-4 py-3 md:grid-cols-[4.75rem_minmax(0,1fr)_12rem_6rem_5.5rem] ${r.enabled ? "" : "opacity-60"}`}>
                  <SeverityTag severity={r.severity} />
                  <div className="min-w-0">
                    <div className="font-medium">{r.title} <span className="ml-1 text-xs font-normal text-muted">{r.rule_id}</span></div>
                    <p className="text-[13px] text-ink-2">{r.description}</p>
                  </div>
                  <a href={`https://attack.mitre.org/techniques/${r.mitre_technique.replace(".", "/")}/`} target="_blank" rel="noreferrer"
                    className="inline-flex items-center gap-1 text-[13px] text-accent hover:underline">
                    {r.mitre_technique} {r.technique_name}<ExternalLink className="size-3 shrink-0" aria-hidden />
                  </a>
                  <Link href={`/alerts?rule=${r.rule_id}&status=all&days=7`} className="text-[13px] tabular-nums hover:text-accent">7일 {num(r.hits_7d ?? 0)}건</Link>
                  <RuleToggle ruleId={r.rule_id} enabled={r.enabled} disabled={!admin} />
                </li>
              ))}
            </ul>
          </Panel>
        ))}
      </div>

      <Panel className="mt-6" bodyClassName="p-0" title="예외" aside={<span>경보 상세에서 &lsquo;예외로 처리&rsquo;로 만듭니다</span>}>
        {supp.length === 0 ? <Empty title="예외가 없습니다">오탐이 반복되는 경보가 있으면 경보 상세 화면에서 조건을 골라 예외를 만드세요.</Empty> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left text-[13px]">
              <thead className="border-b border-line bg-surface-2 text-xs text-muted">
                <tr><th className="px-4 py-2 font-medium">규칙</th><th className="px-3 py-2 font-medium">조건</th><th className="px-3 py-2 font-medium">이유</th><th className="px-3 py-2 text-right font-medium">자동 종결</th><th className="px-3 py-2 font-medium">만료</th><th className="px-4 py-2" /></tr>
              </thead>
              <tbody className="divide-y divide-line">
                {supp.map((s) => (
                  <tr key={s.id}>
                    <td className="px-4 py-2">{s.rule_id ?? "모든 규칙"}{s.device_id && <span className="ml-1 text-xs text-muted">특정 장치</span>}</td>
                    <td className="px-3 py-2 font-mono text-xs">{Object.entries(s.match).map(([k, v]) => `${k}=${String(v)}`).join("  ") || "조건 없음(규칙 전체)"}</td>
                    <td className="px-3 py-2">{s.reason}</td>
                    <td className="px-3 py-2 text-right tabular-nums">{num(s.hit_count)}건</td>
                    <td className="px-3 py-2 text-ink-2" title={stamp(s.expires_at)}>{s.expires_at ? ago(s.expires_at) : "기한 없음"}</td>
                    <td className="px-4 py-2 text-right">{admin && <SuppressionDelete id={s.id} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
