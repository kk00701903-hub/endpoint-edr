import "server-only";
import * as A from "./demo-assets";
import type { DemoDocs } from "./demo-docs";
import { policyMatches } from "../software-policy";
import type { Device, RemediationItem, RemediationKind, RemediationOverview, RemediationStatus, RemediationView, Severity } from "./types";

// ---------------------------------------------------------------------------
// 데모 모드의 PC 조치 목록. 규칙은 DB(마이그레이션 0010 edr_remediation_items)와 같다:
//   점수에 넣은 보안 점검 실패, 켜 둔 소프트웨어 정책(장치·정책당 1건), 개인정보·오래된 문서(관리자만, 장치당 1건)
// ---------------------------------------------------------------------------

export interface Tracking {
  title: string; status: RemediationStatus; assignee: string | null; note: string; due_date: string | null; updated_at: string; updated_by: string | null;
}
export const keyOf = (device: string, kind: string, item: string) => `${device}|${kind}|${item}`;

type Cur = Omit<RemediationItem, "status" | "assignee" | "assignee_email" | "note" | "due_date" | "updated_at" | "updated_by" | "present" | "hostname" | "last_seen_at">;

function current(assets: A.DemoAssets, docs: DemoDocs, devices: Device[], withDocs: boolean): Cur[] {
  const out: Cur[] = [];
  const active = devices.filter((d) => d.status === "active");
  for (const d of active) {
    const p = assets.posture.get(d.id);
    for (const c of A.POSTURE_CHECKS) {
      const s = p?.get(c.check_id);
      if (s?.status !== "fail" || !A.checkEnabled(assets, c)) continue;
      out.push({ device_id: d.id, kind: "posture", item_key: c.check_id, title: c.title, detail: s.detail || null,
        severity: c.weight >= 20 ? "high" : c.weight >= 10 ? "medium" : "low", since: s.failing_since ?? s.changed_at, guidance: c.remediation });
    }
    for (const pol of assets.policies) {
      const hits = (assets.software.get(d.id) ?? []).filter((s) => policyMatches(pol, s));
      if (hits.length === 0) continue;
      out.push({
        device_id: d.id, kind: "software", item_key: String(pol.id),
        title: (pol.kind === "prohibited" ? "금지 프로그램 삭제: " : "업데이트 필요: ") + hits.map((h) => h.name).sort()[0],
        detail: [...new Set(hits.map((h) => `${h.name}${h.version ? ` ${h.version}` : ""}`))].join(", "), severity: pol.severity,
        since: hits.map((h) => h.first_seen_at).sort()[0] ?? null,
        guidance: pol.kind === "prohibited"
          ? `${pol.reason || "회사에서 허용하지 않은 프로그램입니다"} — 프로그램 제거 후 다음 자산 수집(최대 6시간)에서 목록에서 빠집니다.`
          : `${pol.fixed_version ? `${pol.fixed_version} 이상으로 업데이트하세요.` : "지원이 끝난 제품입니다. 대체 프로그램으로 바꾸세요."}${pol.reference ? ` 참고: ${pol.reference}` : ""}`,
      });
    }
    if (withDocs) {
      const mine = docs.findings.filter((f) => f.device_id === d.id);
      const pii = mine.filter((f) => f.pii_total > 0);
      const stale = mine.filter((f) => f.stale && f.pii_total === 0);
      const first = (xs: typeof mine) => xs.map((f) => f.last_seen_at).sort()[0] ?? null;
      if (pii.length) out.push({ device_id: d.id, kind: "doc_pii", item_key: "pii", title: `개인정보 문서 정리 ${pii.length}개`,
        detail: `개인정보 ${pii.reduce((t, f) => t + f.pii_total, 0).toLocaleString("ko-KR")}건`, severity: "high", since: first(pii),
        guidance: "사용자에게 알려 필요 없는 문서는 지우고, 필요한 문서는 암호를 걸거나 지정 저장소로 옮기게 합니다. 다음 문서 검사에서 다시 보이지 않으면 목록에서 빠집니다." });
      if (stale.length) out.push({ device_id: d.id, kind: "doc_stale", item_key: "stale", title: `오래된 문서 정리 ${stale.length}개`,
        detail: `${Math.round(stale.reduce((t, f) => t + (f.size ?? 0), 0) / 1024 / 1024)} MB`, severity: "low", since: first(stale),
        guidance: "보관 기간이 지난 문서는 지우거나 보관 저장소로 옮기게 합니다. 업무에 계속 쓰는 문서면 예외로 둡니다." });
    }
  }
  return out;
}

const RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export function remediationRows(assets: A.DemoAssets, docs: DemoDocs, devices: Device[], tracking: Map<string, Tracking>, withDocs: boolean,
  emails: Map<string, string>, opts: { kind?: RemediationKind | "docs"; view?: RemediationView; device?: string; assignee?: string; q?: string }): RemediationItem[] {
  const byId = new Map(devices.map((d) => [d.id, d]));
  const cur = current(assets, docs, devices, withDocs);
  const curKeys = new Set(cur.map((c) => keyOf(c.device_id, c.kind, c.item_key)));
  const rows: RemediationItem[] = cur.map((c) => {
    const t = tracking.get(keyOf(c.device_id, c.kind, c.item_key));
    return { ...c, hostname: byId.get(c.device_id)!.hostname, last_seen_at: byId.get(c.device_id)!.last_seen_at, present: true,
      status: t?.status ?? "open", assignee: t?.assignee ?? null, note: t?.note ?? "", due_date: t?.due_date ?? null,
      updated_at: t?.updated_at ?? null, updated_by: t?.updated_by ?? null };
  });
  for (const [k, t] of tracking) {
    if (curKeys.has(k) || Date.now() - Date.parse(t.updated_at) > 90 * 86_400_000) continue;
    const [device_id, kind, item_key] = k.split("|") as [string, RemediationKind, string];
    if (!withDocs && kind.startsWith("doc_")) continue;
    const d = byId.get(device_id);
    if (!d) continue;
    rows.push({ device_id, kind, item_key, hostname: d.hostname, last_seen_at: d.last_seen_at, title: t.title, detail: null, severity: null, since: null,
      guidance: null, present: false, status: t.status, assignee: t.assignee, note: t.note, due_date: t.due_date, updated_at: t.updated_at, updated_by: t.updated_by });
  }
  const view = opts.view ?? "active";
  const q = opts.q?.toLowerCase();
  return rows
    .filter((r) => !opts.kind || r.kind === opts.kind || (opts.kind === "docs" && r.kind.startsWith("doc_")))
    .filter((r) => view === "all" ? true : view === "resolved" ? !r.present : view === "active" ? r.present && r.status !== "exception" : r.present && r.status === view)
    .filter((r) => !opts.device || r.device_id === opts.device)
    .filter((r) => !opts.assignee || r.assignee === opts.assignee)
    .filter((r) => !q || r.hostname.toLowerCase().includes(q) || r.title.toLowerCase().includes(q))
    .map((r) => ({ ...r, assignee_email: r.assignee ? emails.get(r.assignee) ?? null : null }))
    .sort((a, b) => Number(b.present) - Number(a.present) || (b.severity ? RANK[b.severity] : 0) - (a.severity ? RANK[a.severity] : 0)
      || Number(a.status === "done") - Number(b.status === "done") || (a.since ?? "9").localeCompare(b.since ?? "9")
      || a.hostname.localeCompare(b.hostname) || a.kind.localeCompare(b.kind));
}

export function remediationOverview(assets: A.DemoAssets, docs: DemoDocs, devices: Device[], tracking: Map<string, Tracking>, withDocs: boolean): RemediationOverview {
  const all = remediationRows(assets, docs, devices, tracking, withDocs, new Map(), { view: "all" });
  const cur = all.filter((r) => r.present);
  const act = cur.filter((r) => r.status !== "exception");
  const count = <K extends string>(xs: RemediationItem[], f: (r: RemediationItem) => K) =>
    xs.reduce<Partial<Record<K, number>>>((o, r) => ({ ...o, [f(r)]: (o[f(r)] ?? 0) + 1 }), {});
  const today = new Date().toISOString().slice(0, 10);
  return {
    items: act.length, devices: new Set(act.map((r) => r.device_id)).size,
    by_kind: count(act, (r) => r.kind), by_status: count(cur, (r) => r.status),
    high: act.filter((r) => r.severity === "high" || r.severity === "critical").length,
    unassigned: act.filter((r) => !r.assignee && r.status !== "done").length,
    overdue: act.filter((r) => r.due_date && r.due_date < today && r.status !== "done").length,
    resolved_30d: all.filter((r) => !r.present && r.updated_at && Date.now() - Date.parse(r.updated_at) < 30 * 86_400_000).length,
    docs: withDocs,
  };
}
