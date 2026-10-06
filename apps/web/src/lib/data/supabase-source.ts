import "server-only";
import { cookies } from "next/headers";
import { createClient } from "@/lib/supabase/server";
import { PAGE_SIZE, type DataSource } from "./source";
import type { Dataset } from "../hunt/query";
import type {
  Alert, AlertComment, AutorunRow, ConnectionRow, Device, DetectionRule, EnrollmentKey, EntityProfile,
  Incident, MatrixCell, Member, Overview, ProcessRow, Role, SavedQuery, Suppression, Tenant, TimelineItem, TrendPoint,
  AuditEntry, SsoGroupRole, SystemStatus,
  AssetOverview, AssetRow, DeviceInventory, DevicePostureItem, DeviceSoftware, Ioc, PostureDeviceRow, PostureOverview,
  SoftwareChange, SoftwareExposure, SoftwareInstall, SoftwareTitle,
  DocDeviceRow, DocFindingRow, DocOverview, DocScanPolicy, RemediationItem, RemediationOverview,
  NotificationChannel,
} from "./types";
import { DOC_POLICY_DEFAULT } from "./doc-defaults";

const INCIDENT_COLS = "id, title, severity, status, resolution, assigned_to, device_ids, ips, hashes, users, tactics, techniques, rule_ids, alert_count, first_seen_at, last_seen_at, created_at, updated_at";
const DATASET: Record<Dataset, { table: string; ts: string; cols: string }> = {
  process: { table: "process_events", ts: "observed_at", cols: "observed_at, device_id, pid, ppid, name, path, command_line, username, sha256" },
  net: { table: "net_connections", ts: "observed_at", cols: "observed_at, device_id, proto, direction, local_ip, local_port, remote_ip, remote_port, state, pid, process_name, is_external" },
  event: { table: "security_events", ts: "event_time", cols: "event_time, device_id, event_id, channel, target_user, target_domain, logon_type, src_ip, workstation, process_name" },
  autorun: { table: "autoruns", ts: "last_seen_at", cols: "last_seen_at, device_id, location, entry_name, command, image_path, sha256, first_seen_at, removed_at" },
};
const DEVICE_COLS = "id, hostname, os_version, agent_version, status, tags, last_ip, enrolled_at, last_seen_at, health, health_at";
const ALERT_COLS = "id, device_id, rule_id, severity, title, details, status, resolution, assigned_to, created_at, updated_at, incident_id, source, devices(hostname)";

type Client = Awaited<ReturnType<typeof createClient>>;

function must<T>(res: { data: T | null; error: { message: string } | null }): T {
  if (res.error) throw new Error(res.error.message);
  return res.data as T;
}

/** PostgREST or() 필터에 넣을 검색어: 구문을 깨는 문자 제거 */
const orSafe = (q: string) => q.replace(/[%_,()*:."\\]/g, " ").trim();

/** 쓰기(수정·삭제)가 실제로 행을 바꿨는지. RLS 로 막히면 오류 없이 0행이므로 여기서 알린다 */
function changed(res: { data: unknown[] | null; error: { message: string } | null }, what: string) {
  const rows = must(res);
  if (!rows || rows.length === 0) throw new Error(`${what}: 권한이 없거나 이미 없는 항목입니다`);
}

type InvEmbed = Omit<DeviceInventory, "device_id"> & { device_id: string };
type DeviceWithInv = { id: string; hostname: string; last_seen_at: string | null; device_inventory: InvEmbed | InvEmbed[] | null };
const EMPTY_INV: Omit<DeviceInventory, "device_id"> = {
  os_name: null, os_edition: null, os_display_version: null, os_build: null, os_ubr: null, os_product: null, os_arch: null,
  os_installed_at: null, os_label: null, os_end_of_support: null, manufacturer: null, model: null, serial_number: null,
  bios_version: null, cpu: null, cpu_cores: null, memory_mb: null, disk_total_gb: null, disk_free_gb: null, domain: null,
  domain_joined: null, last_user: null, adapters: [], software_count: 0, collected_at: null, updated_at: "",
};
const toAsset = (d: DeviceWithInv): AssetRow => {
  const inv = Array.isArray(d.device_inventory) ? d.device_inventory[0] : d.device_inventory;
  return { ...EMPTY_INV, ...(inv ?? {}), device_id: d.id, hostname: d.hostname, last_seen_at: d.last_seen_at,
    disk_free_gb: inv?.disk_free_gb == null ? null : Number(inv.disk_free_gb), disk_total_gb: inv?.disk_total_gb == null ? null : Number(inv.disk_total_gb) };
};

/** RPC 가 행마다 붙여 주는 전체 개수(count(*) over ())는 Page.total 로 옮기고 행에서는 뺀다 */
function withoutTotal<T extends { total: number }>(row: T): Omit<T, "total"> {
  const { total, ...rest } = row;
  void total;
  return rest;
}

function sinceIso(hours: number) {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

type AlertRow = Omit<Alert, "hostname"> & { devices: { hostname: string } | null };
const toAlert = (r: AlertRow): Alert => {
  const { devices, ...rest } = r;
  return { ...rest, hostname: devices?.hostname ?? null };
};

async function deviceNames(sb: Client, ids: string[]) {
  const uniq = [...new Set(ids)];
  if (uniq.length === 0) return new Map<string, string>();
  const rows = must(await sb.from("devices").select("id, hostname").in("id", uniq)) as { id: string; hostname: string }[];
  return new Map(rows.map((r) => [r.id, r.hostname]));
}

export async function supabaseSource(): Promise<DataSource> {
  const sb = await createClient();

  return {
    async viewer() {
      const { data } = await sb.auth.getUser();
      if (!data.user) return null;
      const rows = must(await sb.from("tenant_members").select("role, tenants(id, name)").eq("user_id", data.user.id)) as unknown as
        { role: Role; tenants: { id: string; name: string } }[];
      const tenants: Tenant[] = rows.map((r) => ({ id: r.tenants.id, name: r.tenants.name, role: r.role }));
      if (tenants.length === 0) return null;
      const chosen = (await cookies()).get("edr_tenant")?.value;
      const tenant = tenants.find((t) => t.id === chosen) ?? tenants[0]!;
      return { userId: data.user.id, email: data.user.email ?? "", tenants, tenant, demo: false };
    },

    async overview(tenant) {
      return must(await sb.rpc("console_overview", { p_tenant: tenant })) as Overview;
    },

    async alertTrend(tenant, days) {
      return must(await sb.rpc("console_alert_trend", { p_tenant: tenant, p_days: days })) as TrendPoint[];
    },

    async logonFailures(tenant, hours) {
      return must(await sb.rpc("console_logon_failures", { p_tenant: tenant, p_hours: hours })) as { bucket: string; n: number }[];
    },

    async alertsSince(tenant, hours) {
      const rows = must(await sb.from("alerts").select(ALERT_COLS).eq("tenant_id", tenant)
        .gte("created_at", sinceIso(hours)).order("created_at", { ascending: false }).limit(1000)) as unknown as AlertRow[];
      return rows.map(toAlert);
    },

    async alerts(tenant, f) {
      const page = Math.max(1, f.page ?? 1);
      let q = sb.from("alerts").select(ALERT_COLS, { count: "exact" }).eq("tenant_id", tenant)
        .gte("created_at", sinceIso((f.days ?? 30) * 24));
      if (f.severity?.length) q = q.in("severity", f.severity);
      if (!f.status || f.status === "active") q = q.neq("status", "closed");
      else if (f.status !== "all") q = q.eq("status", f.status);
      if (f.rule) q = q.eq("rule_id", f.rule);
      if (f.device) q = q.eq("device_id", f.device);
      if (f.source) q = q.eq("source", f.source);
      if (f.q) q = q.ilike("title", `%${f.q.replace(/[%_]/g, "")}%`);
      const res = await q.order("created_at", { ascending: false }).range((page - 1) * PAGE_SIZE, page * PAGE_SIZE - 1);
      const rows = must(res) as unknown as AlertRow[];
      return { rows: rows.map(toAlert), total: res.count ?? rows.length, page, pageSize: PAGE_SIZE };
    },

    async alert(tenant, id) {
      const a = must(await sb.from("alerts").select(ALERT_COLS).eq("tenant_id", tenant).eq("id", id).maybeSingle()) as unknown as AlertRow | null;
      if (!a) return null;
      const [comments, rule, device, members] = await Promise.all([
        sb.from("alert_comments").select("id, alert_id, author_id, body, created_at").eq("alert_id", id).order("created_at"),
        sb.from("detection_rules").select("*").eq("rule_id", a.rule_id).maybeSingle(),
        a.device_id ? sb.from("devices").select(DEVICE_COLS).eq("id", a.device_id).maybeSingle() : Promise.resolve({ data: null, error: null }),
        sb.rpc("console_members", { p_tenant: tenant }),
      ]);
      const emails = new Map(((members.data ?? []) as Member[]).map((m) => [m.user_id, m.email]));
      return {
        alert: toAlert(a),
        comments: (must(comments) as AlertComment[]).map((c) => ({ ...c, author_email: emails.get(c.author_id) ?? undefined })),
        rule: (rule.data as DetectionRule | null) ?? null,
        device: (device.data as Device | null) ?? null,
      };
    },

    async devices(tenant, { q, state = "all", sort = "hostname", page = 1 }) {
      let query = sb.from("devices").select(DEVICE_COLS, { count: "exact" }).eq("tenant_id", tenant).eq("status", "active");
      if (q) query = query.ilike("hostname", `%${q.replace(/[%_]/g, "")}%`);
      const online = sinceIso(0.25), day = sinceIso(24);
      if (state === "online") query = query.gte("last_seen_at", online);
      if (state === "stale") query = query.lt("last_seen_at", online).gte("last_seen_at", day);
      if (state === "offline") query = query.or(`last_seen_at.is.null,last_seen_at.lt.${day}`);
      // "alerts" 정렬은 현재 페이지 안에서만 적용된다(미처리 경보 수는 별도 집계)
      if (sort === "cpu") query = query.order("health->cpu_percent", { ascending: false, nullsFirst: false });
      else if (sort === "memory") query = query.order("health->working_set_mb", { ascending: false, nullsFirst: false });
      else if (sort === "last_seen") query = query.order("last_seen_at", { ascending: true, nullsFirst: true });
      query = query.order("hostname");
      const res = await query.range((page - 1) * PAGE_SIZE, page * PAGE_SIZE - 1);
      const rows = must(res) as Device[];
      // 장치별 미처리 경보 수 (현재 페이지 장치만)
      if (rows.length) {
        const open = must(await sb.from("alerts").select("device_id").eq("tenant_id", tenant).neq("status", "closed")
          .in("device_id", rows.map((d) => d.id)).limit(5000)) as { device_id: string }[];
        const counts = new Map<string, number>();
        open.forEach((o) => counts.set(o.device_id, (counts.get(o.device_id) ?? 0) + 1));
        rows.forEach((d) => (d.open_alerts = counts.get(d.id) ?? 0));
        if (sort === "alerts") rows.sort((a, b) => (b.open_alerts ?? 0) - (a.open_alerts ?? 0));
      }
      return { rows, total: res.count ?? rows.length, page, pageSize: PAGE_SIZE };
    },

    async device(tenant, id) {
      return (must(await sb.from("devices").select(DEVICE_COLS).eq("tenant_id", tenant).eq("id", id).maybeSingle()) as Device | null);
    },

    async deviceTimeline(_tenant, id, hours) {
      return must(await sb.rpc("console_device_timeline", { p_device: id, p_hours: hours, p_limit: 400 })) as TimelineItem[];
    },

    async deviceProcesses(_tenant, id) {
      const rows = must(await sb.from("processes_current")
        .select("pid, ppid, create_time, name, path, command_line, username, sha256, first_seen_at")
        .eq("device_id", id).limit(3000)) as ProcessRow[];
      const shas = [...new Set(rows.map((r) => r.sha256).filter((s): s is string => !!s))];
      if (shas.length) {
        const v = must(await sb.from("file_hashes").select("sha256, verdict").in("sha256", shas)) as { sha256: string; verdict: string }[];
        const m = new Map(v.map((x) => [x.sha256, x.verdict]));
        rows.forEach((r) => (r.verdict = r.sha256 ? m.get(r.sha256) ?? null : null));
      }
      return rows;
    },

    async deviceConnections(_tenant, id, { externalOnly, hours }) {
      let q = sb.from("net_connections")
        .select("observed_at, proto, direction, local_ip, local_port, remote_ip, remote_port, state, pid, process_name, is_external")
        .eq("device_id", id).gte("observed_at", sinceIso(hours));
      if (externalOnly) q = q.eq("is_external", true);
      return must(await q.order("observed_at", { ascending: false }).limit(500)) as ConnectionRow[];
    },

    async deviceAutoruns(_tenant, id) {
      return must(await sb.from("autoruns")
        .select("location, entry_name, command, image_path, sha256, first_seen_at, last_seen_at, removed_at")
        .eq("device_id", id).order("location").order("entry_name").limit(2000)) as AutorunRow[];
    },

    async rules(tenant) {
      const [rules, hits] = await Promise.all([
        sb.from("detection_rules").select("*").order("rule_id"),
        sb.from("alerts").select("rule_id").eq("tenant_id", tenant).gte("created_at", sinceIso(24 * 7)).limit(10000),
      ]);
      const counts = new Map<string, number>();
      ((must(hits) as { rule_id: string }[])).forEach((h) => counts.set(h.rule_id, (counts.get(h.rule_id) ?? 0) + 1));
      return (must(rules) as DetectionRule[]).map((r) => ({ ...r, hits_7d: counts.get(r.rule_id) ?? 0 }));
    },

    async suppressions(tenant) {
      return must(await sb.from("alert_suppressions")
        .select("id, rule_id, device_id, match, reason, created_at, expires_at, hit_count")
        .eq("tenant_id", tenant).order("created_at", { ascending: false })) as Suppression[];
    },

    async enrollmentKeys(tenant) {
      return must(await sb.from("enrollment_keys").select("id, label, max_uses, used_count, expires_at, revoked, created_at")
        .eq("tenant_id", tenant).order("created_at", { ascending: false })) as EnrollmentKey[];
    },

    async members(tenant) {
      return must(await sb.rpc("console_members", { p_tenant: tenant })) as Member[];
    },

    async updateAlerts(tenant, ids, patch) {
      const body: Record<string, unknown> = {};
      if (patch.status) body.status = patch.status;
      if (patch.resolution !== undefined) body.resolution = patch.resolution;
      if (patch.assignToMe) body.assigned_to = (await sb.auth.getUser()).data.user?.id ?? null;
      must(await sb.from("alerts").update(body).eq("tenant_id", tenant).in("id", ids).select("id"));
    },

    async addComment(tenant, alertId, body) {
      const uid = (await sb.auth.getUser()).data.user?.id;
      must(await sb.from("alert_comments").insert({ tenant_id: tenant, alert_id: alertId, author_id: uid, body }).select("id"));
    },

    async createSuppression(tenant, s) {
      const uid = (await sb.auth.getUser()).data.user?.id;
      must(await sb.from("alert_suppressions").insert({
        tenant_id: tenant, rule_id: s.rule_id, device_id: s.device_id, match: s.match, reason: s.reason, created_by: uid,
        expires_at: s.days ? new Date(Date.now() + s.days * 86400_000).toISOString() : null,
      }).select("id"));
    },

    async deleteSuppression(tenant, id) {
      must(await sb.from("alert_suppressions").delete().eq("tenant_id", tenant).eq("id", id).select("id"));
    },

    async setRuleEnabled(ruleId, enabled) {
      const rows = must(await sb.from("detection_rules").update({ enabled, updated_at: new Date().toISOString() })
        .eq("rule_id", ruleId).select("rule_id")) as unknown[];
      if (rows.length === 0) throw new Error("규칙을 바꿀 권한이 없습니다 (owner/admin 필요)");
    },

    async createEnrollmentKey(tenant, label, days, maxUses) {
      return must(await sb.rpc("create_enrollment_key", { p_tenant: tenant, p_label: label, p_max_uses: maxUses, p_days: days })) as string;
    },

    async revokeEnrollmentKey(tenant, id) {
      must(await sb.from("enrollment_keys").update({ revoked: true }).eq("tenant_id", tenant).eq("id", id).select("id"));
    },
    // ---------------- 인시던트 ----------------
    async incidents(tenant, f) {
      const page = Math.max(1, f.page ?? 1);
      let q = sb.from("incidents").select(INCIDENT_COLS, { count: "exact" }).eq("tenant_id", tenant)
        .gte("last_seen_at", sinceIso((f.days ?? 30) * 24));
      if (f.severity?.length) q = q.in("severity", f.severity);
      if (!f.status || f.status === "active") q = q.neq("status", "closed");
      else if (f.status !== "all") q = q.eq("status", f.status);
      if (f.q) q = q.ilike("title", `%${f.q.replace(/[%_]/g, "")}%`);
      const res = await q.order("last_seen_at", { ascending: false }).range((page - 1) * PAGE_SIZE, page * PAGE_SIZE - 1);
      const rows = must(res) as Incident[];
      const names = await deviceNames(sb, rows.flatMap((r) => r.device_ids));
      rows.forEach((r) => (r.hostnames = r.device_ids.map((id) => names.get(id) ?? "?")));
      return { rows, total: res.count ?? rows.length, page, pageSize: PAGE_SIZE };
    },

    async incident(tenant, id) {
      const inc = must(await sb.from("incidents").select(INCIDENT_COLS).eq("tenant_id", tenant).eq("id", id).maybeSingle()) as Incident | null;
      if (!inc) return null;
      const devIds = inc.device_ids.slice(0, 8);
      const [alerts, comments, devices, rules, members] = await Promise.all([
        sb.from("alerts").select(ALERT_COLS).eq("incident_id", id).order("created_at").limit(500),
        sb.from("incident_comments").select("id, incident_id, author_id, body, created_at").eq("incident_id", id).order("created_at"),
        devIds.length ? sb.from("devices").select(DEVICE_COLS).in("id", devIds) : Promise.resolve({ data: [], error: null }),
        sb.from("detection_rules").select("*").in("rule_id", inc.rule_ids.length ? inc.rule_ids : ["-"]),
        sb.rpc("console_members", { p_tenant: tenant }),
      ]);
      const devs = must(devices) as Device[];
      inc.hostnames = inc.device_ids.map((d) => devs.find((x) => x.id === d)?.hostname ?? "?");
      const processes: Record<string, ProcessRow[]> = {};
      const connections: Record<string, ConnectionRow[]> = {};
      await Promise.all(devIds.slice(0, 5).map(async (d) => {
        const [p, c] = await Promise.all([
          sb.from("processes_current").select("pid, ppid, create_time, name, path, command_line, username, sha256, first_seen_at").eq("device_id", d).limit(3000),
          sb.from("net_connections").select("observed_at, proto, direction, local_ip, local_port, remote_ip, remote_port, state, pid, process_name, is_external")
            .eq("device_id", d).eq("is_external", true).gte("observed_at", new Date(Date.parse(inc.first_seen_at) - 3600_000).toISOString()).limit(500),
        ]);
        processes[d] = must(p) as ProcessRow[];
        connections[d] = must(c) as ConnectionRow[];
      }));
      const shas = [...new Set(Object.values(processes).flat().map((p) => p.sha256).filter((x): x is string => !!x))];
      if (shas.length) {
        const v = must(await sb.from("file_hashes").select("sha256, verdict").in("sha256", shas.slice(0, 1000))) as { sha256: string; verdict: string }[];
        const m = new Map(v.map((x) => [x.sha256, x.verdict]));
        Object.values(processes).flat().forEach((p) => (p.verdict = p.sha256 ? m.get(p.sha256) ?? null : null));
      }
      const emails = new Map(((members.data ?? []) as Member[]).map((m) => [m.user_id, m.email]));
      return {
        incident: inc,
        alerts: (must(alerts) as unknown as AlertRow[]).map(toAlert),
        comments: (must(comments) as (AlertComment & { incident_id: number })[]).map((c) => ({ ...c, alert_id: 0, author_email: emails.get(c.author_id) ?? undefined })),
        devices: devs,
        rules: must(rules) as DetectionRule[],
        processes,
        connections,
      };
    },

    async updateIncident(tenant, id, patch) {
      if (patch.status === "closed") {
        must(await sb.rpc("console_close_incident", { p_incident: id, p_resolution: patch.resolution ?? "benign" }));
        return;
      }
      // 인시던트와 딸린 경보를 한 트랜잭션에서 바꾼다(감사 기록은 인시던트 한 줄). 권한 없으면 DB 가 거부.
      const { error } = await sb.rpc("console_update_incident", { p_incident: id, p_status: patch.status ?? null, p_assign_to_me: !!patch.assignToMe });
      if (error) throw new Error(error.code === "42501" ? "인시던트를 바꿀 권한이 없습니다" : error.message);
    },

    async addIncidentComment(tenant, id, body) {
      const uid = (await sb.auth.getUser()).data.user?.id;
      must(await sb.from("incident_comments").insert({ tenant_id: tenant, incident_id: id, author_id: uid, body }).select("id"));
    },

    // ---------------- 엔터티 ----------------
    async entity(tenant, kind, value, days) {
      const res = (must(await sb.rpc("console_entity", { p_tenant: tenant, p_kind: kind, p_value: value, p_days: days })) ?? {}) as Record<string, unknown>;
      const key = kind === "ip" ? "details->>src_ip" : kind === "hash" ? "details->>sha256" : "details->>user";
      const [alerts, incs] = await Promise.all([
        sb.from("alerts").select(ALERT_COLS).eq("tenant_id", tenant).eq(key, kind === "hash" ? value.toLowerCase() : value)
          .order("created_at", { ascending: false }).limit(50),
        sb.from("incidents").select(INCIDENT_COLS).eq("tenant_id", tenant)
          .contains(kind === "ip" ? "ips" : kind === "hash" ? "hashes" : "users", [kind === "hash" ? value.toLowerCase() : value])
          .order("last_seen_at", { ascending: false }).limit(20),
      ]);
      const { first_seen, last_seen, observations, devices, ...facts } = res;
      return {
        kind, value,
        first_seen: (first_seen as string) ?? null, last_seen: (last_seen as string) ?? null,
        observations: Number(observations ?? 0),
        devices: (devices as EntityProfile["devices"]) ?? [],
        facts,
        alerts: (must(alerts) as unknown as AlertRow[]).map(toAlert),
        incidents: must(incs) as Incident[],
      };
    },

    async attackMatrix(tenant, days) {
      return must(await sb.rpc("console_attack_matrix", { p_tenant: tenant, p_days: days })) as MatrixCell[];
    },

    // ---------------- 쿼리 헌팅 ----------------
    async runQuery(tenant, query, hours) {
      const t0 = Date.now();
      const ds = DATASET[query.dataset];
      // 텔레메트리 테이블에는 devices 외래키가 없으므로(적재 속도 우선) 장치 이름 조건은 장치 id 목록으로 바꿔 건다
      const hostTerms = query.terms.filter((t) => t.field.key === "device.hostname");
      let deviceFilter: string[] | null = null;
      if (hostTerms.length) {
        let dq = sb.from("devices").select("id").eq("tenant_id", tenant);
        for (const t of hostTerms) {
          const v = t.value.replace(/[%_]/g, "");
          if (t.op === "=") dq = dq.ilike("hostname", v);
          else if (t.op === "!=") dq = dq.not("hostname", "ilike", v);
          else if (t.op === "~") dq = dq.ilike("hostname", `%${v}%`);
          else if (t.op === "!~") dq = dq.not("hostname", "ilike", `%${v}%`);
        }
        deviceFilter = (must(await dq.limit(5000)) as { id: string }[]).map((d) => d.id);
        if (deviceFilter.length === 0) return { dataset: query.dataset, rows: [], truncated: false, ms: Date.now() - t0 };
      }
      let q = sb.from(ds.table).select(ds.cols).eq("tenant_id", tenant);
      if (query.dataset !== "autorun") q = q.gte(ds.ts, sinceIso(hours));
      if (deviceFilter) q = q.in("device_id", deviceFilter);
      for (const t of query.terms) {
        if (t.field.key === "device.hostname") continue;
        const col = t.field.column;
        const v = t.value.replace(/[%_]/g, "");
        if (t.op === "=") q = t.field.kind === "text" ? q.ilike(col, v) : q.eq(col, t.value);
        else if (t.op === "!=") q = t.field.kind === "text" ? q.not(col, "ilike", v) : q.neq(col, t.value);
        else if (t.op === "~") q = q.ilike(col, `%${v}%`);
        else if (t.op === "!~") q = q.not(col, "ilike", `%${v}%`);
        else if (t.op === ">") q = q.gt(col, t.value);
        else if (t.op === "<") q = q.lt(col, t.value);
        else if (t.op === ">=") q = q.gte(col, t.value);
        else if (t.op === "<=") q = q.lte(col, t.value);
      }
      const rows = must(await q.order(ds.ts, { ascending: false }).limit(501)) as unknown as Record<string, unknown>[];
      const names = await deviceNames(sb, rows.map((r) => String(r.device_id)));
      return {
        dataset: query.dataset,
        rows: rows.slice(0, 500).map((r) => ({ ...r, ts: r[ds.ts], hostname: names.get(String(r.device_id)) ?? null })),
        truncated: rows.length > 500,
        ms: Date.now() - t0,
      };
    },

    async savedQueries(tenant) {
      return must(await sb.from("saved_queries").select("id, name, query, hours, created_at, created_by").eq("tenant_id", tenant).order("name")) as SavedQuery[];
    },

    async saveQuery(tenant, name, query, hours) {
      const uid = (await sb.auth.getUser()).data.user?.id;
      must(await sb.from("saved_queries").insert({ tenant_id: tenant, name, query, hours, created_by: uid }).select("id"));
    },

    async deleteQuery(tenant, id) {
      must(await sb.from("saved_queries").delete().eq("tenant_id", tenant).eq("id", id).select("id"));
    },

    // ---------------- 운영 상태 · 감사 기록 ----------------
    async systemStatus(tenant) {
      return must(await sb.rpc("console_system_status", { p_tenant: tenant })) as SystemStatus;
    },

    async auditLog(tenant, opts) {
      const page = Math.max(1, opts.page ?? 1);
      let q = sb.from("audit_log")
        .select("id, actor_id, actor_email, action, target_type, target_id, target_label, changes, created_at", { count: "exact" })
        .eq("tenant_id", tenant).order("created_at", { ascending: false }).order("id", { ascending: false })
        .range((page - 1) * PAGE_SIZE, page * PAGE_SIZE - 1);
      if (opts.action) q = q.like("action", `${opts.action}%`);
      const { data, error, count } = await q;
      if (error) throw new Error(error.message);
      return { rows: (data ?? []) as AuditEntry[], total: count ?? 0, page, pageSize: PAGE_SIZE };
    },

    async ssoGroupRoles(tenant) {
      return must(await sb.from("sso_group_roles").select("provider, idp_group, role, created_at")
        .eq("tenant_id", tenant).order("role").order("idp_group")) as SsoGroupRole[];
    },

    // ---------------- 자산 · 소프트웨어 ----------------
    async assetOverview(tenant) {
      return must(await sb.rpc("console_asset_overview", { p_tenant: tenant })) as AssetOverview;
    },

    async assets(tenant, { q, filter = "all", page = 1, pageSize = PAGE_SIZE }) {
      page = Math.max(1, page);
      const embed = filter === "low_disk" ? "device_inventory!inner(*)" : "device_inventory(*)";
      let query = sb.from("devices").select(`id, hostname, last_seen_at, ${embed}`, { count: "exact" })
        .eq("tenant_id", tenant).eq("status", "active");
      if (filter === "low_disk") query = query.lt("device_inventory.disk_free_gb", 10);
      if (filter === "unsupported" || filter === "ending") {
        const ids = (must(await sb.from("device_posture").select("device_id").eq("tenant_id", tenant).eq("check_id", "os_supported")
          .eq("status", filter === "unsupported" ? "fail" : "warn").limit(5000)) as { device_id: string }[]).map((r) => r.device_id);
        if (ids.length === 0) return { rows: [], total: 0, page, pageSize };
        query = query.in("id", ids);
      }
      const term = q ? orSafe(q) : "";
      if (term) {
        // 장치 이름 또는 일련번호·모델·마지막 사용자
        const ids = (must(await sb.from("device_inventory").select("device_id").eq("tenant_id", tenant)
          .or(`serial_number.ilike.*${term}*,model.ilike.*${term}*,last_user.ilike.*${term}*,manufacturer.ilike.*${term}*`).limit(500)) as { device_id: string }[])
          .map((r) => r.device_id);
        query = ids.length ? query.or(`hostname.ilike.*${term}*,id.in.(${ids.join(",")})`) : query.ilike("hostname", `%${term}%`);
      }
      const res = await query.order("hostname").range((page - 1) * pageSize, page * pageSize - 1);
      const rows = must(res) as unknown as DeviceWithInv[];
      return { rows: rows.map(toAsset), total: res.count ?? rows.length, page, pageSize };
    },

    async deviceInventory(tenant, id) {
      const r = must(await sb.from("device_inventory").select("*").eq("tenant_id", tenant).eq("device_id", id).maybeSingle()) as DeviceInventory | null;
      return r && { ...r, disk_free_gb: r.disk_free_gb == null ? null : Number(r.disk_free_gb), disk_total_gb: r.disk_total_gb == null ? null : Number(r.disk_total_gb) };
    },

    async deviceSoftware(tenant, id) {
      return must(await sb.from("device_software").select("name, version, publisher, install_date, scope, arch, first_seen_at")
        .eq("tenant_id", tenant).eq("device_id", id).order("name").limit(5000)) as DeviceSoftware[];
    },

    async softwareCatalog(tenant, { q, page = 1, pageSize = PAGE_SIZE }) {
      page = Math.max(1, page);
      const rows = must(await sb.rpc("console_software_catalog", { p_tenant: tenant, p_q: q ?? null, p_limit: pageSize, p_offset: (page - 1) * pageSize })) as
        (SoftwareTitle & { total: number })[];
      return { rows: rows.map(withoutTotal), total: rows[0]?.total ?? 0, page, pageSize };
    },

    async softwareInstalls(tenant, name) {
      return must(await sb.rpc("console_software_devices", { p_tenant: tenant, p_name: name })) as SoftwareInstall[];
    },

    async softwareChanges(tenant, { device, days = 30, page = 1, pageSize = PAGE_SIZE }) {
      page = Math.max(1, page);
      let q = sb.from("software_changes").select("id, device_id, change, name, version, prev_version, publisher, observed_at", { count: "exact" })
        .eq("tenant_id", tenant).gte("observed_at", sinceIso(days * 24));
      if (device) q = q.eq("device_id", device);
      const res = await q.order("observed_at", { ascending: false }).order("id", { ascending: false }).range((page - 1) * pageSize, page * pageSize - 1);
      const rows = must(res) as SoftwareChange[];
      const names = await deviceNames(sb, rows.map((r) => r.device_id));
      return { rows: rows.map((r) => ({ ...r, hostname: names.get(r.device_id) ?? null })), total: res.count ?? rows.length, page, pageSize };
    },

    async softwareExposure(tenant) {
      const rows = must(await sb.rpc("console_software_exposure", { p_tenant: tenant })) as SoftwareExposure[];
      const names = await deviceNames(sb, rows.flatMap((r) => r.device_ids.slice(0, 8)));
      return rows.map((r) => ({ ...r, hostnames: r.device_ids.slice(0, 8).map((id) => names.get(id) ?? id) }));
    },

    async createSoftwarePolicy(tenant, p) {
      const uid = (await sb.auth.getUser()).data.user?.id;
      must(await sb.from("software_policies").insert({ tenant_id: tenant, ...p, created_by: uid }).select("id"));
    },

    async setSoftwarePolicyEnabled(tenant, id, enabled) {
      changed(await sb.from("software_policies").update({ enabled }).eq("tenant_id", tenant).eq("id", id).select("id"), "정책 변경");
    },

    async deleteSoftwarePolicy(tenant, id) {
      changed(await sb.from("software_policies").delete().eq("tenant_id", tenant).eq("id", id).select("id"), "정책 삭제");
    },

    // ---------------- 보안 상태 ----------------
    async postureOverview(tenant) {
      return must(await sb.rpc("console_posture_overview", { p_tenant: tenant })) as PostureOverview;
    },

    async postureDevices(tenant, { check, status, page = 1, pageSize = PAGE_SIZE }) {
      page = Math.max(1, page);
      const rows = must(await sb.rpc("console_posture_devices", {
        p_tenant: tenant, p_check: check ?? null, p_status: status ?? "fail", p_limit: pageSize, p_offset: (page - 1) * pageSize,
      })) as (PostureDeviceRow & { total: number })[];
      return { rows: rows.map(withoutTotal), total: rows[0]?.total ?? 0, page, pageSize };
    },

    async devicePosture(_tenant, id) {
      const [items, score] = await Promise.all([
        sb.rpc("console_device_posture", { p_device: id }),
        sb.rpc("edr_posture_score", { p_device: id }),
      ]);
      return { items: must(items) as DevicePostureItem[], score: (must(score) as number | null) ?? null };
    },

    async setPostureCheckEnabled(tenant, checkId, enabled) {
      const uid = (await sb.auth.getUser()).data.user?.id;
      changed(await sb.from("posture_policies").upsert(
        { tenant_id: tenant, check_id: checkId, enabled, updated_by: uid, updated_at: new Date().toISOString() },
        { onConflict: "tenant_id,check_id" }).select("check_id"), "점검 항목 변경");
    },

    // ---------------- 위협 지표 ----------------
    async iocs(tenant) {
      const [rows, members] = await Promise.all([
        sb.from("iocs").select("id, type, value, severity, description, source, enabled, expires_at, hit_count, last_hit_at, created_by, created_at")
          .eq("tenant_id", tenant).order("created_at", { ascending: false }).order("id", { ascending: false }).limit(2000),
        sb.rpc("console_members", { p_tenant: tenant }),
      ]);
      const emails = new Map(((members.data ?? []) as Member[]).map((m) => [m.user_id, m.email]));
      return (must(rows) as Ioc[]).map((r) => ({ ...r, created_by_email: r.created_by ? emails.get(r.created_by) ?? null : null }));
    },

    async createIocs(tenant, list) {
      const uid = (await sb.auth.getUser()).data.user?.id;
      const rows = list.map((i) => ({
        tenant_id: tenant, type: i.type, value: i.value, severity: i.severity, description: i.description, source: i.source,
        expires_at: i.days ? new Date(Date.now() + i.days * 86_400_000).toISOString() : null, created_by: uid,
      }));
      // 이미 등록된 지표는 건너뛴다(ON CONFLICT DO NOTHING). 등록과 동시에 DB 트리거가 최근 7일을 소급해 찾는다
      const inserted = must(await sb.from("iocs").upsert(rows, { onConflict: "tenant_id,type,value", ignoreDuplicates: true }).select("id")) as { id: number }[];
      let hits = 0;
      if (inserted.length) {
        const after = must(await sb.from("iocs").select("hit_count").in("id", inserted.map((r) => r.id))) as { hit_count: number }[];
        hits = after.reduce((s, r) => s + Number(r.hit_count), 0);
      }
      return { created: inserted.length, skipped: list.length - inserted.length, hits };
    },

    async setIocEnabled(tenant, id, enabled) {
      changed(await sb.from("iocs").update({ enabled }).eq("tenant_id", tenant).eq("id", id).select("id"), "위협 지표 변경");
    },

    async deleteIoc(tenant, id) {
      changed(await sb.from("iocs").delete().eq("tenant_id", tenant).eq("id", id).select("id"), "위협 지표 삭제");
    },

    // ---------------- 알림 연동 ----------------
    async notificationChannels(tenant) {
      const [rows, outbox] = await Promise.all([
        sb.from("notification_channels").select("id, name, kind, target, secret_ref, min_severity, rule_prefixes, enabled, updated_at")
          .eq("tenant_id", tenant).order("name"),
        sb.from("notification_outbox").select("channel_id, status, sent_at").eq("tenant_id", tenant).order("sent_at", { ascending: false }).limit(5000),
      ]);
      const stat = new Map<number, { pending: number; failed: number; last: string | null }>();
      for (const o of (outbox.data ?? []) as { channel_id: number; status: string; sent_at: string | null }[]) {
        const s = stat.get(o.channel_id) ?? { pending: 0, failed: 0, last: null };
        if (o.status === "pending") s.pending++;
        else if (o.status === "failed") s.failed++;
        else if (o.status === "sent" && o.sent_at && !s.last) s.last = o.sent_at;
        stat.set(o.channel_id, s);
      }
      return (must(rows) as NotificationChannel[]).map((c) => {
        const s = stat.get(c.id);
        return { ...c, rule_prefixes: c.rule_prefixes ?? [], last_sent_at: s?.last ?? null, pending: s?.pending ?? 0, failed: s?.failed ?? 0 };
      });
    },

    async saveNotificationChannel(tenant, input) {
      const row = {
        tenant_id: tenant, name: input.name, kind: input.kind, target: input.target, secret_ref: input.secret_ref,
        min_severity: input.min_severity, rule_prefixes: input.rule_prefixes, enabled: input.enabled, updated_at: new Date().toISOString(),
      };
      if (input.id) {
        changed(await sb.from("notification_channels").update(row).eq("tenant_id", tenant).eq("id", input.id).select("id"), "알림 채널 변경");
      } else {
        changed(await sb.from("notification_channels").insert(row).select("id"), "알림 채널 추가");
      }
    },

    async deleteNotificationChannel(tenant, id) {
      changed(await sb.from("notification_channels").delete().eq("tenant_id", tenant).eq("id", id).select("id"), "알림 채널 삭제");
    },

    async testNotificationChannel(_tenant, id) {
      const r = await sb.rpc("console_notification_test", { p_channel: id });
      if (r.error) throw new Error(r.error.message);
    },

    // ---------------- 문서 감사 (권한·조회 감사는 DB 함수·RLS 가 판단) ----------------
    async docPolicy(tenant) {
      const [row, members] = await Promise.all([
        sb.from("doc_scan_policies").select("enabled, interval_hours, folders, extra_paths, extensions, detect, keywords, stale_days, max_file_mb, notice_confirmed_at, notice_confirmed_by, updated_at")
          .eq("tenant_id", tenant).maybeSingle(),
        sb.rpc("console_members", { p_tenant: tenant }),
      ]);
      const p = must(row) as DocScanPolicy | null;
      if (!p) return { ...DOC_POLICY_DEFAULT };
      const emails = new Map(((members.data ?? []) as Member[]).map((m) => [m.user_id, m.email]));
      return { ...p, notice_confirmed_by_email: p.notice_confirmed_by ? emails.get(p.notice_confirmed_by) ?? null : null };
    },

    async saveDocPolicy(tenant, p) {
      const uid = (await sb.auth.getUser()).data.user?.id;
      const { confirmNotice, ...rest } = p;
      const now = new Date().toISOString();
      // 고지 확인은 이번에 확인했을 때만 바꾼다(빼 두면 기존 값 유지)
      const row = { tenant_id: tenant, ...rest, updated_by: uid, updated_at: now, ...(confirmNotice ? { notice_confirmed_at: now, notice_confirmed_by: uid } : {}) };
      const res = await sb.from("doc_scan_policies").upsert(row, { onConflict: "tenant_id" }).select("tenant_id");
      if (res.error?.message.includes("check constraint")) throw new Error("직원 고지 완료를 확인해야 문서 감사를 켤 수 있습니다");
      changed(res, "문서 감사 정책 저장");
    },

    async docOverview(tenant) {
      return must(await sb.rpc("console_doc_overview", { p_tenant: tenant })) as DocOverview;
    },

    async docFindings(tenant, { kind, q, device, keyword, page = 1, pageSize = PAGE_SIZE, purpose = "view" }) {
      page = Math.max(1, page);
      const rows = must(await sb.rpc("console_doc_findings", {
        p_tenant: tenant, p_kind: kind, p_q: q || null, p_device: device || null, p_keyword: keyword || null,
        p_limit: pageSize, p_offset: (page - 1) * pageSize, p_purpose: purpose,
      })) as (DocFindingRow & { total: number })[];
      return { rows: rows.map(withoutTotal), total: Number(rows[0]?.total ?? 0), page, pageSize };
    },

    async docDevices(tenant) {
      return must(await sb.rpc("console_doc_devices", { p_tenant: tenant })) as DocDeviceRow[];
    },

    async requestDocScan(tenant, deviceIds) {
      const uid = (await sb.auth.getUser()).data.user?.id;
      if (!uid || deviceIds.length === 0) return 0;
      // 이미 대기 중(7일 이내 미완료)인 장치는 다시 요청하지 않는다
      const pending = must(await sb.from("doc_scan_requests").select("device_id").eq("tenant_id", tenant).is("completed_at", null)
        .gt("requested_at", new Date(Date.now() - 7 * 86_400_000).toISOString()).in("device_id", deviceIds)) as { device_id: string }[];
      const skip = new Set(pending.map((r) => r.device_id));
      const rows = deviceIds.filter((d) => !skip.has(d)).map((device_id) => ({ tenant_id: tenant, device_id, requested_by: uid }));
      if (rows.length === 0) return 0;
      const inserted = must(await sb.from("doc_scan_requests").insert(rows).select("id")) as { id: number }[];
      return inserted.length;
    },

    // ---------------- PC 조치 목록 (계산·권한·감사는 DB 함수) ----------------
    async remediationOverview(tenant) {
      return must(await sb.rpc("console_remediation_overview", { p_tenant: tenant })) as RemediationOverview;
    },

    async remediation(tenant, { kind, view = "active", device, assignee, q, page = 1, pageSize = PAGE_SIZE }) {
      page = Math.max(1, page);
      const [res, members] = await Promise.all([
        sb.rpc("console_remediation", {
          p_tenant: tenant, p_kind: kind ?? null, p_status: view, p_device: device || null, p_assignee: assignee || null,
          p_q: q || null, p_limit: pageSize, p_offset: (page - 1) * pageSize,
        }),
        sb.rpc("console_members", { p_tenant: tenant }),
      ]);
      const rows = must(res) as (RemediationItem & { total: number })[];
      const emails = new Map(((members.data ?? []) as Member[]).map((m) => [m.user_id, m.email]));
      return {
        rows: rows.map(withoutTotal).map((r) => ({ ...r, assignee_email: r.assignee ? emails.get(r.assignee) ?? null : null })),
        total: Number(rows[0]?.total ?? 0), page, pageSize,
      };
    },

    async updateRemediation(tenant, items, patch) {
      return must(await sb.rpc("console_remediation_update", {
        p_tenant: tenant, p_items: items, p_status: patch.status ?? null,
        p_assignee: patch.assignee ?? null, p_clear_assignee: patch.assignee === null,
        p_note: patch.note ?? null, p_due_date: patch.due_date ?? null, p_clear_due: patch.due_date === null,
      })) as number;
    },
  };
}
