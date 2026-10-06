"use server";

import { isIP } from "node:net";
import { revalidatePath } from "next/cache";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { z } from "zod";
import { canAdmin, canTriage, getContext } from "./context";
import { isDemo } from "./data/source";
import { createClient } from "./supabase/server";

export type ActionResult = { ok: true; message?: string; value?: string } | { ok: false; error: string };

const fail = (error: string): ActionResult => ({ ok: false, error });
const errText = (e: unknown) => (e instanceof Error ? e.message : "알 수 없는 오류");

// ---------- 경보 처리 ----------
const triageSchema = z.object({
  ids: z.array(z.number().int().positive()).min(1).max(500),
  status: z.enum(["open", "acknowledged", "closed"]).optional(),
  resolution: z.enum(["true_positive", "false_positive", "benign"]).nullable().optional(),
  assignToMe: z.boolean().optional(),
});

export async function triageAlerts(input: z.input<typeof triageSchema>): Promise<ActionResult> {
  const p = triageSchema.safeParse(input);
  if (!p.success) return fail("요청 형식이 올바르지 않습니다");
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("경보를 처리하려면 분석가 이상 권한이 필요합니다");
  if (p.data.status === "closed" && !p.data.resolution) return fail("종결할 때는 판정(실제 위협·오탐·정상 활동)을 선택하세요");
  try {
    await source.updateAlerts(tenant, p.data.ids, p.data);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/", "layout");
  const n = p.data.ids.length;
  const what = p.data.status === "closed" ? "종결했습니다" : p.data.status === "acknowledged" ? "조사 중으로 바꿨습니다" : p.data.status === "open" ? "다시 열었습니다" : "담당자로 지정했습니다";
  return { ok: true, message: `경보 ${n}건을 ${what}` };
}

const commentSchema = z.object({ alertId: z.number().int().positive(), body: z.string().trim().min(1).max(4000) });

export async function addComment(input: z.input<typeof commentSchema>): Promise<ActionResult> {
  const p = commentSchema.safeParse(input);
  if (!p.success) return fail("메모 내용을 입력하세요");
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("메모를 남기려면 분석가 이상 권한이 필요합니다");
  try {
    await source.addComment(tenant, p.data.alertId, p.data.body);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/alerts");
  return { ok: true, message: "메모를 남겼습니다" };
}

// ---------- 예외 규칙 ----------
const suppSchema = z.object({
  rule_id: z.string().max(40).nullable(),
  device_id: z.string().uuid().nullable().or(z.string().max(60).nullable()),
  match: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])),
  reason: z.string().trim().min(2).max(500),
  days: z.number().int().min(1).max(365).nullable(),
});

export async function createSuppression(input: z.input<typeof suppSchema>): Promise<ActionResult> {
  const p = suppSchema.safeParse(input);
  if (!p.success) return fail("예외 이유를 2자 이상 적어 주세요");
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("예외를 만들려면 분석가 이상 권한이 필요합니다");
  try {
    await source.createSuppression(tenant, p.data);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/rules");
  return { ok: true, message: "예외를 만들었습니다. 이후 같은 조건의 경보는 자동 종결됩니다" };
}

export async function deleteSuppression(id: number): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("예외를 지우려면 관리자 권한이 필요합니다");
  try {
    await source.deleteSuppression(tenant, id);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/rules");
  return { ok: true, message: "예외를 지웠습니다" };
}

// ---------- 규칙 ----------
export async function setRuleEnabled(ruleId: string, enabled: boolean): Promise<ActionResult> {
  const { source, viewer } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("규칙을 켜고 끄려면 관리자 권한이 필요합니다");
  if (!/^EDR-[A-Z]+-\d{3}$/.test(ruleId)) return fail("규칙 ID 형식이 올바르지 않습니다");
  try {
    await source.setRuleEnabled(ruleId, enabled);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/rules");
  return { ok: true, message: `${ruleId} 규칙을 ${enabled ? "켰습니다" : "껐습니다"}` };
}

// ---------- 등록키 ----------
const keySchema = z.object({ label: z.string().trim().min(1).max(80), days: z.number().int().min(1).max(365), maxUses: z.number().int().min(1).max(100000) });

export async function createEnrollmentKey(input: z.input<typeof keySchema>): Promise<ActionResult> {
  const p = keySchema.safeParse(input);
  if (!p.success) return fail("이름, 유효 기간(1~365일), 사용 횟수를 확인하세요");
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("등록키는 관리자만 만들 수 있습니다");
  try {
    const key = await source.createEnrollmentKey(tenant, p.data.label, p.data.days, p.data.maxUses);
    revalidatePath("/settings");
    return { ok: true, value: key };
  } catch (e) {
    return fail(errText(e));
  }
}

export async function revokeEnrollmentKey(id: string): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("등록키는 관리자만 폐기할 수 있습니다");
  try {
    await source.revokeEnrollmentKey(tenant, id);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/settings");
  return { ok: true, message: "등록키를 폐기했습니다. 이미 등록된 PC 는 영향 없습니다" };
}

// ---------- 인시던트 ----------
const incSchema = z.object({
  id: z.number().int().positive(),
  status: z.enum(["open", "acknowledged", "closed"]).optional(),
  resolution: z.enum(["true_positive", "false_positive", "benign"]).optional(),
  assignToMe: z.boolean().optional(),
});

export async function triageIncident(input: z.input<typeof incSchema>): Promise<ActionResult> {
  const p = incSchema.safeParse(input);
  if (!p.success) return fail("요청 형식이 올바르지 않습니다");
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("인시던트를 처리하려면 분석가 이상 권한이 필요합니다");
  if (p.data.status === "closed" && !p.data.resolution) return fail("종결할 때는 판정을 선택하세요");
  try {
    await source.updateIncident(tenant, p.data.id, p.data);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/", "layout");
  const what = p.data.status === "closed" ? "종결했습니다. 포함된 경보도 같은 판정으로 종결됩니다" : p.data.status === "acknowledged" ? "조사 중으로 바꿨습니다" : p.data.status === "open" ? "다시 열었습니다" : "담당자로 지정했습니다";
  return { ok: true, message: `인시던트를 ${what}` };
}

export async function addIncidentComment(input: { id: number; body: string }): Promise<ActionResult> {
  const p = z.object({ id: z.number().int().positive(), body: z.string().trim().min(1).max(4000) }).safeParse(input);
  if (!p.success) return fail("메모 내용을 입력하세요");
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("메모를 남기려면 분석가 이상 권한이 필요합니다");
  try {
    await source.addIncidentComment(tenant, p.data.id, p.data.body);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath(`/incidents/${p.data.id}`);
  return { ok: true, message: "메모를 남겼습니다" };
}

// ---------- 저장 쿼리 ----------
export async function saveQuery(input: { name: string; query: string; hours: number }): Promise<ActionResult> {
  const p = z.object({ name: z.string().trim().min(1).max(80), query: z.string().trim().min(1).max(2000), hours: z.number().int().min(1).max(24 * 90) }).safeParse(input);
  if (!p.success) return fail("쿼리 이름(80자 이내)과 내용을 확인하세요");
  const { parseQuery } = await import("./hunt/query");
  const parsed = parseQuery(p.data.query);
  if (!parsed.ok) return fail(parsed.error);
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("쿼리를 저장하려면 분석가 이상 권한이 필요합니다");
  try {
    await source.saveQuery(tenant, p.data.name, p.data.query, p.data.hours);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/hunt");
  return { ok: true, message: `'${p.data.name}' 쿼리를 저장했습니다` };
}

export async function deleteQuery(id: number): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("권한이 없습니다");
  try {
    await source.deleteQuery(tenant, id);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/hunt");
  return { ok: true, message: "저장된 쿼리를 지웠습니다" };
}

// ---------- 위협 지표(IOC) ----------
const SEV = z.enum(["low", "medium", "high", "critical"]);

/** 붙여 넣은 값 하나를 지표로: SHA-256 해시 또는 IP·대역. 아니면 사유 */
export type ParsedIoc = { type: "sha256" | "ip"; value: string } | { error: string; value: string };
function parseIocValue(raw: string): ParsedIoc {
  const v = raw.trim().replace(/^\[|\]$/g, "").replace(/\[\.\]/g, "."); // 1.2.3[.]4 처럼 무력화해 둔 표기도 받는다
  if (/^[0-9a-f]{64}$/i.test(v)) return { type: "sha256", value: v.toLowerCase() };
  if (/^[0-9a-f]{32}$/i.test(v) || /^[0-9a-f]{40}$/i.test(v)) return { error: "MD5·SHA-1 은 지원하지 않습니다(SHA-256 만)", value: v };
  const [addr, mask, extra] = v.split("/");
  const fam = isIP(addr ?? "");
  if (!fam || extra !== undefined) return { error: "SHA-256 해시나 IP 주소·대역이 아닙니다", value: v };
  if (mask !== undefined) {
    const m = Number(mask);
    const max = fam === 4 ? 32 : 128, min = fam === 4 ? 16 : 48;
    if (!/^\d{1,3}$/.test(mask) || m > max) return { error: "대역 표기가 올바르지 않습니다", value: v };
    if (m < min) return { error: `너무 넓은 대역입니다(IPv${fam} /${min} 이상만)`, value: v };
  }
  return { type: "ip", value: v.toLowerCase() };
}

const iocSchema = z.object({
  values: z.string().min(1).max(100_000),
  severity: SEV,
  description: z.string().trim().max(500),
  source: z.string().trim().max(200),
  days: z.number().int().min(1).max(3650).nullable(),
});

export async function createIocs(input: z.input<typeof iocSchema>): Promise<ActionResult> {
  const p = iocSchema.safeParse(input);
  if (!p.success) return fail("입력값을 확인하세요(설명 500자, 출처 200자, 만료 1~3650일)");
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("위협 지표를 등록하려면 분석가 이상 권한이 필요합니다");
  const tokens = [...new Set(p.data.values.split(/[\s,;]+/).map((t) => t.trim()).filter(Boolean))];
  if (tokens.length === 0) return fail("등록할 해시나 IP 를 입력하세요");
  if (tokens.length > 500) return fail("한 번에 500개까지 등록할 수 있습니다");
  const parsed = tokens.map(parseIocValue);
  const bad = parsed.filter((x): x is { error: string; value: string } => "error" in x);
  if (bad.length) return fail(`${bad.length}개 값을 받을 수 없습니다 — ${bad.slice(0, 3).map((b) => `${b.value}: ${b.error}`).join(" / ")}`);
  try {
    const r = await source.createIocs(tenant, parsed.map((x) => ({
      type: (x as { type: "sha256" | "ip" }).type, value: x.value, severity: p.data.severity,
      description: p.data.description, source: p.data.source || null, days: p.data.days,
    })));
    revalidatePath("/iocs");
    revalidatePath("/", "layout");
    const parts = [`${r.created}개 등록`];
    if (r.skipped) parts.push(`이미 있는 ${r.skipped}개는 건너뜀`);
    parts.push(r.hits ? `최근 7일 기록에서 ${r.hits}건 발견 — 경보를 확인하세요` : "최근 7일 기록에서는 발견되지 않았습니다");
    return { ok: true, message: parts.join(". ") };
  } catch (e) {
    return fail(errText(e));
  }
}

export async function setIocEnabled(id: number, enabled: boolean): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("분석가 이상 권한이 필요합니다");
  if (!Number.isInteger(id) || id <= 0) return fail("잘못된 요청입니다");
  try {
    await source.setIocEnabled(tenant, id, enabled);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/iocs");
  return { ok: true, message: enabled ? "지표를 켰습니다. 최근 7일 기록도 다시 찾습니다" : "지표를 껐습니다" };
}

export async function deleteIoc(id: number): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("분석가 이상 권한이 필요합니다");
  if (!Number.isInteger(id) || id <= 0) return fail("잘못된 요청입니다");
  try {
    await source.deleteIoc(tenant, id);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/iocs");
  return { ok: true, message: "지표를 지웠습니다. 이미 만들어진 경보는 그대로 남습니다" };
}

// ---------- 알림 연동 (슬랙·이메일·SIEM) ----------
const RULE_PREFIX = /^[A-Z0-9-]{1,40}$/;
const channelSchema = z.object({
  id: z.number().int().positive().optional(),
  name: z.string().trim().min(1).max(80),
  kind: z.enum(["slack", "email", "syslog", "webhook"]),
  target: z.string().trim().max(500),
  secret_ref: z.string().trim().max(120).regex(/^[A-Z0-9_]*$/, "비밀값 키 이름은 영문 대문자·숫자·밑줄만 쓸 수 있습니다"),
  min_severity: SEV,
  rule_prefixes: z.array(z.string().trim().regex(RULE_PREFIX, "규칙 접두사 형식이 올바르지 않습니다")).max(20),
  enabled: z.boolean(),
});

export async function saveNotificationChannel(input: z.input<typeof channelSchema>): Promise<ActionResult> {
  const p = channelSchema.safeParse(input);
  if (!p.success) return fail(p.error.issues[0]?.message ?? "요청 형식이 올바르지 않습니다");
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("알림 채널은 관리자만 다룰 수 있습니다");
  const d = p.data;
  // 종류별 필수값 확인(비밀값 자체는 저장하지 않고 .env 키 이름만 받는다)
  if (d.kind === "slack" && !d.secret_ref) return fail("슬랙은 웹훅 URL 이 든 .env 키 이름(secret_ref)이 필요합니다");
  if (d.kind === "email" && !d.target) return fail("이메일은 받는 주소가 필요합니다");
  if (d.kind === "syslog" && !d.target) return fail("SIEM(syslog)은 host:port 가 필요합니다");
  if (d.kind === "webhook" && !d.secret_ref && !d.target) return fail("웹훅은 URL 이 든 .env 키 이름이나 주소가 필요합니다");
  try {
    await source.saveNotificationChannel(tenant, d);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/settings");
  return { ok: true, message: d.id ? "알림 채널을 바꿨습니다" : "알림 채널을 추가했습니다" };
}

export async function deleteNotificationChannel(id: number): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("알림 채널은 관리자만 다룰 수 있습니다");
  if (!Number.isInteger(id) || id <= 0) return fail("잘못된 요청입니다");
  try {
    await source.deleteNotificationChannel(tenant, id);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/settings");
  return { ok: true, message: "알림 채널을 지웠습니다" };
}

export async function testNotificationChannel(id: number): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("알림 채널은 관리자만 다룰 수 있습니다");
  if (!Number.isInteger(id) || id <= 0) return fail("잘못된 요청입니다");
  try {
    await source.testNotificationChannel(tenant, id);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/settings");
  return { ok: true, message: "테스트 알림을 대기열에 넣었습니다. 1분 안에 채널로 도착하는지 확인하세요" };
}

// ---------- 소프트웨어 정책(취약 버전·금지) ----------
const swSchema = z.object({
  kind: z.enum(["vulnerable", "prohibited"]),
  name_pattern: z.string().trim().min(2).max(120),
  publisher_pattern: z.string().trim().max(120),
  fixed_version: z.string().trim().max(40).regex(/^$|\d/, "버전에는 숫자가 있어야 합니다"),
  severity: SEV,
  reference: z.string().trim().max(300),
  reason: z.string().trim().max(500),
});

export async function createSoftwarePolicy(input: z.input<typeof swSchema>): Promise<ActionResult> {
  const p = swSchema.safeParse(input);
  if (!p.success) return fail(p.error.issues[0]?.path[0] === "name_pattern" ? "프로그램 이름 조건을 2자 이상 적어 주세요" : "입력값을 확인하세요");
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("소프트웨어 정책은 관리자만 만들 수 있습니다");
  const d = p.data;
  try {
    await source.createSoftwarePolicy(tenant, {
      kind: d.kind, name_pattern: d.name_pattern, publisher_pattern: d.publisher_pattern || null,
      fixed_version: d.kind === "vulnerable" ? d.fixed_version || null : null, severity: d.severity,
      reference: d.reference || null, reason: d.reason,
    });
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/assets");
  return { ok: true, message: d.kind === "prohibited" ? "금지 정책을 만들었습니다. 이미 설치된 PC 는 1분 안에 경보로 알립니다" : "취약 버전 정책을 만들었습니다" };
}

export async function setSoftwarePolicyEnabled(id: number, enabled: boolean): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("관리자 권한이 필요합니다");
  if (!Number.isInteger(id) || id <= 0) return fail("잘못된 요청입니다");
  try {
    await source.setSoftwarePolicyEnabled(tenant, id, enabled);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/assets");
  return { ok: true, message: enabled ? "정책을 켰습니다" : "정책을 껐습니다" };
}

export async function deleteSoftwarePolicy(id: number): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("관리자 권한이 필요합니다");
  if (!Number.isInteger(id) || id <= 0) return fail("잘못된 요청입니다");
  try {
    await source.deleteSoftwarePolicy(tenant, id);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/assets");
  return { ok: true, message: "정책을 지웠습니다" };
}

// ---------- 보안 상태 점검 항목 ----------
export async function setPostureCheckEnabled(checkId: string, enabled: boolean): Promise<ActionResult> {
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("점검 항목은 관리자만 바꿀 수 있습니다");
  if (!/^[a-z0-9_]{2,40}$/.test(checkId)) return fail("잘못된 요청입니다");
  try {
    await source.setPostureCheckEnabled(tenant, checkId, enabled);
  } catch (e) {
    return fail(errText(e));
  }
  revalidatePath("/posture");
  return { ok: true, message: enabled ? "이 항목을 보안 점수에 넣었습니다" : "이 항목을 보안 점수에서 뺐습니다" };
}

// ---------- 문서 감사 (소유자·관리자만) ----------
const noDots = (v: string) => !v.split(/[\\/]/).includes("..");
const docPolicySchema = z.object({
  enabled: z.boolean(),
  interval_hours: z.number().int().min(1).max(2160),
  folders: z.array(z.string().trim().min(1).max(60).regex(/^[^\\/:*?"<>|]+$/).refine(noDots)).max(20),
  extra_paths: z.array(z.string().trim().max(260).regex(/^[A-Za-z]:\\[^*?"<>|]*$/).refine(noDots)).max(20),
  extensions: z.array(z.string().trim().toLowerCase().regex(/^[a-z0-9]{1,8}$/)).min(1).max(40),
  detect: z.array(z.enum(["rrn", "frn", "passport", "driver", "card", "phone"])).max(6),
  keywords: z.array(z.string().trim().min(1).max(100)).max(50),
  stale_days: z.number().int().min(0).max(36500),
  max_file_mb: z.number().int().min(1).max(100),
  confirmNotice: z.boolean(),
});

export async function saveDocPolicy(input: z.input<typeof docPolicySchema>): Promise<ActionResult> {
  const p = docPolicySchema.safeParse(input);
  if (!p.success) {
    const f = p.error.issues[0]?.path[0];
    return fail(f === "extra_paths" ? "추가 경로는 D:\\업무 처럼 드라이브 문자로 시작하는 전체 경로로 적어 주세요"
      : f === "folders" ? "사용자 폴더 이름에 \\ / : * ? \" < > | 나 .. 은 쓸 수 없습니다"
        : f === "keywords" ? "키워드는 50개까지, 하나에 100자까지입니다"
          : f === "extensions" ? "확장자를 하나 이상 고르세요" : "입력값을 확인하세요");
  }
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("문서 감사 정책은 소유자·관리자만 바꿀 수 있습니다");
  const d = p.data;
  const uniq = (xs: string[]) => [...new Map(xs.map((x) => [x.toLowerCase(), x])).values()];
  try {
    const cur = await source.docPolicy(tenant);
    if (d.enabled && !cur.notice_confirmed_at && !d.confirmNotice) return fail("켜기 전에 직원 고지를 마쳤는지 확인란에 표시하세요");
    if (d.enabled && d.detect.length === 0 && d.keywords.length === 0 && d.stale_days === 0) return fail("찾을 대상(개인정보 종류·키워드·오래된 문서 기준) 중 하나는 있어야 합니다");
    await source.saveDocPolicy(tenant, { ...d, folders: uniq(d.folders), extra_paths: uniq(d.extra_paths), extensions: uniq(d.extensions),
      keywords: uniq(d.keywords) });
    revalidatePath("/documents");
    return { ok: true, message: !d.enabled ? "정책을 저장했습니다. 문서 감사는 꺼져 있습니다"
      : cur.enabled ? "정책을 저장했습니다. PC 들은 15분 안에 새 정책을 받습니다"
        : "문서 감사를 켰습니다. PC 들은 15분 안에 정책을 받아 첫 검사를 시작합니다" };
  } catch (e) {
    return fail(errText(e));
  }
}

const docRequestSchema = z.union([z.literal("all"), z.array(z.string().regex(/^[0-9A-Za-z-]{8,64}$/)).min(1).max(5000)]);

/** "지금 검사" 요청. 에이전트가 다음 정책 확인 때(최대 15분) 받아 간다 */
export async function requestDocScan(input: z.input<typeof docRequestSchema>): Promise<ActionResult> {
  const p = docRequestSchema.safeParse(input);
  if (!p.success) return fail("잘못된 요청입니다");
  const { source, viewer, tenant } = await getContext();
  if (!canAdmin(viewer.tenant.role)) return fail("검사 요청은 소유자·관리자만 할 수 있습니다");
  try {
    const pol = await source.docPolicy(tenant);
    if (!pol.enabled) return fail("문서 감사가 꺼져 있습니다. 설정에서 먼저 켜세요");
    const ids = p.data === "all" ? (await source.docDevices(tenant)).map((d) => d.device_id) : p.data;
    const n = await source.requestDocScan(tenant, ids);
    revalidatePath("/documents");
    if (n === 0) return { ok: true, message: "이미 요청이 대기 중입니다. PC 가 받아 가면 검사를 시작합니다" };
    return { ok: true, message: `${n}대에 검사를 요청했습니다. PC 가 켜져 있으면 15분 안에 시작합니다` };
  } catch (e) {
    return fail(errText(e));
  }
}

// ---------- PC 조치 목록 (분석가 이상, 문서 감사 항목은 소유자·관리자) ----------
const remediationSchema = z.object({
  items: z.array(z.object({
    device_id: z.string().regex(/^[0-9A-Za-z-]{8,64}$/),
    kind: z.enum(["posture", "software", "doc_pii", "doc_stale"]),
    item_key: z.string().min(1).max(64),
    title: z.string().max(300),
  })).min(1).max(500),
  status: z.enum(["open", "in_progress", "done", "exception"]).optional(),
  assignee: z.string().regex(/^[0-9A-Za-z-]{2,64}$/).nullable().optional(),   // null = 담당자 비우기
  note: z.string().trim().max(1000).optional(),
  due_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).nullable().optional(),    // null = 기한 비우기
});

export async function updateRemediation(input: z.input<typeof remediationSchema>): Promise<ActionResult> {
  const p = remediationSchema.safeParse(input);
  if (!p.success) return fail(p.error.issues[0]?.path[0] === "note" ? "메모는 1000자까지입니다" : "요청 형식이 올바르지 않습니다");
  const { items, ...patch } = p.data;
  if (patch.status === undefined && patch.assignee === undefined && patch.note === undefined && patch.due_date === undefined) return fail("바꿀 내용을 고르세요");
  const { source, viewer, tenant } = await getContext();
  if (!canTriage(viewer.tenant.role)) return fail("조치 항목을 처리하려면 분석가 이상 권한이 필요합니다");
  if (!canAdmin(viewer.tenant.role) && items.some((i) => i.kind.startsWith("doc_"))) return fail("문서 감사 항목은 소유자·관리자만 처리할 수 있습니다");
  try {
    const n = await source.updateRemediation(tenant, items, patch);
    revalidatePath("/remediation");
    const what = patch.status === "done" ? "완료로 표시했습니다. 다음 수집·검사에서 실제로 고쳐졌는지 확인합니다"
      : patch.status === "exception" ? "예외로 처리했습니다" : patch.status === "in_progress" ? "진행 중으로 바꿨습니다"
        : patch.status === "open" ? "대기로 되돌렸습니다" : patch.assignee !== undefined ? (patch.assignee ? "담당자를 지정했습니다" : "담당자를 비웠습니다") : "저장했습니다";
    return { ok: true, message: `${n}건을 ${what}` };
  } catch (e) {
    return fail(errText(e));
  }
}

// ---------- 조직·테마·로그인 ----------
export async function switchTenant(id: string) {
  (await cookies()).set("edr_tenant", id, { path: "/", httpOnly: true, sameSite: "lax", maxAge: 60 * 60 * 24 * 365 });
  revalidatePath("/", "layout");
}

export async function setTheme(theme: "light" | "dark") {
  const store = await cookies();
  store.set("edr_theme", theme === "light" ? "light" : "dark", { path: "/", sameSite: "lax", maxAge: 60 * 60 * 24 * 365 });
  revalidatePath("/", "layout");
}

const loginSchema = z.object({ email: z.string().email(), password: z.string().min(6), next: z.string().optional() });

export async function signIn(_: ActionResult | null, form: FormData): Promise<ActionResult> {
  const p = loginSchema.safeParse(Object.fromEntries(form));
  if (!p.success) return fail("이메일과 비밀번호(6자 이상)를 확인하세요");
  if (isDemo()) redirect("/");
  const sb = await createClient();
  const { error } = await sb.auth.signInWithPassword({ email: p.data.email, password: p.data.password });
  if (error) return fail("이메일 또는 비밀번호가 맞지 않습니다");
  const next = p.data.next?.startsWith("/") && !p.data.next.startsWith("//") ? p.data.next : "/";
  redirect(next);
}

export async function signOut() {
  if (isDemo()) redirect("/login");
  const sb = await createClient();
  const { data } = await sb.auth.getUser();
  await sb.auth.signOut();
  // 회사 계정(SSO)으로 들어왔으면 Keycloak 세션도 끝내야 "다른 계정으로 로그인"이 된다
  const ssoLogout = process.env.SSO_LOGOUT_URL;
  if (ssoLogout && data.user?.app_metadata?.provider === process.env.NEXT_PUBLIC_SSO_PROVIDER) redirect(ssoLogout);
  redirect("/login");
}
