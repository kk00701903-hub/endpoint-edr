import Link from "next/link";
import { AlertTriangle, CheckCircle2, CircleX } from "lucide-react";
import { EnrollDialog } from "@/components/enroll-dialog";
import { NotificationControls } from "@/components/notification-controls";
import { RevokeKey } from "@/components/rule-controls";
import { Empty, PageHeader, Panel, Segmented } from "@/components/ui";
import { cn } from "@/lib/cn";
import { canAdmin, getContext } from "@/lib/context";
import type { AuditEntry, SystemStatus } from "@/lib/data/types";
import { RESOLUTION_LABEL, ROLE_LABEL, SEVERITY_LABEL, STATUS_LABEL, ago, day, fullDay, nowMs, num, stamp } from "@/lib/format";

export const metadata = { title: "설정" };

const AUDIT_FILTERS = [
  { value: "", label: "전체" }, { value: "incident", label: "인시던트" }, { value: "alert", label: "경보" }, { value: "rule", label: "규칙" },
  { value: "suppression", label: "예외" }, { value: "enrollment_key", label: "등록키" }, { value: "member", label: "구성원" },
  { value: "ioc", label: "위협 지표" }, { value: "sw_policy", label: "SW 정책" }, { value: "posture_policy", label: "보안 점검" },
  { value: "doc_scan", label: "문서 감사" }, { value: "remediation", label: "PC 조치" },
  { value: "notification", label: "알림 연동" },
] as const;
type AuditFilter = (typeof AUDIT_FILTERS)[number]["value"];

export default async function SettingsPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const { source, viewer, tenant } = await getContext();
  const admin = canAdmin(viewer.tenant.role);
  const auditFilter = (AUDIT_FILTERS.some((f) => f.value === sp.audit) ? sp.audit : "") as AuditFilter;
  const auditPage = Math.max(1, Number(sp.ap) || 1);
  const [keys, members, status, audit, ssoMap, channels] = await Promise.all([
    admin ? source.enrollmentKeys(tenant) : Promise.resolve([]),
    source.members(tenant),
    source.systemStatus(tenant),
    admin ? source.auditLog(tenant, { page: auditPage, action: auditFilter || undefined }) : Promise.resolve(null),
    source.ssoGroupRoles(tenant),
    admin ? source.notificationChannels(tenant) : Promise.resolve([]),
  ]);
  const now = nowMs();
  const ingestUrl = process.env.EDR_INGEST_URL ?? "https://ingest.example.com";

  return (
    <>
      <PageHeader title="설정" description={`${viewer.tenant.name} 조직의 시스템 상태, 에이전트 등록, 구성원, 감사 기록입니다.`} />

      <SystemStatusPanel s={status} now={now} />

      <Panel bodyClassName="p-0" title="에이전트 등록키" aside={admin ? <EnrollDialog ingestUrl={ingestUrl} /> : <span>관리자만 볼 수 있습니다</span>}>
        {!admin ? <Empty title="등록키는 관리자만 다룰 수 있습니다" /> : keys.length === 0 ? (
          <Empty title="등록키가 없습니다">등록키를 만들어 에이전트 config.json 에 넣으면 PC 가 이 조직에 등록됩니다.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-[13px]">
              <thead className="border-b border-line bg-surface-2 text-xs text-muted">
                <tr><th className="px-4 py-2 font-medium">이름</th><th className="px-3 py-2 font-medium">사용</th><th className="px-3 py-2 font-medium">만료</th><th className="px-3 py-2 font-medium">상태</th><th className="px-3 py-2 font-medium">만든 날</th><th className="px-4 py-2" /></tr>
              </thead>
              <tbody className="divide-y divide-line">
                {keys.map((k) => {
                  const expired = Date.parse(k.expires_at) < now;
                  const full = k.used_count >= k.max_uses;
                  return (
                    <tr key={k.id} className={k.revoked || expired ? "text-ink-2" : ""}>
                      <td className="px-4 py-2 font-medium">{k.label ?? "이름 없음"}</td>
                      <td className="px-3 py-2 tabular-nums">{num(k.used_count)} / {num(k.max_uses)}대</td>
                      <td className="px-3 py-2" title={stamp(k.expires_at)}>{ago(k.expires_at)}</td>
                      <td className="px-3 py-2">{k.revoked ? "폐기됨" : expired ? "만료됨" : full ? "한도 도달" : <span className="text-ok">사용 가능</span>}</td>
                      <td className="px-3 py-2 text-ink-2">{day(k.created_at)}</td>
                      <td className="px-4 py-2 text-right">{!k.revoked && !expired && <RevokeKey id={k.id} />}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Panel bodyClassName="p-0" title="구성원" aside={<span>추가·역할 변경은 Supabase 에서</span>}>
          <ul className="divide-y divide-line">
            {members.map((m) => (
              <li key={m.user_id} className="flex items-center justify-between px-4 py-2.5 text-[13px]">
                <span className="font-medium">{m.email ?? m.user_id}{m.user_id === viewer.userId && <span className="ml-2 text-xs font-normal text-ink-2">나</span>}</span>
                <span className="flex items-center gap-2 text-ink-2">
                  {m.managed_by === "sso" && <span className="rounded border border-line-strong px-1.5 text-xs" title="AD 그룹으로 자동 가입. 역할은 AD 그룹이 바뀌면 다음 로그인 때 맞춰진다">AD 그룹</span>}
                  {ROLE_LABEL[m.role]}
                </span>
              </li>
            ))}
          </ul>
          <p className="border-t border-line px-4 py-3 text-xs text-ink-2">
            열람자: 보기만 / 분석가: 경보 처리·메모·예외 만들기 / 관리자: 규칙 켜기·끄기, 예외 삭제, 등록키 / 소유자: 관리자 + 구성원 관리
          </p>
        </Panel>

        <Panel title="PC 에 에이전트 설치">
          <ol className="list-decimal space-y-2 pl-5 text-[13px]">
            <li><code className="font-mono text-xs">edr-agent-amd64.exe</code> 를 <code className="font-mono text-xs">C:\Program Files\EndpointEDR\edr-agent.exe</code> 로 복사</li>
            <li>등록키를 만들 때 나온 config.json 을 <code className="font-mono text-xs">C:\ProgramData\EndpointEDR\</code> 에 저장</li>
            <li>관리자 PowerShell 에서 <code className="font-mono text-xs">edr-agent.exe install</code> 후 <code className="font-mono text-xs">Start-Service EndpointEDRAgent</code></li>
            <li>1~2분 뒤 장치 화면에 나타나면 완료. 여러 대는 GPO 시작 스크립트로 배포</li>
          </ol>
          <p className="mt-3 text-xs text-ink-2">설치 전 점검: <code className="font-mono">edr-agent.exe console</code> — 1회 수집 결과만 화면에 출력하고 서버로 보내지 않습니다.</p>
        </Panel>
      </div>

      {admin && (
        <Panel className="mt-4" bodyClassName="p-0" title="알림 연동"
          aside={<span className="hidden sm:inline">경보를 슬랙·이메일·SIEM 으로 보냅니다</span>}>
          <NotificationControls channels={channels} />
        </Panel>
      )}

      {ssoMap.length > 0 && (
        <Panel className="mt-4" bodyClassName="p-0" title="회사 계정(AD) 연동"
          aside={<span>로그인 버튼 {process.env.NEXT_PUBLIC_SSO_PROVIDER ? "켜짐" : "꺼짐"}</span>}>
          <table className="w-full text-left text-[13px]">
            <thead className="border-b border-line bg-surface-2 text-xs text-ink-2">
              <tr><th className="px-4 py-2 font-medium">AD 그룹</th><th className="px-3 py-2 font-medium">콘솔 역할</th><th className="px-4 py-2 font-medium">자동 가입된 구성원</th></tr>
            </thead>
            <tbody className="divide-y divide-line">
              {ssoMap.map((g) => (
                <tr key={g.provider + g.idp_group}>
                  <td className="px-4 py-2 font-mono text-[12.5px]">{g.idp_group}</td>
                  <td className="px-3 py-2">{ROLE_LABEL[g.role]}</td>
                  <td className="px-4 py-2 text-ink-2 tabular-nums">{num(members.filter((m) => m.managed_by === "sso" && m.role === g.role).length)}명</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="border-t border-line px-4 py-3 text-xs text-ink-2">
            AD 그룹에 넣고 빼면 다음 로그인 때 역할이 바뀝니다. 어느 그룹에도 없는 회사 계정은 로그인해도 콘솔을 쓸 수 없습니다. 여러 그룹에 있으면 가장 높은 역할을 줍니다. 관리자가 직접 등록한 구성원은 AD 그룹과 관계없이 그대로 유지됩니다.
            {!process.env.NEXT_PUBLIC_SSO_PROVIDER && " 지금은 로그인 화면에 회사 계정 버튼이 없습니다(실험 구성은 node deploy/sso-lab/lab.mjs on 으로 켭니다)."}
          </p>
        </Panel>
      )}

      {audit && (
        <Panel className="mt-4" bodyClassName="p-0" title="감사 기록" id="audit"
          aside={<span className="hidden sm:inline">누가 언제 무엇을 바꿨는지. 고치거나 지울 수 없습니다</span>}>
          <div className="overflow-x-auto border-b border-line px-4 py-2.5">
            <Segmented items={AUDIT_FILTERS.map((f) => ({ value: f.value, label: f.label }))} value={auditFilter}
              hrefFor={(v) => `/settings?${new URLSearchParams({ ...(v && { audit: v }) })}#audit`} />
          </div>
          {audit.rows.length === 0 ? <Empty title="기록이 없습니다">인시던트 처리, 규칙 변경, 등록키 발급 같은 조치를 하면 여기에 남습니다.</Empty> : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] text-left text-[13px]">
                <thead className="border-b border-line bg-surface-2 text-xs text-ink-2">
                  <tr><th className="px-4 py-2 font-medium">시각</th><th className="px-3 py-2 font-medium">사용자</th><th className="px-3 py-2 font-medium">한 일</th><th className="px-3 py-2 font-medium">대상</th><th className="px-4 py-2 font-medium">바뀐 내용</th></tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {audit.rows.map((a) => (
                    <tr key={a.id} className="align-top">
                      <td className="px-4 py-2 whitespace-nowrap text-ink-2" title={stamp(a.created_at)} suppressHydrationWarning>{ago(a.created_at, now)}</td>
                      <td className="px-3 py-2">{a.actor_email ?? a.actor_id?.slice(0, 8) ?? "—"}</td>
                      <td className="px-3 py-2 whitespace-nowrap font-medium">{ACTION_LABEL[a.action] ?? a.action}</td>
                      <td className="max-w-[22rem] px-3 py-2"><AuditTarget a={a} /></td>
                      <td className="px-4 py-2 text-ink-2">{changeText(a)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {audit.total > audit.pageSize && (
            <div className="flex items-center justify-between border-t border-line px-4 py-2 text-[13px] text-ink-2">
              <span>{num(audit.total)}건 중 {num((audit.page - 1) * audit.pageSize + 1)}–{num(Math.min(audit.total, audit.page * audit.pageSize))}</span>
              <span className="flex gap-3">
                {audit.page > 1 && <Link className="text-accent hover:underline" href={`/settings?${new URLSearchParams({ ...(auditFilter && { audit: auditFilter }), ap: String(audit.page - 1) })}#audit`}>이전</Link>}
                {audit.page * audit.pageSize < audit.total && <Link className="text-accent hover:underline" href={`/settings?${new URLSearchParams({ ...(auditFilter && { audit: auditFilter }), ap: String(audit.page + 1) })}#audit`}>다음</Link>}
              </span>
            </div>
          )}
        </Panel>
      )}
    </>
  );
}

// ---------------- 시스템 상태 ----------------
type Health = "ok" | "warn" | "bad";
const HEALTH_ICON = { ok: CheckCircle2, warn: AlertTriangle, bad: CircleX } as const;
const HEALTH_LABEL: Record<Health, string> = { ok: "정상", warn: "확인 필요", bad: "문제" };
const HEALTH_TEXT: Record<Health, string> = { ok: "text-ok", warn: "text-warn", bad: "text-sev-high" };

function SystemStatusPanel({ s, now }: { s: SystemStatus; now: number }) {
  const age = (t: string | null) => (t ? (now - Date.parse(t)) / 60_000 : Infinity); // 분
  const daysLeft = s.partitions_until ? Math.floor((Date.parse(s.partitions_until) - now) / 86_400_000) : -1;
  const runner = s.scheduler === "pg_cron" ? "pg_cron" : "enricher(RUN_DETECTIONS=1)";
  const items: { label: string; health: Health; value: string; hint: string; title?: string }[] = [
    { label: "탐지 실행", health: age(s.detections_at) > 15 ? "bad" : age(s.detections_at) > 5 ? "warn" : "ok",
      value: s.detections_at ? ago(s.detections_at, now) : "실행 기록 없음", hint: `1분마다 · ${runner}`, title: stamp(s.detections_at) },
    { label: "수집", health: age(s.last_ingest_at) > 30 ? "bad" : age(s.last_ingest_at) > 10 ? "warn" : "ok",
      value: s.last_ingest_at ? ago(s.last_ingest_at, now) : "수집 기록 없음", hint: `최근 1시간 보고한 PC ${num(s.devices_reporting_1h)}대`, title: stamp(s.last_ingest_at) },
    { label: "저장 공간(월 파티션)", health: daysLeft < 7 ? "bad" : daysLeft < 31 ? "warn" : "ok",
      value: s.partitions_until ? `${fullDay(s.partitions_until)} 전까지` : "확인 불가", hint: daysLeft >= 0 ? `${num(daysLeft)}일 남음` : "파티션 없음" },
    { label: "파티션·보존 작업", health: age(s.maintenance_at) > 3 * 1440 ? "bad" : age(s.maintenance_at) > 26 * 60 ? "warn" : "ok",
      value: s.maintenance_at ? ago(s.maintenance_at, now) : "실행 기록 없음", hint: `하루 1회 · ${runner}`, title: stamp(s.maintenance_at) },
    { label: "평판 조회 대기", health: "ok", value: `${num(s.pending_hashes)}개`, hint: "VirusTotal·MalwareBazaar 조회 전 해시" },
  ];
  const worst: Health = items.some((i) => i.health === "bad") ? "bad" : items.some((i) => i.health === "warn") ? "warn" : "ok";
  return (
    <Panel className="mb-4" bodyClassName="p-0" title="시스템 상태"
      aside={<span className={cn("inline-flex items-center gap-1.5 font-medium", HEALTH_TEXT[worst])}>{(() => { const I = HEALTH_ICON[worst]; return <I className="size-4" aria-hidden />; })()}{worst === "ok" ? "모두 정상" : worst === "warn" ? "확인할 항목이 있습니다" : "조치가 필요한 항목이 있습니다"}</span>}>
      <dl className="grid grid-cols-1 gap-px bg-line sm:grid-cols-2 xl:grid-cols-5">
        {items.map((i) => {
          const Icon = HEALTH_ICON[i.health];
          return (
            <div key={i.label} className="bg-surface px-4 py-3">
              <dt className="flex items-center justify-between gap-2 text-[13px] text-ink-2">
                {i.label}
                <span className={cn("inline-flex items-center gap-1 text-xs font-medium", HEALTH_TEXT[i.health])}><Icon className="size-3.5" aria-hidden />{HEALTH_LABEL[i.health]}</span>
              </dt>
              <dd className="mt-1 font-medium" title={i.title} suppressHydrationWarning>{i.value}</dd>
              <dd className="mt-0.5 text-xs text-ink-2">{i.hint}</dd>
            </div>
          );
        })}
      </dl>
    </Panel>
  );
}

// ---------------- 감사 기록 표시 ----------------
const ACTION_LABEL: Record<string, string> = {
  "incident.update": "인시던트 상태 변경", "incident.close": "인시던트 종결", "incident.reopen": "인시던트 다시 열기",
  "alert.update": "경보 변경", "alert.close": "경보 종결", "alert.reopen": "경보 다시 열기",
  "rule.enable": "탐지 규칙 켬", "rule.disable": "탐지 규칙 끔",
  "suppression.create": "예외 만듦", "suppression.delete": "예외 삭제",
  "enrollment_key.create": "등록키 발급", "enrollment_key.revoke": "등록키 폐기", "enrollment_key.update": "등록키 변경",
  "member.add": "구성원 추가", "member.remove": "구성원 제거", "member.role": "역할 변경", "device.update": "장치 변경",
  "member.sso_add": "AD 그룹으로 가입", "member.sso_role": "AD 그룹으로 역할 변경", "member.sso_remove": "AD 그룹에서 빠져 접근 제거",
  "sso_map.create": "AD 그룹 대응 추가", "sso_map.update": "AD 그룹 대응 변경", "sso_map.delete": "AD 그룹 대응 삭제",
  "ioc.create": "위협 지표 등록", "ioc.update": "위협 지표 변경", "ioc.delete": "위협 지표 삭제",
  "sw_policy.create": "소프트웨어 정책 추가", "sw_policy.update": "소프트웨어 정책 변경", "sw_policy.delete": "소프트웨어 정책 삭제",
  "doc_scan.enable": "문서 감사 켬", "doc_scan.disable": "문서 감사 끔", "doc_scan.policy": "문서 감사 정책 변경",
  "remediation.status": "조치 상태 변경", "remediation.assign": "조치 담당자 지정", "remediation.update": "조치 메모·기한 변경", "remediation.bulk": "조치 항목 일괄 처리",
  "doc_scan.request": "문서 검사 요청", "doc_scan.view": "문서 감사 결과 조회", "doc_scan.export": "문서 감사 결과 내려받기",
  "posture_policy.enable": "보안 점검 항목 점수 반영", "posture_policy.disable": "보안 점검 항목 점수 제외", "posture_policy.reset": "보안 점검 항목 기본값",
  "notification.channel.create": "알림 채널 추가", "notification.channel.update": "알림 채널 변경", "notification.channel.delete": "알림 채널 삭제",
};
const FIELD_LABEL: Record<string, string> = { assignee: "담당자", note: "메모", due_date: "기한", count: "건수", assignee_cleared: "담당자 비움", interval_hours: "검사 간격(시간)", folders: "검사 폴더", extra_paths: "추가 경로", extensions: "문서 종류", detect: "찾을 개인정보", keywords: "키워드", stale_days: "오래된 문서 기준(일)", max_file_mb: "파일 크기 상한(MB)", notice_confirmed_at: "직원 고지 확인", device_id: "장치", q: "검색어", keyword: "키워드", request_id: "요청 번호", description: "설명", source: "출처", kind: "종류", fixed_version: "취약 기준 버전", name_pattern: "이름 조건", publisher_pattern: "게시자 조건", reference: "참고", reason: "이유", groups: "AD 그룹", status: "상태", resolution: "판정", assigned_to: "담당자", enabled: "사용", revoked: "폐기", role: "역할", max_uses: "최대 등록 대수", expires_at: "만료", rule_id: "규칙", match: "조건", severity: "심각도", tags: "태그" };

function valueText(field: string, v: unknown, targetType: string): string {
  if (v == null) return "없음";
  if (field === "status" && targetType === "remediation" && typeof v === "string")
    return ({ open: "대기", in_progress: "진행 중", done: "완료 표시", exception: "예외" } as Record<string, string>)[v] ?? v;
  if (field === "assignee") return typeof v === "string" && v.length > 20 ? "지정됨" : String(v);
  if (field === "status" && v === "open" && targetType === "incident") return "미처리";
  if (field === "status" && typeof v === "string") return STATUS_LABEL[v as keyof typeof STATUS_LABEL] ?? v;
  if (field === "resolution" && typeof v === "string") return RESOLUTION_LABEL[v as keyof typeof RESOLUTION_LABEL] ?? v;
  if (field === "role" && typeof v === "string") return ROLE_LABEL[v as keyof typeof ROLE_LABEL] ?? v;
  if (field === "assigned_to") return typeof v === "string" && v.length > 20 ? "지정됨" : String(v);
  if (field === "enabled") return v ? "켬" : "끔";
  if (field === "revoked") return v ? "예" : "아니오";
  if (field === "severity" && typeof v === "string") return SEVERITY_LABEL[v as keyof typeof SEVERITY_LABEL] ?? v;
  if (field === "kind") return v === "prohibited" ? "금지" : v === "vulnerable" ? "취약 버전" : String(v);
  if ((field === "expires_at" || field === "notice_confirmed_at") && typeof v === "string") return fullDay(v);
  if (Array.isArray(v)) return v.join(", ") || "없음";
  if (typeof v === "object") return Object.entries(v as Record<string, unknown>).map(([k, x]) => `${k}=${typeof x === "string" ? x : JSON.stringify(x)}`).join(", ") || "없음";
  return String(v);
}

function changeText(a: AuditEntry): string {
  const parts = Object.entries(a.changes ?? {}).filter(([k]) => k !== "device_id").map(([k, v]) =>
    k === "groups" && Array.isArray(v) ? `AD 그룹 ${v.length ? v.join(", ") : "없음"}`
    : Array.isArray(v) && v.length === 2 ? `${FIELD_LABEL[k] ?? k} ${valueText(k, v[0], a.target_type)} → ${valueText(k, v[1], a.target_type)}` : `${FIELD_LABEL[k] ?? k} ${valueText(k, v, a.target_type)}`);
  return parts.join(", ") || "—";
}

function AuditTarget({ a }: { a: AuditEntry }) {
  const label = a.target_label || a.target_id || "—";
  const href = a.target_type === "incident" ? `/incidents/${a.target_id}`
    : a.target_type === "alert" ? `/alerts?status=all&id=${a.target_id}`
    : a.target_type === "rule" || a.target_type === "suppression" ? "/rules"
    : a.target_type === "device" ? `/devices/${a.target_id}`
    : a.target_type === "ioc" ? "/iocs"
    : a.target_type === "sw_policy" ? "/assets?tab=exposure"
    : a.target_type === "posture_policy" ? `/posture?check=${a.target_id}`
    : a.target_type === "remediation" ? (a.target_id ? `/remediation?device=${a.target_id}&view=all` : "/remediation")
    : a.target_type === "doc_scan" ? (a.target_id ? `/documents?tab=${a.target_id}` : "/documents?tab=policy") : null;
  return href ? <Link href={href} className="line-clamp-2 hover:text-accent">{label}</Link> : <span className="line-clamp-2">{label}</span>;
}
