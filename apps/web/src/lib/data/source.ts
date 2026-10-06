import "server-only";
import type { ParsedQuery } from "../hunt/query";
import type {
  Alert, AlertComment, AlertFilter, AlertStatus, AutorunRow, ConnectionRow, Device, DetectionRule,
  EnrollmentKey, EntityKind, EntityProfile, Incident, IncidentDetail, IncidentFilter, MatrixCell, Member,
  Overview, Page, ProcessRow, QueryResult, Resolution, SavedQuery, Suppression, TimelineItem, TrendPoint, Viewer,
  SystemStatus, AuditEntry, SsoGroupRole,
  AssetFilter, AssetOverview, AssetRow, DeviceInventory, DevicePostureItem, DeviceSoftware, Ioc, NewIoc, NewSoftwarePolicy,
  PostureDeviceRow, PostureOverview, PostureStatus, SoftwareChange, SoftwareExposure, SoftwareInstall, SoftwareTitle,
  DocDeviceRow, DocFindingKind, DocFindingRow, DocOverview, DocScanPolicy, DocScanPolicyInput,
  RemediationItem, RemediationKind, RemediationOverview, RemediationPatch, RemediationRef, RemediationView,
  NotificationChannel, NewNotificationChannel,
} from "./types";

export interface AlertDetail {
  alert: Alert;
  comments: AlertComment[];
  rule: DetectionRule | null;
  device: Device | null;
}

export type DeviceState = "all" | "online" | "stale" | "offline";
export type DeviceSort = "hostname" | "cpu" | "memory" | "last_seen" | "alerts";

/** 콘솔이 쓰는 모든 조회·변경. Supabase 구현과 데모(예시 데이터) 구현이 같은 계약을 따른다. */
export interface DataSource {
  viewer(): Promise<Viewer | null>;

  overview(tenant: string): Promise<Overview>;
  alertTrend(tenant: string, days: number): Promise<TrendPoint[]>;
  logonFailures(tenant: string, hours: number): Promise<{ bucket: string; n: number }[]>;
  alertsSince(tenant: string, hours: number): Promise<Alert[]>;

  alerts(tenant: string, filter: AlertFilter): Promise<Page<Alert>>;
  alert(tenant: string, id: number): Promise<AlertDetail | null>;

  devices(tenant: string, opts: { q?: string; state?: DeviceState; sort?: DeviceSort; page?: number }): Promise<Page<Device>>;
  device(tenant: string, id: string): Promise<Device | null>;
  deviceTimeline(tenant: string, id: string, hours: number): Promise<TimelineItem[]>;
  deviceProcesses(tenant: string, id: string): Promise<ProcessRow[]>;
  deviceConnections(tenant: string, id: string, opts: { externalOnly: boolean; hours: number }): Promise<ConnectionRow[]>;
  deviceAutoruns(tenant: string, id: string): Promise<AutorunRow[]>;

  rules(tenant: string): Promise<DetectionRule[]>;
  suppressions(tenant: string): Promise<Suppression[]>;
  enrollmentKeys(tenant: string): Promise<EnrollmentKey[]>;
  members(tenant: string): Promise<Member[]>;

  updateAlerts(tenant: string, ids: number[], patch: { status?: AlertStatus; resolution?: Resolution | null; assignToMe?: boolean }): Promise<void>;
  addComment(tenant: string, alertId: number, body: string): Promise<void>;
  createSuppression(tenant: string, s: { rule_id: string | null; device_id: string | null; match: Record<string, unknown>; reason: string; days: number | null }): Promise<void>;
  deleteSuppression(tenant: string, id: number): Promise<void>;
  setRuleEnabled(ruleId: string, enabled: boolean): Promise<void>;
  createEnrollmentKey(tenant: string, label: string, days: number, maxUses: number): Promise<string>;
  revokeEnrollmentKey(tenant: string, id: string): Promise<void>;

  // ---- 인시던트 · 엔터티 · ATT&CK · 쿼리 헌팅 ----
  incidents(tenant: string, filter: IncidentFilter): Promise<Page<Incident>>;
  incident(tenant: string, id: number): Promise<IncidentDetail | null>;
  updateIncident(tenant: string, id: number, patch: { status?: AlertStatus; resolution?: Exclude<Resolution, "suppressed">; assignToMe?: boolean }): Promise<void>;
  addIncidentComment(tenant: string, id: number, body: string): Promise<void>;
  entity(tenant: string, kind: EntityKind, value: string, days: number): Promise<EntityProfile>;
  attackMatrix(tenant: string, days: number): Promise<MatrixCell[]>;
  runQuery(tenant: string, query: ParsedQuery, hours: number): Promise<QueryResult>;
  savedQueries(tenant: string): Promise<SavedQuery[]>;
  saveQuery(tenant: string, name: string, query: string, hours: number): Promise<void>;
  deleteQuery(tenant: string, id: number): Promise<void>;

  // ---- 운영 상태 · 감사 기록 ----
  systemStatus(tenant: string): Promise<SystemStatus>;
  /** 소유자·관리자만 행이 보인다(RLS). 최신순. */
  auditLog(tenant: string, opts: { page?: number; action?: string }): Promise<Page<AuditEntry>>;
  /** 회사 계정(AD) 그룹 → 역할 대응표. SSO 를 쓰지 않으면 빈 배열 */
  ssoGroupRoles(tenant: string): Promise<SsoGroupRole[]>;

  // ---- 자산 · 소프트웨어 (Falcon Discover / Genian 단말 정보) ----
  assetOverview(tenant: string): Promise<AssetOverview>;
  assets(tenant: string, opts: { q?: string; filter?: AssetFilter; page?: number; pageSize?: number }): Promise<Page<AssetRow>>;
  deviceInventory(tenant: string, id: string): Promise<DeviceInventory | null>;
  deviceSoftware(tenant: string, id: string): Promise<DeviceSoftware[]>;
  softwareCatalog(tenant: string, opts: { q?: string; page?: number; pageSize?: number }): Promise<Page<SoftwareTitle>>;
  softwareInstalls(tenant: string, name: string): Promise<SoftwareInstall[]>;
  softwareChanges(tenant: string, opts: { device?: string; days?: number; page?: number; pageSize?: number }): Promise<Page<SoftwareChange>>;
  /** 소프트웨어 정책(취약·금지)마다 지금 해당하는 장치 */
  softwareExposure(tenant: string): Promise<SoftwareExposure[]>;
  createSoftwarePolicy(tenant: string, p: NewSoftwarePolicy): Promise<void>;
  setSoftwarePolicyEnabled(tenant: string, id: number, enabled: boolean): Promise<void>;
  deleteSoftwarePolicy(tenant: string, id: number): Promise<void>;

  // ---- 보안 상태 (Falcon ZTA / Genian 정책 준수) ----
  postureOverview(tenant: string): Promise<PostureOverview>;
  postureDevices(tenant: string, opts: { check?: string; status?: PostureStatus; page?: number; pageSize?: number }): Promise<Page<PostureDeviceRow>>;
  devicePosture(tenant: string, id: string): Promise<{ score: number | null; items: DevicePostureItem[] }>;
  setPostureCheckEnabled(tenant: string, checkId: string, enabled: boolean): Promise<void>;

  // ---- 위협 지표(IOC) ----
  iocs(tenant: string): Promise<Ioc[]>;
  /** 등록 직후 최근 7일 소급 결과(적중 장치 수)를 돌려준다 */
  createIocs(tenant: string, list: NewIoc[]): Promise<{ created: number; skipped: number; hits: number }>;
  setIocEnabled(tenant: string, id: number, enabled: boolean): Promise<void>;
  deleteIoc(tenant: string, id: number): Promise<void>;

  // ---- 알림 연동 (소유자·관리자만 관리) ----
  notificationChannels(tenant: string): Promise<NotificationChannel[]>;
  saveNotificationChannel(tenant: string, input: NewNotificationChannel): Promise<void>;
  deleteNotificationChannel(tenant: string, id: number): Promise<void>;
  /** 테스트 알림 1건을 대기열에 넣는다(실제 전송은 enricher) */
  testNotificationChannel(tenant: string, id: number): Promise<void>;

  // ---- 문서 감사 (소유자·관리자만. 다른 역할은 오류) ----
  /** 정책이 없으면 기본값(꺼짐) */
  docPolicy(tenant: string): Promise<DocScanPolicy>;
  saveDocPolicy(tenant: string, p: DocScanPolicyInput): Promise<void>;
  docOverview(tenant: string): Promise<DocOverview>;
  /** 결과 목록. 조회(view)·내보내기(export)는 감사 기록에 남는다 */
  docFindings(tenant: string, opts: { kind: DocFindingKind; q?: string; device?: string; keyword?: string; page?: number; pageSize?: number; purpose?: "view" | "export" }): Promise<Page<DocFindingRow>>;
  docDevices(tenant: string): Promise<DocDeviceRow[]>;
  /** "지금 검사" 요청. 이미 대기 중인 장치는 건너뛴다. 새로 요청한 수를 돌려준다 */
  requestDocScan(tenant: string, deviceIds: string[]): Promise<number>;

  // ---- PC 조치 목록 (문서 감사 항목은 소유자·관리자에게만 나온다) ----
  remediationOverview(tenant: string): Promise<RemediationOverview>;
  remediation(tenant: string, opts: { kind?: RemediationKind | "docs"; view?: RemediationView; device?: string; assignee?: string; q?: string; page?: number; pageSize?: number }): Promise<Page<RemediationItem>>;
  /** 담당자·상태·메모·기한 바꾸기(분석가 이상, 문서 감사 항목은 관리자). 바뀐 항목 수 */
  updateRemediation(tenant: string, items: RemediationRef[], patch: RemediationPatch): Promise<number>;
}

export function isDemo(): boolean {
  return process.env.EDR_DEMO === "1" || !process.env.NEXT_PUBLIC_SUPABASE_URL;
}

export async function getSource(): Promise<DataSource> {
  if (isDemo()) {
    const { demoSource } = await import("./demo-source");
    return demoSource;
  }
  const { supabaseSource } = await import("./supabase-source");
  return supabaseSource();
}

export const PAGE_SIZE = 50;
