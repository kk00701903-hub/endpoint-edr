// 콘솔이 다루는 도메인 타입. DB 컬럼과 1:1 로 맞춘다(supabase/migrations 참고).
// 스키마를 바꾸면 여기와 supabase-source.ts 의 select 목록을 함께 고친다.

export type Severity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "closed";
export type Resolution = "true_positive" | "false_positive" | "benign" | "suppressed";
export type Role = "owner" | "admin" | "analyst" | "viewer";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export interface Tenant {
  id: string;
  name: string;
  role: Role;
}

export interface Viewer {
  userId: string;
  email: string;
  tenants: Tenant[];
  tenant: Tenant;
  demo: boolean;
}

export interface AgentHealth {
  uptime_sec: number;
  cpu_percent: number;
  working_set_mb: number;
  goroutines: number;
  spool_files: number;
  spool_bytes: number;
  scan_ms: Record<string, number>;
  last_errors?: string[];
}

export interface Device {
  id: string;
  hostname: string;
  os_version: string | null;
  agent_version: string | null;
  status: "active" | "disabled" | "retired";
  tags: string[];
  last_ip: string | null;
  enrolled_at: string;
  last_seen_at: string | null;
  health: AgentHealth | null;
  health_at: string | null;
  open_alerts?: number;
}

export interface Alert {
  id: number;
  device_id: string | null;
  hostname?: string | null;
  rule_id: string;
  severity: Severity;
  title: string;
  details: Record<string, unknown>;
  status: AlertStatus;
  resolution: Resolution | null;
  assigned_to: string | null;
  created_at: string;
  updated_at: string;
  incident_id?: number | null;
  source?: AlertSource;   // edr(내장 탐지) | wazuh(외부 오픈소스 EDR)
}

export type AlertSource = "edr" | "wazuh";

export interface AlertComment {
  id: number;
  alert_id: number;
  author_id: string;
  author_email?: string;
  body: string;
  created_at: string;
}

export interface DetectionRule {
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  mitre_tactic: string;
  mitre_technique: string;
  technique_name: string;
  data_source: string;
  enabled: boolean;
  hits_7d?: number;
}

export interface Suppression {
  id: number;
  rule_id: string | null;
  device_id: string | null;
  match: Record<string, unknown>;
  reason: string;
  created_at: string;
  expires_at: string | null;
  hit_count: number;
}

export interface ProcessRow {
  pid: number;
  ppid: number | null;
  create_time: string;
  name: string;
  path: string | null;
  command_line: string | null;
  username: string | null;
  sha256: string | null;
  verdict?: string | null;
  first_seen_at: string;
}

export interface ConnectionRow {
  observed_at: string;
  proto: string;
  direction: string;
  local_ip: string | null;
  local_port: number | null;
  remote_ip: string | null;
  remote_port: number | null;
  state: string | null;
  pid: number | null;
  process_name: string | null;
  is_external: boolean;
}

export interface AutorunRow {
  location: string;
  entry_name: string;
  command: string | null;
  image_path: string | null;
  sha256: string | null;
  first_seen_at: string;
  last_seen_at: string;
  removed_at: string | null;
}

export interface TimelineItem {
  ts: string;
  kind: "alert" | "event" | "autorun" | "process" | "software";
  severity: Severity | "info";
  title: string;
  detail: Record<string, unknown>;
}

export interface EnrollmentKey {
  id: string;
  label: string | null;
  max_uses: number;
  used_count: number;
  expires_at: string;
  revoked: boolean;
  created_at: string;
}

export interface Member {
  user_id: string;
  email: string | null;
  role: Role;
  created_at: string;
  /** manual: 관리자가 직접 넣음 / sso: 회사 계정(AD 그룹)으로 자동 가입 (마이그레이션 0007) */
  managed_by?: "manual" | "sso";
}

export interface Overview {
  open_alerts: Partial<Record<Severity, number>>;
  alerts_24h: number;
  alerts_prev_24h: number;
  devices: {
    total: number;
    online: number;
    stale: number;
    offline: number;
    avg_cpu: number | null;
    max_cpu: number | null;
    avg_mem: number | null;
    max_mem: number | null;
    /** 에이전트 CPU% 분포: [<0.25, 0.25~0.5, 0.5~1, 1~2, ≥2] 구간별 장치 수 */
    cpu_buckets: number[];
  };
  failed_logons_24h: number;
  malicious_hashes: number;
  pending_hashes: number;
  mttr_minutes: number | null;
  top_rules: { rule_id: string; title: string | null; mitre_technique: string | null; n: number }[];
  top_devices: { id: string; hostname: string; n: number; high: number }[];
}

export interface TrendPoint {
  bucket: string;
  severity: Severity;
  n: number;
}


export interface AlertFilter {
  severity?: Severity[];
  status?: AlertStatus | "active" | "all";
  rule?: string;
  q?: string;
  device?: string;
  days?: number;
  page?: number;
  source?: AlertSource;
}

export interface Page<T> {
  rows: T[];
  total: number;
  page: number;
  pageSize: number;
}

// ---------------------------------------------------------------------------
// 인시던트 · 엔터티 · ATT&CK · 헌팅 (마이그레이션 0005)
// ---------------------------------------------------------------------------
export interface Incident {
  id: number;
  title: string;
  severity: Severity;
  status: AlertStatus;
  resolution: Exclude<Resolution, "suppressed"> | null;
  assigned_to: string | null;
  device_ids: string[];
  ips: string[];
  hashes: string[];
  users: string[];
  tactics: string[];
  techniques: string[];
  rule_ids: string[];
  alert_count: number;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
  hostnames?: string[];
}

export interface IncidentFilter {
  status?: AlertStatus | "active" | "all";
  severity?: Severity[];
  q?: string;
  days?: number;
  page?: number;
}

export interface IncidentDetail {
  incident: Incident;
  alerts: Alert[];
  comments: AlertComment[];
  devices: Device[];
  rules: DetectionRule[];
  /** 공격 그래프용: 인시던트 장치들의 현재 프로세스와 외부 통신 */
  processes: Record<string, ProcessRow[]>;
  connections: Record<string, ConnectionRow[]>;
}

export type EntityKind = "ip" | "hash" | "user";

export interface EntityProfile {
  kind: EntityKind;
  value: string;
  first_seen: string | null;
  last_seen: string | null;
  observations: number;
  devices: { id: string; hostname: string; n: number; last: string }[];
  /** 종류별 추가 사실 (logon_failures, reputation, names, paths, source_ips 등) */
  facts: Record<string, unknown>;
  alerts: Alert[];
  incidents: Incident[];
}

export interface MatrixCell {
  technique: string;
  tactic: string;
  hits: number;
  last_seen: string | null;
}

export interface SavedQuery {
  id: number;
  name: string;
  query: string;
  hours: number;
  created_at: string;
  created_by: string;
}

export interface QueryResult {
  dataset: string;
  rows: Record<string, unknown>[];
  truncated: boolean;
  ms: number;
}

// ---------------------------------------------------------------------------
// 운영 상태 · 감사 기록 (마이그레이션 0006)
// ---------------------------------------------------------------------------
export interface SystemStatus {
  now: string;
  detections_at: string | null;   // 마지막 탐지 실행
  maintenance_at: string | null;  // 마지막 파티션·보존 작업
  scheduler: "pg_cron" | "enricher";
  partitions_until: string | null; // 이 날짜 이후 데이터는 저장할 파티션이 없음
  last_ingest_at: string | null;
  devices_reporting_1h: number;
  pending_hashes: number;
}

export interface AuditEntry {
  id: number;
  actor_id: string | null;
  actor_email: string | null;
  action: string;          // incident.close, rule.disable, enrollment_key.create …
  target_type: string;
  target_id: string | null;
  target_label: string | null;
  changes: Record<string, unknown>;
  created_at: string;
}

/** AD 그룹 → 콘솔 역할 대응표 (마이그레이션 0007) */
export interface SsoGroupRole {
  provider: string;
  idp_group: string;
  role: Exclude<Role, "owner">;
  created_at: string;
}

// ---------------------------------------------------------------------------
// 자산 · 보안 상태 · 소프트웨어 정책 · 위협 지표 (마이그레이션 0008)
// ---------------------------------------------------------------------------

export interface NetworkAdapter { name: string; mac?: string | null; ips?: string[] }

/** device_inventory 한 행(장치당 1개) */
export interface DeviceInventory {
  device_id: string;
  os_name: string | null;
  os_edition: string | null;
  os_display_version: string | null;
  os_build: number | null;
  os_ubr: number | null;
  os_product: "client" | "server" | null;
  os_arch: string | null;
  os_installed_at: string | null;
  os_label: string | null;            // 수명 주기 표 이름 예: Windows 11 24H2
  os_end_of_support: string | null;   // YYYY-MM-DD
  manufacturer: string | null;
  model: string | null;
  serial_number: string | null;
  bios_version: string | null;
  cpu: string | null;
  cpu_cores: number | null;
  memory_mb: number | null;
  disk_total_gb: number | null;
  disk_free_gb: number | null;
  domain: string | null;
  domain_joined: boolean | null;
  last_user: string | null;
  adapters: NetworkAdapter[];
  software_count: number;
  collected_at: string | null;
  updated_at: string;
}

/** 자산 목록 한 줄 = 장치 + 자산 정보 */
export interface AssetRow extends DeviceInventory {
  hostname: string;
  last_seen_at: string | null;
}

export type AssetFilter = "all" | "unsupported" | "ending" | "low_disk";

export interface AssetOverview {
  devices: number;
  inventoried: number;
  software_titles: number;
  installs_7d: number;
  unsupported: number;
  ending_90d: number;
  domain_joined: number;
  low_disk: number;
  os: { label: string; product: "client" | "server" | null; end_of_support: string | null; n: number }[];
  manufacturers: { label: string; n: number }[];
}

export interface DeviceSoftware {
  name: string;
  version: string;
  publisher: string | null;
  install_date: string | null;
  scope: "machine" | "user";
  arch: string | null;
  first_seen_at: string;
}

/** 이름별 소프트웨어 목록(설치 대수 순) */
export interface SoftwareTitle {
  name: string;
  publisher: string | null;
  versions: string[];
  devices: number;
  first_seen_at: string;
}

export interface SoftwareInstall {
  device_id: string;
  hostname: string;
  version: string;
  publisher: string | null;
  scope: "machine" | "user";
  install_date: string | null;
  first_seen_at: string;
}

export interface SoftwareChange {
  id: number;
  device_id: string;
  hostname?: string | null;
  change: "installed" | "removed" | "updated";
  name: string;
  version: string | null;
  prev_version: string | null;
  publisher: string | null;
  observed_at: string;
}

export type SoftwarePolicyKind = "vulnerable" | "prohibited";

/** 소프트웨어 정책 + 지금 해당하는 장치 수 */
export interface SoftwareExposure {
  policy_id: number;
  kind: SoftwarePolicyKind;
  severity: Severity;
  name_pattern: string;
  publisher_pattern: string | null;
  fixed_version: string | null;
  reference: string | null;
  reason: string;
  builtin: boolean;
  enabled: boolean;
  created_at: string;
  software: string[];
  versions: string[];
  devices: number;
  device_ids: string[];
  hostnames?: string[];   // 화면 표시용(device_ids 앞부분)
}

export type PostureStatus = "pass" | "warn" | "fail" | "unknown";

export interface PostureCheckSummary {
  check_id: string;
  title: string;
  description: string;
  remediation: string;
  category: string;
  weight: number;
  enabled: boolean;          // 이 조직의 보안 점수·경보에 포함
  default_enabled: boolean;
  drift_alert: boolean;      // 통과 → 실패로 바뀌면 경보(EDR-POS-001)
  source: "agent" | "server";
  pass: number;
  warn: number;
  fail: number;
  unknown: number;
}

export interface PostureOverview {
  score: number | null;
  devices: number;
  scored: number;
  buckets: [number, number, number, number];   // 50 미만 · 50~69 · 70~89 · 90 이상
  checks: PostureCheckSummary[];
  worst: { device_id: string; hostname: string; score: number; fails: string[] }[];
}

export interface PostureDeviceRow {
  device_id: string;
  hostname: string;
  score: number | null;
  status: PostureStatus | null;
  detail: string | null;
  checked_at: string | null;
  fails: string[];
}

export interface DevicePostureItem {
  check_id: string;
  title: string;
  description: string;
  remediation: string;
  category: string;
  weight: number;
  enabled: boolean;
  drift_alert: boolean;
  status: PostureStatus | null;   // 아직 보고 안 됨이면 null
  detail: string | null;
  changed_at: string | null;
  failing_since: string | null;
  checked_at: string | null;
}

export type IocType = "sha256" | "ip";

export interface Ioc {
  id: number;
  type: IocType;
  value: string;
  severity: Severity;
  description: string;
  source: string | null;
  enabled: boolean;
  expires_at: string | null;
  hit_count: number;
  last_hit_at: string | null;
  created_by: string | null;
  created_by_email?: string | null;
  created_at: string;
}

export interface NewIoc {
  type: IocType;
  value: string;
  severity: Severity;
  description: string;
  source: string | null;
  days: number | null;   // 만료까지 일수, null 이면 기한 없음
}

// ---------- 알림 연동 (슬랙·이메일·SIEM) ----------
export type NotificationKind = "slack" | "email" | "syslog" | "webhook";

export interface NotificationChannel {
  id: number;
  name: string;
  kind: NotificationKind;
  target: string;          // 이메일 주소(쉼표), 슬랙 표시용 채널명, syslog host:port
  secret_ref: string;      // 비밀값이 든 .env 키 이름 (값 자체가 아님)
  min_severity: Severity;
  rule_prefixes: string[]; // 비우면 전체. 예: ["EDR-AUTH","EDR-IOC"]
  enabled: boolean;
  updated_at: string;
  last_sent_at?: string | null;   // 최근 전송 성공 시각
  pending?: number;               // 보내지 못하고 대기 중인 건수
  failed?: number;                // 실패로 멈춘 건수
}

export interface NewNotificationChannel {
  id?: number;             // 있으면 수정
  name: string;
  kind: NotificationKind;
  target: string;
  secret_ref: string;
  min_severity: Severity;
  rule_prefixes: string[];
  enabled: boolean;
}

export interface NewSoftwarePolicy {
  kind: SoftwarePolicyKind;
  name_pattern: string;
  publisher_pattern: string | null;
  fixed_version: string | null;
  severity: Severity;
  reference: string | null;
  reason: string;
}

// ---------------------------------------------------------------------------
// 문서 감사 (보안 관리자의 PC 감사) — 소유자·관리자만. 서버에는 파일 위치와 종류별 건수만 있다(내용·값 없음)
// ---------------------------------------------------------------------------
export type DocPiiKind = "rrn" | "frn" | "passport" | "driver" | "card" | "phone";
export type DocFindingKind = "pii" | "keyword" | "stale";

/** doc_scan_policies 1:1 */
export interface DocScanPolicy {
  enabled: boolean;
  interval_hours: number;
  folders: string[];        // 각 사용자 폴더 아래 이름(Desktop 등)
  extra_paths: string[];    // 추가 절대 경로(D:\업무 등)
  extensions: string[];
  detect: DocPiiKind[];
  keywords: string[];
  stale_days: number;       // 0 이면 오래된 문서 찾기 안 함
  max_file_mb: number;
  notice_confirmed_at: string | null;
  notice_confirmed_by: string | null;
  notice_confirmed_by_email?: string | null;
  updated_at: string | null;
}

export type DocScanPolicyInput = Omit<DocScanPolicy, "notice_confirmed_at" | "notice_confirmed_by" | "notice_confirmed_by_email" | "updated_at"> & {
  /** 이번 저장에서 "직원 고지 완료"를 확인함 */
  confirmNotice: boolean;
};

/** console_doc_overview */
export interface DocOverview {
  devices: number;
  devices_scanned: number;
  last_scan_at: string | null;
  running: number;
  pending_requests: number;
  pii_files: number;
  pii_devices: number;
  pii_by_kind: Partial<Record<DocPiiKind, number>>;
  keyword_files: number;
  keywords_by_word: Record<string, number>;   // 키워드 → 문서 수
  stale_files: number;
  stale_bytes: number;
}

/** console_doc_findings */
export interface DocFindingRow {
  device_id: string;
  hostname: string;
  path: string;
  ext: string | null;
  size: number | null;
  modified_at: string | null;
  pii: Partial<Record<DocPiiKind, number>>;
  pii_total: number;
  keywords: Record<string, number>;
  keyword_total: number;
  stale: boolean;
  unreadable: string | null;
  last_seen_at: string;
}

/** console_doc_devices */
export interface DocDeviceRow {
  device_id: string;
  hostname: string;
  last_seen_at: string | null;
  last_scan_at: string | null;
  last_status: "running" | "done" | null;
  files_scanned: number | null;
  files_skipped: number | null;
  pii_files: number;
  keyword_files: number;
  stale_files: number;
  pending_request_at: string | null;
  request_picked: boolean | null;
}

// ---------------------------------------------------------------------------
// PC 조치 목록 (마이그레이션 0010) — 지금 데이터에서 계산한 "고쳐야 할 것" + 담당자·처리 상태
// ---------------------------------------------------------------------------
export type RemediationKind = "posture" | "software" | "doc_pii" | "doc_stale";
export type RemediationStatus = "open" | "in_progress" | "done" | "exception";
/** 목록 보기: active = 대기·진행 중·완료 표시(아직 남아 있는 것), resolved = 처리 기록은 있는데 이제 없는 것 */
export type RemediationView = "active" | RemediationStatus | "resolved" | "all";

/** console_remediation 1행 */
export interface RemediationItem {
  device_id: string;
  hostname: string;
  last_seen_at: string | null;
  kind: RemediationKind;
  item_key: string;          // 점검 ID | 소프트웨어 정책 ID | pii | stale
  title: string;
  detail: string | null;
  severity: Severity | null; // 해결 확인됨 행은 null
  since: string | null;
  guidance: string | null;
  present: boolean;          // false = 해결 확인됨
  status: RemediationStatus;
  assignee: string | null;
  assignee_email?: string | null;
  note: string;
  due_date: string | null;   // YYYY-MM-DD
  updated_at: string | null;
  updated_by: string | null;
}

/** console_remediation_overview */
export interface RemediationOverview {
  items: number;
  devices: number;
  by_kind: Partial<Record<RemediationKind, number>>;
  by_status: Partial<Record<RemediationStatus, number>>;
  high: number;
  unassigned: number;
  overdue: number;
  resolved_30d: number;
  docs: boolean;             // 문서 감사 항목을 볼 수 있는 역할인지
}

export interface RemediationRef { device_id: string; kind: RemediationKind; item_key: string; title: string }
/** 바꿀 값만. assignee/due_date 를 null 로 주면 비운다 */
export interface RemediationPatch { status?: RemediationStatus; assignee?: string | null; note?: string; due_date?: string | null }
