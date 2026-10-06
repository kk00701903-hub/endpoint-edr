-- =====================================================================
-- 콘솔 기능 + 성능 보강
--   1) 장치 상태(에이전트 자원 사용량) 저장
--   2) processes_current : 장치별 "지금 실행 중인 프로세스" 표 (Process Explorer 화면을 빠르게)
--   3) BRIN 인덱스 : 시간 범위 조회가 많은 대용량 파티션용 (B-tree 대비 수백 분의 1 크기)
--   4) 탐지 규칙 카탈로그(MITRE ATT&CK 매핑) + 규칙 켜기/끄기
--   5) 경보 판정(resolution)·코멘트 + 예외(오탐 억제) 규칙
--   6) 콘솔 전용 집계 함수 (security invoker → RLS 그대로 적용)
-- =====================================================================

-- ---------- 1) 장치 상태 ----------
alter table public.devices
  add column if not exists health    jsonb,
  add column if not exists health_at timestamptz;

-- ---------- 2) 현재 프로세스 ----------
create table public.processes_current (
  tenant_id     uuid not null,
  device_id     uuid not null references public.devices(id) on delete cascade,
  pid           int  not null,
  create_time   timestamptz not null default '-infinity',  -- 시작 시각을 못 읽은 보호 프로세스는 -infinity
  ppid          int,
  name          text not null,
  path          text,
  command_line  text,
  username      text,
  sha256        text,
  first_seen_at timestamptz not null default now(),
  primary key (device_id, pid, create_time)
);
create index on public.processes_current (tenant_id);
create index on public.processes_current (sha256) where sha256 is not null;

alter table public.processes_current enable row level security;
grant select on public.processes_current to authenticated, grafana_reader;
grant select, insert, update, delete on public.processes_current to edr_ingest;
create policy proc_cur_select  on public.processes_current for select to authenticated
  using (tenant_id in (select public.my_tenant_ids()));
create policy ingest_all       on public.processes_current for all to edr_ingest using (true) with check (true);
create policy grafana_read     on public.processes_current for select to grafana_reader using (true);

-- ---------- 3) BRIN (부모에 만들면 모든 월 파티션에 자동 적용) ----------
create index if not exists process_events_observed_brin  on public.process_events  using brin (observed_at);
create index if not exists net_connections_observed_brin on public.net_connections using brin (observed_at);
create index if not exists security_events_time_brin     on public.security_events using brin (event_time);
-- 장치 상세 화면(장치 + 기간) 조회용
create index if not exists security_events_device_time on public.security_events (device_id, event_time desc);
create index if not exists autorun_changes_device_time on public.autorun_changes (device_id, observed_at desc);
create index if not exists alerts_device_time          on public.alerts (device_id, created_at desc);

-- ---------- 4) 탐지 규칙 카탈로그 ----------
create table public.detection_rules (
  rule_id          text primary key,
  title            text not null,
  description      text not null,
  severity         text not null check (severity in ('low','medium','high','critical')),
  mitre_tactic     text not null,     -- 예: Credential Access
  mitre_technique  text not null,     -- 예: T1110
  technique_name   text not null,
  data_source      text not null,     -- 어떤 수집기 데이터로 판단하는지
  enabled          boolean not null default true,
  updated_at       timestamptz not null default now()
);

insert into public.detection_rules values
 ('EDR-AUTH-001','로그온 무차별 대입','같은 PC·같은 출발지에서 10분 내 로그온 실패(4625) 10회 이상','high','Credential Access','T1110','Brute Force','보안 이벤트',true,now()),
 ('EDR-AUTH-002','무차별 대입 후 로그온 성공','실패 5회 이상 직후 같은 출발지에서 네트워크/RDP 로그온 성공','critical','Credential Access','T1110','Brute Force','보안 이벤트',true,now()),
 ('EDR-AUTH-003','외부 IP 원격 데스크톱 로그온','공인 IP 에서 RDP(LogonType 10) 로그온 성공','high','Initial Access','T1133','External Remote Services','보안 이벤트',true,now()),
 ('EDR-LOG-001','이벤트 로그 삭제','보안(1102) 또는 시스템(104) 로그 삭제 — 흔적 지우기','high','Defense Evasion','T1070.001','Clear Windows Event Logs','보안 이벤트',true,now()),
 ('EDR-PERSIST-001','새 서비스 설치','서비스 설치 이벤트(7045)','medium','Persistence','T1543.003','Windows Service','보안 이벤트',true,now()),
 ('EDR-PERSIST-002','자동 실행 항목 추가·변경','Run 키·시작프로그램·서비스·예약작업 등 기준선 대비 추가/변경 (사용자·임시 경로면 high)','medium','Persistence','T1547.001','Registry Run Keys / Startup Folder','자동 실행',true,now()),
 ('EDR-PERSIST-003','예약 작업 생성·변경','예약 작업 생성(4698)/변경(4702)','medium','Persistence','T1053.005','Scheduled Task','보안 이벤트',true,now()),
 ('EDR-ACCT-001','로컬 계정 생성','계정 생성(4720)','medium','Persistence','T1136.001','Create Account: Local Account','보안 이벤트',true,now()),
 ('EDR-ACCT-002','보안 그룹 구성원 추가','보안/로컬/유니버설 그룹 구성원 추가(4728/4732/4756)','high','Persistence','T1098','Account Manipulation','보안 이벤트',true,now()),
 ('EDR-NET-001','외부에서 RDP 연결','공인 IP 로부터 3389 인바운드 연결 수립','high','Lateral Movement','T1021.001','Remote Desktop Protocol','네트워크',true,now()),
 ('EDR-MAL-001','평판 악성 파일 실행','해시 평판이 악성/의심인 파일을 최근 7일 내 실행','critical','Execution','T1204.002','User Execution: Malicious File','프로세스 + 해시 평판',true,now());

create or replace function public.is_any_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.tenant_members
                 where user_id = (select auth.uid()) and role in ('owner','admin'))
$$;
revoke all on function public.is_any_admin() from public, anon;
grant execute on function public.is_any_admin() to authenticated;

alter table public.detection_rules enable row level security;
grant select on public.detection_rules to authenticated, grafana_reader, edr_enricher;
grant update (enabled, updated_at) on public.detection_rules to authenticated;
create policy rules_read   on public.detection_rules for select to authenticated using (true);
create policy rules_toggle on public.detection_rules for update to authenticated
  using ((select public.is_any_admin())) with check ((select public.is_any_admin()));
create policy grafana_read on public.detection_rules for select to grafana_reader using (true);
create policy enricher_read on public.detection_rules for select to edr_enricher using (true);

-- ---------- 5) 경보 판정·코멘트·예외 ----------
alter table public.alerts
  add column if not exists resolution text
    check (resolution in ('true_positive','false_positive','benign','suppressed'));
grant update (resolution) on public.alerts to authenticated;

create table public.alert_comments (
  id          bigint generated always as identity primary key,
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  alert_id    bigint not null references public.alerts(id) on delete cascade,
  author_id   uuid not null references auth.users(id),
  body        text not null check (length(body) between 1 and 4000),
  created_at  timestamptz not null default now()
);
create index on public.alert_comments (alert_id, created_at);
alter table public.alert_comments enable row level security;
grant select, insert on public.alert_comments to authenticated;
create policy comments_read on public.alert_comments for select to authenticated
  using (tenant_id in (select public.my_tenant_ids()));
create policy comments_write on public.alert_comments for insert to authenticated
  with check (author_id = (select auth.uid())
              and (select public.has_tenant_role(tenant_id, array['owner','admin','analyst'])));

-- 예외: 조건(details 의 키·값 부분 일치)에 맞는 경보는 생성 즉시 "종결(suppressed)" 로 남긴다(삭제하지 않음 → 감사 추적 가능)
create table public.alert_suppressions (
  id          bigint generated always as identity primary key,
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  rule_id     text references public.detection_rules(rule_id),   -- null 이면 모든 규칙
  device_id   uuid references public.devices(id) on delete cascade,  -- null 이면 모든 장치
  match       jsonb not null default '{}'::jsonb,                 -- 예: {"entry": "OneDrive"}
  reason      text not null,
  created_by  uuid references auth.users(id),
  created_at  timestamptz not null default now(),
  expires_at  timestamptz,
  hit_count   bigint not null default 0
);
create index on public.alert_suppressions (tenant_id);
alter table public.alert_suppressions enable row level security;
grant select, insert, delete on public.alert_suppressions to authenticated;
create policy supp_read on public.alert_suppressions for select to authenticated
  using (tenant_id in (select public.my_tenant_ids()));
create policy supp_write on public.alert_suppressions for insert to authenticated
  with check (created_by = (select auth.uid())
              and (select public.has_tenant_role(tenant_id, array['owner','admin','analyst'])));
create policy supp_delete on public.alert_suppressions for delete to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner','admin'])));

create or replace function public.edr_before_alert_insert()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  s_id bigint;
begin
  -- 꺼진 규칙은 경보를 만들지 않는다
  if exists (select 1 from detection_rules r where r.rule_id = new.rule_id and not r.enabled) then
    return null;
  end if;
  select s.id into s_id from alert_suppressions s
  where s.tenant_id = new.tenant_id
    and (s.rule_id is null or s.rule_id = new.rule_id)
    and (s.device_id is null or s.device_id = new.device_id)
    and new.details @> s.match
    and (s.expires_at is null or s.expires_at > now())
  order by s.id limit 1;
  if s_id is not null then
    new.status := 'closed';
    new.resolution := 'suppressed';
    new.details := new.details || jsonb_build_object('suppression_id', s_id);
    update alert_suppressions set hit_count = hit_count + 1 where id = s_id;
  end if;
  return new;
end $$;
revoke all on function public.edr_before_alert_insert() from public, anon, authenticated;
create trigger trg_before_alert_insert before insert on public.alerts
  for each row execute function public.edr_before_alert_insert();

-- updated_at 자동 갱신
create or replace function public.edr_touch_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at := now(); return new; end $$;
create trigger trg_alerts_touch before update on public.alerts
  for each row execute function public.edr_touch_updated_at();

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table public.alert_comments;
  end if;
end $$;

-- ---------- 6) 콘솔 집계 함수 (security invoker: 호출한 사용자의 RLS 로 동작) ----------

-- 홈 화면 요약 (한 번의 왕복으로 카드 전체)
create or replace function public.console_overview(p_tenant uuid)
returns jsonb language sql stable security invoker set search_path = public as $$
  select jsonb_build_object(
    'open_alerts', (select coalesce(jsonb_object_agg(severity, n), '{}'::jsonb) from (
        select severity, count(*) n from alerts where tenant_id = p_tenant and status <> 'closed' group by severity) x),
    'alerts_24h', (select count(*) from alerts where tenant_id = p_tenant and created_at > now() - interval '24 hours'),
    'alerts_prev_24h', (select count(*) from alerts where tenant_id = p_tenant
                          and created_at between now() - interval '48 hours' and now() - interval '24 hours'),
    'devices', (select jsonb_build_object(
        'total',   count(*),
        'online',  count(*) filter (where last_seen_at > now() - interval '15 minutes'),
        'stale',   count(*) filter (where last_seen_at <= now() - interval '15 minutes' and last_seen_at > now() - interval '24 hours'),
        'offline', count(*) filter (where last_seen_at is null or last_seen_at <= now() - interval '24 hours'),
        'avg_cpu', round(avg((health->>'cpu_percent')::numeric), 2),
        'max_cpu', max((health->>'cpu_percent')::numeric),
        'avg_mem', round(avg((health->>'working_set_mb')::numeric), 1),
        'max_mem', max((health->>'working_set_mb')::numeric),
        'cpu_buckets', jsonb_build_array(
            count(*) filter (where (health->>'cpu_percent')::numeric < 0.25),
            count(*) filter (where (health->>'cpu_percent')::numeric >= 0.25 and (health->>'cpu_percent')::numeric < 0.5),
            count(*) filter (where (health->>'cpu_percent')::numeric >= 0.5 and (health->>'cpu_percent')::numeric < 1),
            count(*) filter (where (health->>'cpu_percent')::numeric >= 1 and (health->>'cpu_percent')::numeric < 2),
            count(*) filter (where (health->>'cpu_percent')::numeric >= 2)))
      from devices where tenant_id = p_tenant and status = 'active'),
    'failed_logons_24h', (select count(*) from security_events
        where tenant_id = p_tenant and event_id = 4625 and event_time > now() - interval '24 hours'),
    'malicious_hashes', (select count(*) from tenant_file_hashes t join file_hashes f using (sha256)
        where t.tenant_id = p_tenant and f.verdict in ('malicious','suspicious')),
    'pending_hashes', (select count(*) from tenant_file_hashes t join file_hashes f using (sha256)
        where t.tenant_id = p_tenant and f.verdict = 'pending'),
    'mttr_minutes', (select round(extract(epoch from avg(updated_at - created_at)) / 60)
        from alerts where tenant_id = p_tenant and status = 'closed' and resolution is distinct from 'suppressed'
          and created_at > now() - interval '30 days'),
    'top_rules', (select coalesce(jsonb_agg(x order by n desc), '[]'::jsonb) from (
        select a.rule_id, r.title, r.mitre_technique, count(*) n from alerts a left join detection_rules r using (rule_id)
        where a.tenant_id = p_tenant and a.created_at > now() - interval '7 days'
        group by a.rule_id, r.title, r.mitre_technique order by n desc limit 6) x),
    'top_devices', (select coalesce(jsonb_agg(x order by n desc), '[]'::jsonb) from (
        select d.id, d.hostname, count(*) n,
               count(*) filter (where a.severity in ('critical','high')) high
        from alerts a join devices d on d.id = a.device_id
        where a.tenant_id = p_tenant and a.created_at > now() - interval '7 days' and a.status <> 'closed'
        group by d.id, d.hostname order by n desc limit 6) x)
  )
$$;

-- 경보 추이 (일/시간 버킷 × 심각도)
create or replace function public.console_alert_trend(p_tenant uuid, p_days int default 14)
returns table (bucket timestamptz, severity text, n bigint)
language sql stable security invoker set search_path = public as $$
  select date_trunc(case when p_days <= 2 then 'hour' else 'day' end, created_at) as bucket, severity, count(*)
  from alerts
  where tenant_id = p_tenant and created_at > now() - make_interval(days => p_days)
  group by 1, 2 order by 1
$$;

-- 로그온 실패 추이 (시간 버킷)
create or replace function public.console_logon_failures(p_tenant uuid, p_hours int default 24)
returns table (bucket timestamptz, n bigint)
language sql stable security invoker set search_path = public as $$
  select date_bin('1 hour', event_time, 'epoch'), count(*)
  from security_events
  where tenant_id = p_tenant and event_id = 4625 and event_time > now() - make_interval(hours => p_hours)
  group by 1 order by 1
$$;

-- 장치 타임라인: 경보·보안 이벤트·자동실행 변경·새 프로세스를 시간순으로 합친다
create or replace function public.console_device_timeline(p_device uuid, p_hours int default 72, p_limit int default 300)
returns table (ts timestamptz, kind text, severity text, title text, detail jsonb)
language sql stable security invoker set search_path = public as $$
  (select created_at, 'alert', severity, title, details || jsonb_build_object('alert_id', id, 'rule_id', rule_id, 'status', status)
     from alerts where device_id = p_device and created_at > now() - make_interval(hours => p_hours))
  union all
  (select event_time, 'event',
          case when event_id in (1102,104) then 'high' when event_id = 4625 then 'low' else 'info' end,
          event_id || ' ' || coalesce(target_user, '') || coalesce(' ← ' || host(src_ip), ''),
          jsonb_build_object('event_id', event_id, 'logon_type', logon_type, 'src_ip', host(src_ip), 'record_id', record_id)
     from security_events where device_id = p_device and event_time > now() - make_interval(hours => p_hours))
  union all
  (select observed_at, 'autorun', case change when 'added' then 'medium' else 'info' end,
          case change when 'added' then '추가: ' when 'modified' then '변경: ' else '삭제: ' end || entry_name,
          jsonb_build_object('location', location, 'command', command)
     from autorun_changes where device_id = p_device and change <> 'baseline'
      and observed_at > now() - make_interval(hours => p_hours))
  union all
  (select observed_at, 'process', 'info', name,
          jsonb_build_object('pid', pid, 'path', path, 'command_line', command_line, 'user', username, 'sha256', sha256)
     from process_events where device_id = p_device and not is_snapshot
      and observed_at > now() - make_interval(hours => p_hours))
  order by 1 desc limit p_limit
$$;

revoke all on function public.console_overview(uuid), public.console_alert_trend(uuid, int),
  public.console_logon_failures(uuid, int), public.console_device_timeline(uuid, int, int) from public, anon;
grant execute on function public.console_overview(uuid)                  to authenticated;
grant execute on function public.console_alert_trend(uuid, int)          to authenticated;
grant execute on function public.console_logon_failures(uuid, int)       to authenticated;
grant execute on function public.console_device_timeline(uuid, int, int) to authenticated;

-- 구성원 목록 + 이메일 (auth.users 는 직접 읽을 수 없으므로 소속 확인 후 반환)
create or replace function public.console_members(p_tenant uuid)
returns table (user_id uuid, email text, role text, created_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select m.user_id, u.email::text, m.role, m.created_at
  from public.tenant_members m join auth.users u on u.id = m.user_id
  where m.tenant_id = p_tenant
    and p_tenant in (select public.my_tenant_ids())
  order by m.created_at
$$;
revoke all on function public.console_members(uuid) from public, anon;
grant execute on function public.console_members(uuid) to authenticated;
