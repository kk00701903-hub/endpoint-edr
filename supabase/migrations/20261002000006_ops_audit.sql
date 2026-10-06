-- =====================================================================
-- 0006 : 운영 안정성 + 감사 기록
--   1) EDR-AUTH-001 이 늦게 도착한 로그온 실패(스풀 재전송)도 잡도록 수정
--   2) 파티션 생성·보존 정리를 edr_maintenance() 하나로 묶고, pg_cron 이 없으면 enricher 가 대신 실행
--      작업 시각은 detection_state 에 남겨 콘솔 "시스템 상태"에 표시
--   3) 감사 기록(audit_log): 사용자가 한 관리·조치 행위를 바꿀 수 없게 남긴다
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1) 탐지 함수 교체 — AUTH-001 만 바뀜(나머지 규칙은 0003 과 동일)
-- ---------------------------------------------------------------------
create or replace function public.edr_run_detections()
returns int
language plpgsql security definer set search_path = public
as $$
declare
  v_from timestamptz;
  v_to   timestamptz := now();
  n      int := 0;
  c      int;
begin
  -- 동시 실행 방지
  if not pg_try_advisory_xact_lock(hashtext('edr_run_detections')) then
    return 0;
  end if;

  select last_run - interval '1 minute' into v_from from detection_state where name = 'main';
  if v_from is null then
    v_from := v_to - interval '15 minutes';
  end if;

  -- EDR-AUTH-001 : 무차별 대입(4625) — 같은 장치·같은 출발지에서 "발생 시각 기준" 10분 안에 10회 이상 실패
  --   이번에 새로 들어온 실패가 있는 (장치, 출발지)만 골라, 그 주변 실패로 10분 이동 창을 계산한다.
  --   → 네트워크가 끊겼다가 나중에 스풀로 올라온 실패도 탐지된다(이전: "지금부터 10분 전"만 봄).
  --   같은 공격은 발생 시각의 시(hour) 단위로 1건.
  with fresh as (
    select device_id, src_ip, min(event_time) as lo, max(event_time) as hi
    from security_events
    where event_id = 4625 and ingested_at > v_from and event_time > v_to - interval '2 days'
    group by device_id, src_ip
  ), win as (
    select s.tenant_id, s.device_id, s.src_ip, s.event_time, s.target_user, s.logon_type,
           count(*) over (partition by s.device_id, s.src_ip order by s.event_time
                          range between interval '10 minutes' preceding and current row) as cnt
    from security_events s
    join fresh f on f.device_id = s.device_id and f.src_ip is not distinct from s.src_ip
    where s.event_id = 4625
      and s.event_time between f.lo - interval '10 minutes' and f.hi
  ), hit as (
    select tenant_id, device_id, src_ip, date_trunc('hour', event_time) as hr,
           max(cnt) as peak, min(event_time) as first_at, max(event_time) as last_at,
           jsonb_agg(distinct target_user) as users, jsonb_agg(distinct logon_type) as types
    from win
    where cnt >= 10
    group by tenant_id, device_id, src_ip, date_trunc('hour', event_time)
  )
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
  select h.tenant_id, h.device_id, 'EDR-AUTH-001', 'high',
         '로그온 무차별 대입 의심 (' || coalesce(host(h.src_ip), '출발지 미상') || ')',
         jsonb_build_object('src_ip', host(h.src_ip), 'failures', h.peak,
                            'users', h.users, 'logon_types', h.types, 'window_minutes', 10,
                            'first_at', h.first_at, 'last_at', h.last_at,
                            'delayed', v_to - h.last_at > interval '10 minutes'),
         format('AUTH001:%s:%s:%s', h.device_id, coalesce(host(h.src_ip), '-'),
                to_char(h.hr at time zone 'UTC', 'YYYYMMDDHH24'))
  from hit h
  on conflict (tenant_id, dedup_key) do nothing;
  get diagnostics c = row_count; n := n + c;

  -- EDR-AUTH-002 : 실패 다수 후 같은 출발지에서 로그온 성공 → 계정 탈취 가능성
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
  select ok.tenant_id, ok.device_id, 'EDR-AUTH-002', 'critical',
         '무차별 대입 후 로그온 성공: ' || coalesce(ok.target_user, '?') || ' ← ' || host(ok.src_ip),
         jsonb_build_object('src_ip', host(ok.src_ip), 'user', ok.target_user,
                            'logon_type', ok.logon_type, 'failures_before', f.cnt, 'event_time', ok.event_time),
         format('AUTH002:%s:%s', ok.device_id, ok.record_id)
  from security_events ok
  cross join lateral (
    select count(*) as cnt from security_events x
    where x.device_id = ok.device_id and x.event_id = 4625 and x.src_ip = ok.src_ip
      and x.event_time between ok.event_time - interval '30 minutes' and ok.event_time
  ) f
  where ok.event_id = 4624 and ok.logon_type in (3, 10) and ok.src_ip is not null
    and ok.ingested_at > v_from and ok.event_time > v_to - interval '2 days'
    and f.cnt >= 5
  on conflict (tenant_id, dedup_key) do nothing;
  get diagnostics c = row_count; n := n + c;

  -- EDR-AUTH-003 : 공인 IP 에서 RDP(LogonType 10) 로그온 성공
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
  select s.tenant_id, s.device_id, 'EDR-AUTH-003', 'high',
         '외부 IP 에서 원격 데스크톱 로그온: ' || coalesce(s.target_user, '?') || ' ← ' || host(s.src_ip),
         jsonb_build_object('src_ip', host(s.src_ip), 'user', s.target_user, 'event_time', s.event_time),
         format('AUTH003:%s:%s', s.device_id, s.record_id)
  from security_events s
  where s.event_id = 4624 and s.logon_type = 10 and edr_is_public_ip(s.src_ip)
    and s.ingested_at > v_from and s.event_time > v_to - interval '2 days'
  on conflict (tenant_id, dedup_key) do nothing;
  get diagnostics c = row_count; n := n + c;

  -- EDR-LOG-001 / PERSIST-001 / PERSIST-003 / ACCT-001 / ACCT-002 : 단일 이벤트 규칙
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
  select s.tenant_id, s.device_id, r.rule_id, r.severity,
         r.title || coalesce(': ' || nullif(coalesce(s.data->>'ServiceName', s.data->>'TaskName', s.target_user), ''), ''),
         jsonb_build_object('event_id', s.event_id, 'event_time', s.event_time, 'data', s.data),
         format('%s:%s:%s:%s', r.rule_id, s.device_id, s.channel, s.record_id)
  from security_events s
  join (values
    (1102, 'EDR-LOG-001',     'high',   '보안 감사 로그가 삭제됨'),
    (104,  'EDR-LOG-001',     'high',   '시스템 이벤트 로그가 삭제됨'),
    (7045, 'EDR-PERSIST-001', 'medium', '새 서비스 설치'),
    (4698, 'EDR-PERSIST-003', 'medium', '예약 작업 생성'),
    (4702, 'EDR-PERSIST-003', 'low',    '예약 작업 변경'),
    (4720, 'EDR-ACCT-001',    'medium', '로컬 계정 생성'),
    (4728, 'EDR-ACCT-002',    'high',   '보안 그룹에 구성원 추가'),
    (4732, 'EDR-ACCT-002',    'high',   '로컬 그룹에 구성원 추가'),
    (4756, 'EDR-ACCT-002',    'high',   '유니버설 그룹에 구성원 추가')
  ) as r(event_id, rule_id, severity, title) on r.event_id = s.event_id
  where s.ingested_at > v_from and s.event_time > v_to - interval '2 days'
  on conflict (tenant_id, dedup_key) do nothing;
  get diagnostics c = row_count; n := n + c;

  -- EDR-PERSIST-002 : 시작프로그램/서비스/예약작업 항목 추가·변경 (기준선 이후)
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
  select a.tenant_id, a.device_id, 'EDR-PERSIST-002',
         case when a.image_path ~* '\\(appdata|temp|users\\public|programdata)\\' then 'high' else 'medium' end,
         '자동 실행 항목 ' || case a.change when 'added' then '추가' else '변경' end || ': ' || a.entry_name,
         jsonb_build_object('location', a.location, 'entry', a.entry_name, 'command', a.command,
                            'image_path', a.image_path, 'sha256', a.sha256, 'change', a.change),
         format('PERSIST002:%s:%s:%s:%s', a.device_id, md5(a.location || '|' || a.entry_name), a.change,
                to_char(a.observed_at, 'YYYYMMDDHH24MISS'))
  from autorun_changes a
  where a.change in ('added', 'modified') and a.ingested_at > v_from
  on conflict (tenant_id, dedup_key) do nothing;
  get diagnostics c = row_count; n := n + c;

  -- EDR-NET-001 : 공인 IP 로부터 RDP(3389) 인바운드 연결 수립
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
  select c2.tenant_id, c2.device_id, 'EDR-NET-001', 'high',
         '외부에서 RDP 포트로 연결됨: ' || host(c2.remote_ip),
         jsonb_build_object('remote_ip', host(c2.remote_ip), 'remote_port', c2.remote_port,
                            'process', c2.process_name, 'observed_at', c2.observed_at),
         format('NET001:%s:%s:%s', c2.device_id, host(c2.remote_ip), to_char(date_trunc('hour', c2.observed_at), 'YYYYMMDDHH24'))
  from net_connections c2
  where c2.direction = 'inbound' and c2.local_port = 3389 and c2.is_external
    and c2.ingested_at > v_from and c2.observed_at > v_to - interval '2 days'
  on conflict (tenant_id, dedup_key) do nothing;
  get diagnostics c = row_count; n := n + c;

  insert into detection_state (name, last_run) values ('main', v_to)
  on conflict (name) do update set last_run = excluded.last_run;
  return n;
end $$;

revoke all on function public.edr_run_detections() from public, anon, authenticated;
grant execute on function public.edr_run_detections() to edr_enricher;

-- ---------------------------------------------------------------------
-- 2) 유지보수 작업 하나로: 파티션 미리 만들기 + 보존 기간 지난 파티션 삭제
--    pg_cron 이 있으면 매일 실행, 없으면 enricher(RUN_DETECTIONS=1)가 시작 시·6시간마다 실행. 여러 번 실행해도 안전.
-- ---------------------------------------------------------------------
create or replace function public.edr_maintenance(months_ahead int default 2, retention_months int default 3)
returns void
language plpgsql security definer set search_path = public
as $$
begin
  if not pg_try_advisory_xact_lock(hashtext('edr_maintenance')) then
    return;  -- 다른 곳에서 실행 중
  end if;
  perform public.edr_ensure_partitions(months_ahead);
  perform public.edr_drop_old_partitions(retention_months);
  insert into detection_state (name, last_run) values ('maintenance', now())
  on conflict (name) do update set last_run = excluded.last_run;
end $$;

revoke all on function public.edr_maintenance(int, int) from public, anon, authenticated;
grant execute on function public.edr_maintenance(int, int) to edr_enricher;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    begin perform cron.unschedule('edr-partitions'); exception when others then null; end;
    begin perform cron.unschedule('edr-retention');  exception when others then null; end;
    perform cron.schedule('edr-maintenance', '10 0 * * *', 'select public.edr_maintenance()');
  end if;
end $$;

select public.edr_maintenance();

-- 시스템 상태(콘솔 설정 화면): 마지막 탐지·유지보수 시각, 파티션이 몇 달 앞까지 있는지, 마지막 수집 시각
create or replace function public.console_system_status(p_tenant uuid)
returns jsonb
language plpgsql stable security definer set search_path = public
as $$
declare res jsonb;
begin
  if p_tenant is null or p_tenant not in (select public.my_tenant_ids()) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  select jsonb_build_object(
    'now', now(),
    'detections_at', (select last_run from detection_state where name = 'main'),
    'maintenance_at', (select last_run from detection_state where name = 'maintenance'),
    'scheduler', case when exists (select 1 from pg_extension where extname = 'pg_cron') then 'pg_cron' else 'enricher' end,
    -- 세 텔레메트리 테이블 중 가장 짧은 쪽 기준, 파티션이 준비된 마지막 날(이 날짜 이후 데이터는 저장 실패)
    'partitions_until', (
      select min(upper_bound) from (
        select p.relname, max(to_date(right(c.relname, 6), 'YYYYMM') + interval '1 month')::date as upper_bound
        from pg_inherits i
        join pg_class c on c.oid = i.inhrelid
        join pg_class p on p.oid = i.inhparent
        where p.relname in ('process_events', 'net_connections', 'security_events')
          and right(c.relname, 6) ~ '^\d{6}$'
        group by p.relname
      ) x),
    'last_ingest_at', (select max(last_seen_at) from devices where tenant_id = p_tenant),
    'devices_reporting_1h', (select count(*) from devices where tenant_id = p_tenant and last_seen_at > now() - interval '1 hour'),
    'pending_hashes', (select count(*) from tenant_file_hashes t join file_hashes f using (sha256)
                        where t.tenant_id = p_tenant and f.verdict = 'pending')
  ) into res;
  return res;
end $$;

revoke all on function public.console_system_status(uuid) from public, anon;
grant execute on function public.console_system_status(uuid) to authenticated;

-- ---------------------------------------------------------------------
-- 3) 감사 기록
--   * 화면·API 로 사용자가 한 행위만 남긴다(auth.uid() 가 있는 경우). 수집·탐지 같은 시스템 동작은 제외.
--   * 쓰기는 트리거(security definer)만 가능. 사용자는 누구도 수정·삭제할 수 없다(정책 없음).
--   * 조회는 조직의 소유자·관리자만.
-- ---------------------------------------------------------------------
create table public.audit_log (
  id           bigint generated always as identity primary key,
  tenant_id    uuid not null references public.tenants(id) on delete cascade,
  actor_id     uuid,
  actor_email  text,
  action       text not null,      -- 예: incident.close, alert.update, rule.disable, enrollment_key.create
  target_type  text not null,
  target_id    text,
  target_label text,
  changes      jsonb not null default '{}'::jsonb,  -- 바뀐 항목 {열: [이전,이후]}
  created_at   timestamptz not null default now()
);
create index on public.audit_log (tenant_id, created_at desc);
alter table public.audit_log enable row level security;
create policy audit_read on public.audit_log for select to authenticated
  using (tenant_id in (select public.my_tenant_ids())
         and (select public.has_tenant_role(tenant_id, array['owner','admin'])));
grant select on public.audit_log to authenticated;
revoke insert, update, delete, truncate on public.audit_log from public, anon, authenticated;

-- 두 행에서 지정한 열 중 바뀐 것만 {열: [이전, 이후]}
create or replace function public.edr_audit_diff(o jsonb, n jsonb, cols text[])
returns jsonb language sql immutable as $$
  select coalesce(jsonb_object_agg(c, jsonb_build_array(o -> c, n -> c)), '{}'::jsonb)
  from unnest(cols) as c
  where (o -> c) is distinct from (n -> c)
$$;

create or replace function public.edr_audit()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  uid    uuid := (select auth.uid());
  email  text;
  o      jsonb := case when tg_op in ('UPDATE', 'DELETE') then to_jsonb(old) end;
  nw     jsonb := case when tg_op in ('INSERT', 'UPDATE') then to_jsonb(new) end;
  r      jsonb := coalesce(nw, o);
  diff   jsonb := '{}'::jsonb;
  act    text;
  ttype  text;
  label  text;
  tid    text;
begin
  if uid is null then
    return null;  -- 시스템 동작(수집·탐지·억제 규칙)은 기록하지 않음
  end if;
  select u.email into email from auth.users u where u.id = uid;

  case tg_table_name
  when 'alerts' then
    -- 인시던트 종결에 딸린 경보 일괄 종결은 인시던트 기록 한 줄로 충분
    if current_setting('edr.audit_cascade', true) = 'on' then return null; end if;
    diff := edr_audit_diff(o, nw, array['status', 'resolution', 'assigned_to']);
    if diff = '{}'::jsonb then return null; end if;
    ttype := 'alert'; tid := r->>'id'; label := r->>'title';
    act := case when nw->>'status' = 'closed' and o->>'status' <> 'closed' then 'alert.close'
                when o->>'status' = 'closed' and nw->>'status' <> 'closed' then 'alert.reopen'
                else 'alert.update' end;
  when 'incidents' then
    diff := edr_audit_diff(o, nw, array['status', 'resolution', 'assigned_to']);
    if diff = '{}'::jsonb then return null; end if;
    ttype := 'incident'; tid := r->>'id'; label := r->>'title';
    act := case when nw->>'status' = 'closed' and o->>'status' <> 'closed' then 'incident.close'
                when o->>'status' = 'closed' and nw->>'status' <> 'closed' then 'incident.reopen'
                else 'incident.update' end;
  when 'detection_rules' then
    diff := edr_audit_diff(o, nw, array['enabled', 'severity']);
    if diff = '{}'::jsonb then return null; end if;
    ttype := 'rule'; tid := r->>'rule_id'; label := r->>'title';
    act := case when (nw->>'enabled')::boolean then 'rule.enable' else 'rule.disable' end;
    -- 규칙은 전사 공통이므로, 바꾼 사람이 관리자인 조직마다 남긴다
    insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
    select m.tenant_id, uid, email, act, ttype, tid, label, diff
    from tenant_members m where m.user_id = uid and m.role in ('owner', 'admin');
    return null;
  when 'alert_suppressions' then
    ttype := 'suppression'; tid := r->>'id';
    label := coalesce(r->>'rule_id', '') || coalesce(' · ' || nullif(r->>'reason', ''), '');
    act := case tg_op when 'INSERT' then 'suppression.create' else 'suppression.delete' end;
    diff := jsonb_build_object('rule_id', r->'rule_id', 'device_id', r->'device_id', 'match', r->'match', 'expires_at', r->'expires_at');
  when 'enrollment_keys' then
    ttype := 'enrollment_key'; tid := r->>'id'; label := r->>'label';
    if tg_op = 'INSERT' then
      act := 'enrollment_key.create';
      diff := jsonb_build_object('max_uses', r->'max_uses', 'expires_at', r->'expires_at');
    else
      diff := edr_audit_diff(o, nw, array['revoked', 'max_uses', 'expires_at']);
      if diff = '{}'::jsonb then return null; end if;   -- 사용 횟수 증가는 기록 안 함
      act := case when (nw->>'revoked')::boolean then 'enrollment_key.revoke' else 'enrollment_key.update' end;
    end if;
  when 'tenant_members' then
    ttype := 'member'; tid := r->>'user_id';
    select u.email into label from auth.users u where u.id = (r->>'user_id')::uuid;
    act := case tg_op when 'INSERT' then 'member.add' when 'DELETE' then 'member.remove' else 'member.role' end;
    diff := case tg_op when 'UPDATE' then edr_audit_diff(o, nw, array['role']) else jsonb_build_object('role', r->'role') end;
    if tg_op = 'UPDATE' and diff = '{}'::jsonb then return null; end if;
  when 'devices' then
    diff := edr_audit_diff(o, nw, array['status', 'tags']);
    if diff = '{}'::jsonb then return null; end if;
    ttype := 'device'; tid := r->>'id'; label := r->>'hostname';
    act := 'device.update';
  else
    return null;
  end case;

  insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
  values ((r->>'tenant_id')::uuid, uid, email, act, ttype, tid, label, diff);
  return null;
end $$;
revoke all on function public.edr_audit() from public, anon, authenticated;

create trigger trg_audit after update on public.alerts
  for each row execute function public.edr_audit();
create trigger trg_audit after update on public.incidents
  for each row execute function public.edr_audit();
create trigger trg_audit after update on public.detection_rules
  for each row execute function public.edr_audit();
create trigger trg_audit after insert or delete on public.alert_suppressions
  for each row execute function public.edr_audit();
create trigger trg_audit after insert or update on public.enrollment_keys
  for each row execute function public.edr_audit();
create trigger trg_audit after insert or update or delete on public.tenant_members
  for each row execute function public.edr_audit();
create trigger trg_audit after update of status, tags on public.devices
  for each row execute function public.edr_audit();

-- 인시던트 종결: 딸린 경보 일괄 종결은 감사 기록에서 인시던트 한 줄로 묶는다(동작은 0005 와 동일)
create or replace function public.console_close_incident(p_incident bigint, p_resolution text)
returns int language plpgsql security invoker set search_path = public as $$
declare n int;
begin
  if p_resolution not in ('true_positive','false_positive','benign') then
    raise exception 'invalid resolution';
  end if;
  update incidents set status = 'closed', resolution = p_resolution where id = p_incident;
  get diagnostics n = row_count;
  if n = 0 then raise exception 'forbidden or not found' using errcode = '42501'; end if;
  perform set_config('edr.audit_cascade', 'on', true);
  update alerts set status = 'closed', resolution = p_resolution where incident_id = p_incident and status <> 'closed';
  perform set_config('edr.audit_cascade', 'off', true);
  return n;
end $$;

-- 인시던트 상태 변경(조사 시작·다시 열기·담당 지정): 딸린 경보 일괄 변경까지 한 번에, 감사 기록은 인시던트 한 줄로
create or replace function public.console_update_incident(p_incident bigint, p_status text, p_assign_to_me boolean default false)
returns int language plpgsql security invoker set search_path = public as $$
declare n int; uid uuid := (select auth.uid());
begin
  if p_status is not null and p_status not in ('open', 'acknowledged') then
    raise exception 'invalid status (종결은 console_close_incident)';
  end if;
  update incidents
     set status = coalesce(p_status, status),
         resolution = case when p_status = 'open' then null else resolution end,
         assigned_to = case when p_assign_to_me then uid else assigned_to end
   where id = p_incident;
  get diagnostics n = row_count;
  if n = 0 then raise exception 'forbidden or not found' using errcode = '42501'; end if;
  if p_status = 'acknowledged' then
    perform set_config('edr.audit_cascade', 'on', true);
    update alerts set status = 'acknowledged', assigned_to = case when p_assign_to_me then uid else assigned_to end
     where incident_id = p_incident and status = 'open';
    perform set_config('edr.audit_cascade', 'off', true);
  end if;
  return n;
end $$;
revoke all on function public.console_update_incident(bigint, text, boolean) from public, anon;
grant execute on function public.console_update_incident(bigint, text, boolean) to authenticated;
