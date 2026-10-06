-- =====================================================================
-- 인시던트 · 엔터티 · ATT&CK 매트릭스 · 저장 쿼리
--   최신 EDR 콘솔(Defender XDR · CrowdStrike · SentinelOne)의 공통 구조:
--   "경보 하나하나"가 아니라 "관련 경보를 묶은 사건(인시던트)" 단위로 처리한다.
--
--   묶음 규칙 (경보가 들어올 때 트리거가 자동으로 판단)
--     1) 같은 장치에서 마지막 경보 후 2시간 안에 생긴 경보
--     2) 다른 장치라도 같은 출발지 IP / 같은 파일 해시가 24시간 안에 다시 나온 경보 (확산 추적)
--     3) 예외 규칙으로 자동 종결된 경보는 묶지 않는다
-- =====================================================================

create or replace function public.edr_sev_rank(s text)
returns int language sql immutable as $$
  select case s when 'critical' then 4 when 'high' then 3 when 'medium' then 2 when 'low' then 1 else 0 end
$$;

create table public.incidents (
  id            bigint generated always as identity primary key,
  tenant_id     uuid not null references public.tenants(id) on delete cascade,
  title         text not null,
  severity      text not null check (severity in ('low','medium','high','critical')),
  status        text not null default 'open' check (status in ('open','acknowledged','closed')),
  resolution    text check (resolution in ('true_positive','false_positive','benign')),
  assigned_to   uuid references auth.users(id),
  device_ids    uuid[] not null default '{}',
  ips           text[] not null default '{}',
  hashes        text[] not null default '{}',
  users         text[] not null default '{}',
  tactics       text[] not null default '{}',
  techniques    text[] not null default '{}',
  rule_ids      text[] not null default '{}',
  alert_count   int not null default 0,
  first_seen_at timestamptz not null,
  last_seen_at  timestamptz not null,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index on public.incidents (tenant_id, status, last_seen_at desc);
create index on public.incidents using gin (device_ids);
create index on public.incidents using gin (ips);
create index on public.incidents using gin (hashes);

alter table public.alerts add column if not exists incident_id bigint references public.incidents(id) on delete set null;
create index if not exists alerts_incident on public.alerts (incident_id);

create trigger trg_incidents_touch before update on public.incidents
  for each row execute function public.edr_touch_updated_at();

-- 경보 → 인시던트 묶기 (AFTER INSERT: 실제로 들어간 경보만. 중복 dedup 으로 버려진 경보는 오지 않는다)
create or replace function public.edr_attach_alert(a public.alerts)
returns void language plpgsql security definer set search_path = public as $$
declare
  inc       bigint;
  v_ip      text := nullif(coalesce(a.details->>'src_ip', a.details->>'remote_ip'), '');
  v_hash    text := nullif(a.details->>'sha256', '');
  v_user    text := nullif(coalesce(a.details->>'user', a.details->'users'->>0), '');
  v_tactic  text;
  v_tech    text;
  v_host    text;
begin
  if a.status = 'closed' then
    return;
  end if;
  select mitre_tactic, mitre_technique into v_tactic, v_tech from detection_rules where rule_id = a.rule_id;
  select hostname into v_host from devices where id = a.device_id;

  select i.id into inc from incidents i
  where i.tenant_id = a.tenant_id and i.status <> 'closed'
    and (
      (a.device_id is not null and a.device_id = any (i.device_ids) and i.last_seen_at > a.created_at - interval '2 hours')
      or (v_ip is not null and v_ip = any (i.ips) and i.last_seen_at > a.created_at - interval '24 hours')
      or (v_hash is not null and v_hash = any (i.hashes) and i.last_seen_at > a.created_at - interval '24 hours')
    )
  order by i.last_seen_at desc
  limit 1;

  if inc is null then
    insert into incidents (tenant_id, title, severity, device_ids, ips, hashes, users, tactics, techniques, rule_ids,
                           alert_count, first_seen_at, last_seen_at)
    values (a.tenant_id, a.title, a.severity,
            case when a.device_id is null then '{}' else array[a.device_id] end,
            case when v_ip is null then '{}' else array[v_ip] end,
            case when v_hash is null then '{}' else array[v_hash] end,
            case when v_user is null then '{}' else array[v_user] end,
            case when v_tactic is null then '{}' else array[v_tactic] end,
            case when v_tech is null then '{}' else array[v_tech] end,
            array[a.rule_id], 1, a.created_at, a.created_at)
    returning id into inc;
  else
    update incidents i set
      severity     = case when edr_sev_rank(a.severity) > edr_sev_rank(i.severity) then a.severity else i.severity end,
      device_ids   = case when a.device_id is null or a.device_id = any (i.device_ids) then i.device_ids else i.device_ids || a.device_id end,
      ips          = case when v_ip is null or v_ip = any (i.ips) then i.ips else i.ips || v_ip end,
      hashes       = case when v_hash is null or v_hash = any (i.hashes) then i.hashes else i.hashes || v_hash end,
      users        = case when v_user is null or v_user = any (i.users) then i.users else i.users || v_user end,
      tactics      = case when v_tactic is null or v_tactic = any (i.tactics) then i.tactics else i.tactics || v_tactic end,
      techniques   = case when v_tech is null or v_tech = any (i.techniques) then i.techniques else i.techniques || v_tech end,
      rule_ids     = case when a.rule_id = any (i.rule_ids) then i.rule_ids else i.rule_ids || a.rule_id end,
      alert_count  = i.alert_count + 1,
      last_seen_at = greatest(i.last_seen_at, a.created_at),
      first_seen_at = least(i.first_seen_at, a.created_at),
      -- 제목: 단계가 3개 이상이면 다단계 공격으로 승격
      title = case
        when cardinality(case when v_tactic is null or v_tactic = any (i.tactics) then i.tactics else i.tactics || v_tactic end) >= 3
          then '다단계 공격 의심: ' || coalesce(v_host, '여러 장치')
            || case when cardinality(i.device_ids) > 1 or (a.device_id is not null and not a.device_id = any (i.device_ids)) then ' 외' else '' end
        else i.title end,
      -- 이미 종결 처리 중이 아니면 새 경보가 붙을 때 다시 '새 경보' 상태로
      status = case when i.status = 'acknowledged' then 'acknowledged' else 'open' end
    where i.id = inc;
  end if;

  update alerts set incident_id = inc where id = a.id;
end $$;

create or replace function public.edr_attach_incident()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  perform edr_attach_alert(new);
  return null;
end $$;
revoke all on function public.edr_attach_alert(public.alerts) from public, anon, authenticated;
revoke all on function public.edr_attach_incident() from public, anon, authenticated;
create trigger trg_z_attach_incident after insert on public.alerts
  for each row execute function public.edr_attach_incident();

-- 인시던트 처리 기록
create table public.incident_comments (
  id          bigint generated always as identity primary key,
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  incident_id bigint not null references public.incidents(id) on delete cascade,
  author_id   uuid not null references auth.users(id),
  body        text not null check (length(body) between 1 and 4000),
  created_at  timestamptz not null default now()
);
create index on public.incident_comments (incident_id, created_at);

-- 저장된 헌팅 쿼리
create table public.saved_queries (
  id          bigint generated always as identity primary key,
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  name        text not null check (length(name) between 1 and 80),
  query       text not null check (length(query) between 1 and 2000),
  hours       int not null default 168,
  created_by  uuid not null references auth.users(id),
  created_at  timestamptz not null default now()
);
create index on public.saved_queries (tenant_id);

-- ---------- RLS ----------
alter table public.incidents         enable row level security;
alter table public.incident_comments enable row level security;
alter table public.saved_queries     enable row level security;

grant select on public.incidents, public.incident_comments, public.saved_queries to authenticated;
grant update (status, resolution, assigned_to) on public.incidents to authenticated;
grant insert on public.incident_comments to authenticated;
grant insert, delete on public.saved_queries to authenticated;
grant select on public.incidents to grafana_reader, edr_enricher;

create policy inc_select on public.incidents for select to authenticated
  using (tenant_id in (select public.my_tenant_ids()));
create policy inc_triage on public.incidents for update to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner','admin','analyst'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner','admin','analyst'])));
create policy grafana_read on public.incidents for select to grafana_reader using (true);
create policy enricher_read on public.incidents for select to edr_enricher using (true);

create policy inc_comments_read on public.incident_comments for select to authenticated
  using (tenant_id in (select public.my_tenant_ids()));
create policy inc_comments_write on public.incident_comments for insert to authenticated
  with check (author_id = (select auth.uid())
              and (select public.has_tenant_role(tenant_id, array['owner','admin','analyst'])));

create policy sq_read on public.saved_queries for select to authenticated
  using (tenant_id in (select public.my_tenant_ids()));
create policy sq_write on public.saved_queries for insert to authenticated
  with check (created_by = (select auth.uid())
              and (select public.has_tenant_role(tenant_id, array['owner','admin','analyst'])));
create policy sq_delete on public.saved_queries for delete to authenticated
  using (created_by = (select auth.uid()) or (select public.has_tenant_role(tenant_id, array['owner','admin'])));

-- 인시던트를 종결하면 그 안의 미처리 경보도 같은 판정으로 종결 (호출자 RLS 로 동작)
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
  update alerts set status = 'closed', resolution = p_resolution where incident_id = p_incident and status <> 'closed';
  return n;
end $$;

-- ---------- 엔터티 프로필: IP / 파일 해시 / 사용자 ----------
create or replace function public.console_entity(p_tenant uuid, p_kind text, p_value text, p_days int default 30)
returns jsonb language plpgsql stable security invoker set search_path = public as $$
declare
  since timestamptz := now() - make_interval(days => p_days);
  res jsonb;
begin
  if p_kind = 'ip' then
    with obs as (
      select device_id, observed_at as ts, 'connection' as src from net_connections
        where tenant_id = p_tenant and remote_ip = p_value::inet and observed_at > since
      union all
      select device_id, event_time, 'logon_' || event_id from security_events
        where tenant_id = p_tenant and src_ip = p_value::inet and event_time > since
    )
    select jsonb_build_object(
      'first_seen', min(ts), 'last_seen', max(ts), 'observations', count(*),
      'is_public', edr_is_public_ip(p_value::inet),
      'logon_failures', count(*) filter (where src = 'logon_4625'),
      'logon_success', count(*) filter (where src = 'logon_4624'),
      'connections', count(*) filter (where src = 'connection'),
      'devices', (select coalesce(jsonb_agg(x order by x->>'last' desc), '[]') from (
          select jsonb_build_object('id', o.device_id, 'hostname', d.hostname, 'n', count(*), 'last', max(o.ts)) x
          from obs o join devices d on d.id = o.device_id group by o.device_id, d.hostname) y))
    into res from obs;
  elsif p_kind = 'hash' then
    with obs as (
      select device_id, observed_at as ts, name, path from process_events
        where tenant_id = p_tenant and sha256 = lower(p_value) and observed_at > since
    )
    select jsonb_build_object(
      'first_seen', min(ts), 'last_seen', max(ts), 'observations', count(*),
      'names', (select coalesce(jsonb_agg(distinct name), '[]') from obs),
      'paths', (select coalesce(jsonb_agg(distinct path), '[]') from obs where path is not null),
      'reputation', (select to_jsonb(f) - 'sources' from file_hashes f where f.sha256 = lower(p_value)),
      'running_now', (select count(*) from processes_current where tenant_id = p_tenant and sha256 = lower(p_value)),
      'autoruns', (select count(*) from autoruns where tenant_id = p_tenant and sha256 = lower(p_value) and removed_at is null),
      'devices', (select coalesce(jsonb_agg(x order by x->>'last' desc), '[]') from (
          select jsonb_build_object('id', o.device_id, 'hostname', d.hostname, 'n', count(*), 'last', max(o.ts)) x
          from obs o join devices d on d.id = o.device_id group by o.device_id, d.hostname) y))
    into res from obs;
  elsif p_kind = 'user' then
    with obs as (
      select device_id, event_time as ts, event_id, src_ip from security_events
        where tenant_id = p_tenant and lower(target_user) = lower(p_value) and event_time > since
    )
    select jsonb_build_object(
      'first_seen', min(ts), 'last_seen', max(ts), 'observations', count(*),
      'logon_failures', count(*) filter (where event_id = 4625),
      'logon_success', count(*) filter (where event_id = 4624),
      'source_ips', (select coalesce(jsonb_agg(distinct host(src_ip)), '[]') from obs where src_ip is not null),
      'processes', (select count(*) from processes_current where tenant_id = p_tenant
                    and lower(coalesce(nullif(split_part(username, '\', 2), ''), username)) = lower(p_value)),
      'devices', (select coalesce(jsonb_agg(x order by x->>'last' desc), '[]') from (
          select jsonb_build_object('id', o.device_id, 'hostname', d.hostname, 'n', count(*), 'last', max(o.ts)) x
          from obs o join devices d on d.id = o.device_id group by o.device_id, d.hostname) y))
    into res from obs;
  else
    raise exception 'unknown entity kind %', p_kind;
  end if;
  return res;
end $$;

-- ---------- ATT&CK 매트릭스: 기법별 경보 수 ----------
create or replace function public.console_attack_matrix(p_tenant uuid, p_days int default 30)
returns table (technique text, tactic text, hits bigint, last_seen timestamptz)
language sql stable security invoker set search_path = public as $$
  select r.mitre_technique, r.mitre_tactic, count(a.id), max(a.created_at)
  from detection_rules r
  left join alerts a on a.rule_id = r.rule_id and a.tenant_id = p_tenant
                    and a.created_at > now() - make_interval(days => p_days)
  group by r.mitre_technique, r.mitre_tactic
$$;

revoke all on function public.console_close_incident(bigint, text), public.console_entity(uuid, text, text, int),
  public.console_attack_matrix(uuid, int) from public, anon;
grant execute on function public.console_close_incident(bigint, text) to authenticated;
grant execute on function public.console_entity(uuid, text, text, int) to authenticated;
grant execute on function public.console_attack_matrix(uuid, int) to authenticated;

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table public.incidents;
  end if;
end $$;

-- 기존 미처리 경보를 시간순으로 인시던트에 묶어 둔다(이 마이그레이션 적용 시 1회)
do $$
declare r public.alerts;
begin
  for r in select * from public.alerts where incident_id is null and status <> 'closed' order by created_at loop
    perform public.edr_attach_alert(r);
  end loop;
end $$;
