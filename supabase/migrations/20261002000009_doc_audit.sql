-- =====================================================================
-- 0009 : 문서 감사 — 보안 관리자의 PC 감사(개인정보 문서 · 키워드 문서 · 오래된 문서)
--   에이전트가 정책대로 PC 의 문서를 읽기만 하고, "어느 파일에 무엇이 몇 건"만 보낸다.
--   문서 내용·개인정보 값(주민등록번호 등)은 서버에 오지 않는다.
--
--   통제
--     * 정책은 기본 꺼짐. 켜려면 "직원 고지 완료"를 기록해야 한다(제약 조건)
--     * 정책·결과·요청은 조직의 소유자·관리자만 보고 바꾼다(RLS)
--     * 정책 변경, "지금 검사" 요청, 결과 조회·내보내기를 모두 감사 기록에 남긴다
--
--   1) doc_scan_policies  조직별 정책(켜짐·간격·폴더·확장자·검출 종류·키워드·오래된 기준)
--   2) doc_scan_requests  콘솔의 "지금 검사" 요청(장치별)
--   3) doc_scans          검사 1회 기록(배치를 합산)
--   4) doc_findings       장치별 현재 결과(검사가 끝나면 그 검사에서 다시 보이지 않은 파일은 지운다)
--   5) 수집 서버 함수: edr_device_policy(정책 받기), edr_apply_doc_scan(결과 저장)
--   6) 콘솔 함수(조회 감사 포함), 권한, 감사, 유지보수(이력 1년)
-- =====================================================================

create table public.doc_scan_policies (
  tenant_id            uuid primary key references public.tenants(id) on delete cascade,
  enabled              boolean not null default false,
  interval_hours       int  not null default 168 check (interval_hours between 1 and 2160),
  folders              text[] not null default '{Desktop,Documents,Downloads}',
  extra_paths          text[] not null default '{}',
  extensions           text[] not null default '{txt,csv,log,docx,xlsx,pptx,hwp,hwpx,pdf,doc,xls,ppt}',
  detect               text[] not null default '{rrn,frn,passport,driver,card}',
  keywords             text[] not null default '{}',
  stale_days           int  not null default 1095 check (stale_days between 0 and 36500),   -- 0 이면 오래된 문서 찾기 안 함
  max_file_mb          int  not null default 20 check (max_file_mb between 1 and 100),
  notice_confirmed_at  timestamptz,                -- 직원 고지를 마쳤다고 관리자가 확인한 시각
  notice_confirmed_by  uuid references auth.users(id),
  updated_by           uuid references auth.users(id),
  updated_at           timestamptz not null default now(),
  check (not enabled or notice_confirmed_at is not null),
  check (detect <@ array['rrn', 'frn', 'passport', 'driver', 'card', 'phone']),
  check (cardinality(keywords) <= 50 and cardinality(folders) <= 20 and cardinality(extra_paths) <= 20 and cardinality(extensions) <= 40)
);

create table public.doc_scan_requests (
  id            bigint generated always as identity primary key,
  tenant_id     uuid not null references public.tenants(id) on delete cascade,
  device_id     uuid not null references public.devices(id) on delete cascade,
  requested_by  uuid references auth.users(id),
  requested_at  timestamptz not null default now(),
  picked_at     timestamptz,     -- 에이전트가 정책을 받아 간 시각
  completed_at  timestamptz,
  scan_id       text
);
create index on public.doc_scan_requests (device_id) where completed_at is null;
create index on public.doc_scan_requests (tenant_id, requested_at desc);

create table public.doc_scans (
  id             bigint generated always as identity primary key,
  tenant_id      uuid not null references public.tenants(id) on delete cascade,
  device_id      uuid not null references public.devices(id) on delete cascade,
  scan_id        text not null,
  trigger        text not null check (trigger in ('schedule', 'request', 'manual')),
  request_id     bigint,
  status         text not null default 'running' check (status in ('running', 'done')),
  started_at     timestamptz not null,
  finished_at    timestamptz,
  files_scanned  int not null default 0,
  files_skipped  int not null default 0,
  errors         int not null default 0,
  findings       int not null default 0,
  received_at    timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  unique (device_id, scan_id)
);
create index on public.doc_scans (tenant_id, started_at desc);

create table public.doc_findings (
  tenant_id      uuid not null references public.tenants(id) on delete cascade,
  device_id      uuid not null references public.devices(id) on delete cascade,
  path           text not null,
  ext            text,
  size           bigint,
  modified_at    timestamptz,
  pii            jsonb not null default '{}'::jsonb,   -- {"rrn": 12, "phone": 3}
  pii_total      int not null default 0,
  keywords       jsonb not null default '{}'::jsonb,   -- {"대외비": 2}
  keyword_total  int not null default 0,
  stale          boolean not null default false,
  unreadable     text,
  scan_id        text not null,
  first_seen_at  timestamptz not null default now(),
  last_seen_at   timestamptz not null default now(),
  primary key (device_id, path)
);
create index on public.doc_findings (tenant_id, pii_total desc) where pii_total > 0;
create index on public.doc_findings (tenant_id, keyword_total desc) where keyword_total > 0;
create index on public.doc_findings (tenant_id, modified_at) where stale;

-- ---------------------------------------------------------------------
-- 수집 서버 함수 (edr_ingest 만 실행)
-- ---------------------------------------------------------------------

-- 장치가 15분마다 받아 가는 정책. 아직 처리하지 않은 "지금 검사" 요청이 있으면 그 번호를 함께 준다.
create or replace function public.edr_device_policy(p_device uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  t   uuid;
  pol doc_scan_policies;
  req bigint;
begin
  select tenant_id into t from devices where id = p_device and status = 'active';
  if t is null then
    raise exception 'device not active' using errcode = '42501';
  end if;
  select * into pol from doc_scan_policies where tenant_id = t;
  if pol.tenant_id is null or not pol.enabled then
    return jsonb_build_object('doc_scan', jsonb_build_object('enabled', false));
  end if;
  select id into req from doc_scan_requests
   where device_id = p_device and completed_at is null and requested_at > now() - interval '7 days'
   order by id desc limit 1;
  if req is not null then
    update doc_scan_requests set picked_at = coalesce(picked_at, now()) where id = req;
  end if;
  return jsonb_build_object('doc_scan', jsonb_build_object(
    'enabled', true, 'interval_hours', pol.interval_hours, 'folders', to_jsonb(pol.folders),
    'extra_paths', to_jsonb(pol.extra_paths), 'extensions', to_jsonb(pol.extensions), 'detect', to_jsonb(pol.detect),
    'keywords', to_jsonb(pol.keywords), 'stale_days', pol.stale_days, 'max_file_mb', pol.max_file_mb,
    'request_id', req, 'version', md5(row(pol.interval_hours, pol.folders, pol.extra_paths, pol.extensions, pol.detect,
                                          pol.keywords, pol.stale_days, pol.max_file_mb)::text)));
end $$;

-- 결과 배치 저장. 같은 검사의 배치를 합산하고, 마지막 배치가 오면 이번 검사에서 다시 보이지 않은 파일의 결과를 지운다.
create or replace function public.edr_apply_doc_scan(p_tenant uuid, p_device uuid, b jsonb)
returns int language plpgsql security definer set search_path = public as $$
declare
  v_scan  text := b->>'scan_id';
  v_final boolean := coalesce((b->>'final')::boolean, false);
  v_req   bigint := nullif(b->>'request_id', '')::bigint;
  n       int;
begin
  if not exists (select 1 from devices where id = p_device and tenant_id = p_tenant) then
    raise exception 'device % not in tenant', p_device using errcode = '42501';
  end if;
  if v_scan is null or v_scan !~ '^[0-9a-f]{8,32}$' then
    raise exception 'bad scan_id';
  end if;

  with f as (
    select left(x->>'path', 1024) as path, (x->>'size')::bigint as size,
           case when (x->>'modified_at') ~ '^(19[89]\d|2\d{3})-' then (x->>'modified_at')::timestamptz end as modified_at,
           coalesce((select jsonb_object_agg(k, v) from jsonb_each(case jsonb_typeof(x->'pii') when 'object' then x->'pii' else '{}'::jsonb end) as e(k, v)
                     where k in ('rrn', 'frn', 'passport', 'driver', 'card', 'phone') and jsonb_typeof(v) = 'number' and (v::text)::int > 0), '{}'::jsonb) as pii,
           coalesce((select jsonb_object_agg(left(k, 100), v) from (select * from jsonb_each(case jsonb_typeof(x->'keywords') when 'object' then x->'keywords' else '{}'::jsonb end) limit 50) as e(k, v)
                     where jsonb_typeof(v) = 'number' and (v::text)::int > 0), '{}'::jsonb) as keywords,
           coalesce((x->>'stale')::boolean, false) as stale, left(x->>'unreadable', 200) as unreadable
    from jsonb_array_elements(case jsonb_typeof(b->'findings') when 'array' then b->'findings' else '[]'::jsonb end) as t(x)
    where coalesce(x->>'path', '') <> ''
    limit 500
  ), u as (  -- 긴 경로를 자른 뒤 같은 값이 되면 하나만(같은 행을 두 번 고치면 오류)
    select distinct on (path) * from f order by path
  )
  insert into doc_findings as d (tenant_id, device_id, path, ext, size, modified_at, pii, pii_total, keywords, keyword_total, stale, unreadable, scan_id)
  select p_tenant, p_device, f.path, lower(substring(f.path from '\.([A-Za-z0-9]{1,8})$')), f.size, f.modified_at,
         f.pii, (select coalesce(sum((v::text)::int), 0) from jsonb_each(f.pii) as e(k, v)),
         f.keywords, (select coalesce(sum((v::text)::int), 0) from jsonb_each(f.keywords) as e(k, v)),
         f.stale, f.unreadable, v_scan
  from u as f
  on conflict (device_id, path) do update set
    ext = excluded.ext, size = excluded.size, modified_at = excluded.modified_at, pii = excluded.pii, pii_total = excluded.pii_total,
    keywords = excluded.keywords, keyword_total = excluded.keyword_total, stale = excluded.stale, unreadable = excluded.unreadable,
    scan_id = excluded.scan_id, last_seen_at = now();
  get diagnostics n = row_count;

  insert into doc_scans as s (tenant_id, device_id, scan_id, trigger, request_id, status, started_at, finished_at,
                              files_scanned, files_skipped, errors, findings)
  values (p_tenant, p_device, v_scan, coalesce(b->>'trigger', 'schedule'), v_req,
          case when v_final then 'done' else 'running' end,
          case when (b->>'started_at') ~ '^(19[89]\d|2\d{3})-' then least((b->>'started_at')::timestamptz, now()) else now() end,
          case when v_final then case when (b->>'finished_at') ~ '^(19[89]\d|2\d{3})-' then least((b->>'finished_at')::timestamptz, now()) else now() end end,
          greatest(coalesce((b->>'files_scanned')::int, 0), 0), greatest(coalesce((b->>'files_skipped')::int, 0), 0),
          greatest(coalesce((b->>'errors')::int, 0), 0), n)
  on conflict (device_id, scan_id) do update set
    files_scanned = s.files_scanned + excluded.files_scanned, files_skipped = s.files_skipped + excluded.files_skipped,
    errors = s.errors + excluded.errors, findings = s.findings + excluded.findings,
    status = case when v_final then 'done' else s.status end,
    finished_at = coalesce(excluded.finished_at, s.finished_at), updated_at = now();

  if v_final then
    -- 이번 검사에서 다시 보이지 않은 파일(지워졌거나 이제 문제없음)은 결과에서 뺀다
    delete from doc_findings where device_id = p_device and scan_id <> v_scan;
    if v_req is not null then
      update doc_scan_requests set completed_at = now(), scan_id = v_scan
       where id = v_req and device_id = p_device and completed_at is null;
    end if;
  end if;
  return n;
end $$;

revoke all on function public.edr_device_policy(uuid), public.edr_apply_doc_scan(uuid, uuid, jsonb) from public, anon, authenticated;
grant execute on function public.edr_device_policy(uuid), public.edr_apply_doc_scan(uuid, uuid, jsonb) to edr_ingest;

-- ---------------------------------------------------------------------
-- 권한: 소유자·관리자만
-- ---------------------------------------------------------------------
alter table public.doc_scan_policies enable row level security;
alter table public.doc_scan_requests enable row level security;
alter table public.doc_scans         enable row level security;
alter table public.doc_findings      enable row level security;

grant select, insert, update on public.doc_scan_policies to authenticated;
grant select, insert on public.doc_scan_requests to authenticated;
grant select on public.doc_scans, public.doc_findings to authenticated;

create policy dsp_admin on public.doc_scan_policies for all to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])) and updated_by = (select auth.uid()));
create policy dsr_read on public.doc_scan_requests for select to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])));
create policy dsr_insert on public.doc_scan_requests for insert to authenticated
  with check ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])) and requested_by = (select auth.uid())
              and exists (select 1 from public.devices d where d.id = device_id and d.tenant_id = doc_scan_requests.tenant_id));
create policy ds_read on public.doc_scans for select to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])));
-- 결과는 화면에서 console_doc_findings(조회 감사 기록)로 본다. 직접 조회도 관리자만.
create policy df_read on public.doc_findings for select to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])));

-- ---------------------------------------------------------------------
-- 감사 기록: 정책 변경 · 지금 검사 요청 (조회·내보내기는 아래 콘솔 함수가 남김)
-- ---------------------------------------------------------------------
create or replace function public.edr_audit_doc_scan()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  uid  uuid := (select auth.uid());
  diff jsonb;
  act  text;
begin
  if uid is null then
    return null;
  end if;
  if tg_table_name = 'doc_scan_policies' then
    diff := edr_audit_diff(case when tg_op = 'UPDATE' then to_jsonb(old) else '{}'::jsonb end, to_jsonb(new),
              array['enabled', 'interval_hours', 'folders', 'extra_paths', 'extensions', 'detect', 'keywords', 'stale_days', 'max_file_mb', 'notice_confirmed_at']);
    if diff = '{}'::jsonb then
      return null;
    end if;
    act := case when tg_op = 'UPDATE' and old.enabled is distinct from new.enabled
                then case when new.enabled then 'doc_scan.enable' else 'doc_scan.disable' end
                when tg_op = 'INSERT' and new.enabled then 'doc_scan.enable'
                else 'doc_scan.policy' end;
    insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
    values (new.tenant_id, uid, (select email from auth.users where id = uid), act, 'doc_scan', null, '문서 감사 정책', diff);
  else
    insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
    values (new.tenant_id, uid, (select email from auth.users where id = uid), 'doc_scan.request', 'device', new.device_id::text,
            (select hostname from devices where id = new.device_id), jsonb_build_object('request_id', new.id));
  end if;
  return null;
end $$;
revoke all on function public.edr_audit_doc_scan() from public, anon, authenticated;
create trigger trg_audit after insert or update on public.doc_scan_policies
  for each row execute function public.edr_audit_doc_scan();
create trigger trg_audit after insert on public.doc_scan_requests
  for each row execute function public.edr_audit_doc_scan();

-- ---------------------------------------------------------------------
-- 콘솔 함수 — 모두 소유자·관리자만. 결과 조회·내보내기는 감사 기록에 남긴다(같은 사람의 조회는 10분에 한 번만)
-- ---------------------------------------------------------------------
create or replace function public.edr_require_admin(p_tenant uuid)
returns void language plpgsql stable security definer set search_path = public as $$
begin
  if p_tenant is null or not public.has_tenant_role(p_tenant, array['owner', 'admin']) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
end $$;
revoke all on function public.edr_require_admin(uuid) from public, anon;
grant execute on function public.edr_require_admin(uuid) to authenticated;

create or replace function public.console_doc_overview(p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare res jsonb;
begin
  perform edr_require_admin(p_tenant);
  select jsonb_build_object(
    'devices', (select count(*) from devices where tenant_id = p_tenant and status = 'active'),
    'devices_scanned', (select count(distinct device_id) from doc_scans where tenant_id = p_tenant and status = 'done'),
    'last_scan_at', (select max(finished_at) from doc_scans where tenant_id = p_tenant and status = 'done'),
    'running', (select count(*) from doc_scans where tenant_id = p_tenant and status = 'running' and updated_at > now() - interval '1 day'),
    'pending_requests', (select count(*) from doc_scan_requests where tenant_id = p_tenant and completed_at is null and requested_at > now() - interval '7 days'),
    'pii_files', (select count(*) from doc_findings where tenant_id = p_tenant and pii_total > 0),
    'pii_devices', (select count(distinct device_id) from doc_findings where tenant_id = p_tenant and pii_total > 0),
    'pii_by_kind', (select coalesce(jsonb_object_agg(k, n), '{}'::jsonb) from (
        select k, sum((v::text)::int) as n from doc_findings, jsonb_each(pii) as e(k, v)
        where tenant_id = p_tenant group by k) x),
    'keyword_files', (select count(*) from doc_findings where tenant_id = p_tenant and keyword_total > 0),
    'keywords_by_word', (select coalesce(jsonb_object_agg(k, n), '{}'::jsonb) from (
        select k, count(*) as n from doc_findings, jsonb_each(keywords) as e(k, v)
        where tenant_id = p_tenant group by k) x),
    'stale_files', (select count(*) from doc_findings where tenant_id = p_tenant and stale),
    'stale_bytes', (select coalesce(sum(size), 0) from doc_findings where tenant_id = p_tenant and stale)
  ) into res;
  return res;
end $$;

-- 결과 목록. p_kind: pii | keyword | stale. p_purpose: view(한 번에 500행) | export(5만 행) — 감사 기록 이름이 다르다
create or replace function public.console_doc_findings(p_tenant uuid, p_kind text, p_q text default null, p_device uuid default null,
                                                       p_keyword text default null, p_limit int default 50, p_offset int default 0,
                                                       p_purpose text default 'view')
returns table (device_id uuid, hostname text, path text, ext text, size bigint, modified_at timestamptz, pii jsonb, pii_total int,
               keywords jsonb, keyword_total int, stale boolean, unreadable text, last_seen_at timestamptz, total bigint)
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := (select auth.uid());
begin
  perform edr_require_admin(p_tenant);
  if p_kind not in ('pii', 'keyword', 'stale') then
    raise exception 'bad kind';
  end if;
  if p_purpose = 'export' or not exists (
       select 1 from audit_log a where a.tenant_id = p_tenant and a.actor_id = uid and a.action = 'doc_scan.view'
          and a.created_at > now() - interval '10 minutes') then
    insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
    values (p_tenant, uid, (select email from auth.users where id = uid),
            case when p_purpose = 'export' then 'doc_scan.export' else 'doc_scan.view' end, 'doc_scan', p_kind,
            case p_kind when 'pii' then '개인정보 문서' when 'keyword' then '키워드 문서' else '오래된 문서' end,
            jsonb_strip_nulls(jsonb_build_object('device_id', p_device, 'q', nullif(p_q, ''), 'keyword', nullif(p_keyword, ''))));
  end if;
  return query
    select f.device_id, d.hostname, f.path, f.ext, f.size, f.modified_at, f.pii, f.pii_total, f.keywords, f.keyword_total,
           f.stale, f.unreadable, f.last_seen_at, count(*) over ()
    from doc_findings f join devices d on d.id = f.device_id
    where f.tenant_id = p_tenant
      and (p_kind <> 'pii' or f.pii_total > 0)
      and (p_kind <> 'keyword' or f.keyword_total > 0)
      and (p_kind <> 'stale' or f.stale)
      and (p_device is null or f.device_id = p_device)
      and (coalesce(p_keyword, '') = '' or f.keywords ? p_keyword)
      and (coalesce(p_q, '') = '' or f.path ilike edr_like(p_q) or d.hostname ilike edr_like(p_q))
    order by case p_kind when 'pii' then f.pii_total when 'keyword' then f.keyword_total else 0 end desc,
             case when p_kind = 'stale' then f.modified_at end asc nulls last, d.hostname, f.path
    limit least(greatest(p_limit, 1), case when p_purpose = 'export' then 50000 else 500 end) offset greatest(p_offset, 0);
end $$;

-- 장치별 검사 현황
create or replace function public.console_doc_devices(p_tenant uuid)
returns table (device_id uuid, hostname text, last_seen_at timestamptz, last_scan_at timestamptz, last_status text, files_scanned int,
               files_skipped int, pii_files bigint, keyword_files bigint, stale_files bigint, pending_request_at timestamptz,
               request_picked boolean)
language plpgsql stable security definer set search_path = public as $$
begin
  perform edr_require_admin(p_tenant);
  return query
    select d.id, d.hostname, d.last_seen_at, s.finished_at, s.status, s.files_scanned, s.files_skipped,
           (select count(*) from doc_findings f where f.device_id = d.id and f.pii_total > 0),
           (select count(*) from doc_findings f where f.device_id = d.id and f.keyword_total > 0),
           (select count(*) from doc_findings f where f.device_id = d.id and f.stale),
           r.requested_at, r.picked_at is not null
    from devices d
    left join lateral (select * from doc_scans x where x.device_id = d.id order by x.started_at desc limit 1) s on true
    left join lateral (select * from doc_scan_requests q where q.device_id = d.id and q.completed_at is null
                        and q.requested_at > now() - interval '7 days' order by q.id desc limit 1) r on true
    where d.tenant_id = p_tenant and d.status = 'active'
    order by (select count(*) from doc_findings f where f.device_id = d.id and f.pii_total > 0) desc, d.hostname;
end $$;

revoke all on function public.console_doc_overview(uuid), public.console_doc_devices(uuid),
  public.console_doc_findings(uuid, text, text, uuid, text, int, int, text) from public, anon;
grant execute on function public.console_doc_overview(uuid), public.console_doc_devices(uuid),
  public.console_doc_findings(uuid, text, text, uuid, text, int, int, text) to authenticated;

-- ---------------------------------------------------------------------
-- 유지보수: 검사 기록·요청은 1년 보관 (동작은 0008 과 같고 두 줄 추가)
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
  delete from software_changes where observed_at < now() - interval '365 days';
  delete from doc_scans where started_at < now() - interval '365 days';
  delete from doc_scan_requests where requested_at < now() - interval '365 days';
  insert into detection_state (name, last_run) values ('maintenance', now())
  on conflict (name) do update set last_run = excluded.last_run;
end $$;
revoke all on function public.edr_maintenance(int, int) from public, anon, authenticated;
grant execute on function public.edr_maintenance(int, int) to edr_enricher;
