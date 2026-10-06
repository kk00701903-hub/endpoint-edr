-- =====================================================================
-- 0010 : PC 조치 목록 — PC 마다 "보안·문서에서 고쳐야 할 것"을 한 화면에 모으고, 담당자·처리 상태를 관리한다
--
--   조치 항목은 지금 데이터에서 계산한다(따로 쌓지 않음). 고쳐지면 다음 수집·검사에서 저절로 목록에서 빠진다.
--     posture    보안 점검 실패(조직에서 점수에 넣은 항목만) — 지원 종료 Windows 포함
--     software   취약 버전(업데이트 필요)·금지 프로그램(삭제 필요) — 켜 둔 소프트웨어 정책
--     doc_pii    개인정보 문서 정리(문서 감사) — 소유자·관리자만 보고 바꾼다
--     doc_stale  오래된 문서 정리(문서 감사) — 소유자·관리자만
--   처리 기록(remediation_tracking): 담당자·상태(대기·진행 중·완료 표시·예외)·메모·기한.
--     쓰기는 console_remediation_update 함수로만(권한 확인 + 감사 기록). 여러 건을 한꺼번에 바꾸면 감사 기록은 대표 한 줄.
--   항목이 사라졌는데 처리 기록이 있으면 "해결 확인됨"으로 보여 준다(90일).
-- =====================================================================

create table public.remediation_tracking (
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  device_id   uuid not null references public.devices(id) on delete cascade,
  kind        text not null check (kind in ('posture', 'software', 'doc_pii', 'doc_stale')),
  item_key    text not null check (length(item_key) between 1 and 64),   -- 점검 ID | 정책 ID | pii | stale
  title       text not null default '' check (length(title) <= 300),     -- 처리할 때의 항목 이름(해결된 뒤에도 보이게)
  status      text not null default 'open' check (status in ('open', 'in_progress', 'done', 'exception')),
  assignee    uuid references auth.users(id) on delete set null,
  note        text not null default '' check (length(note) <= 1000),
  due_date    date,
  updated_by  uuid references auth.users(id),
  updated_at  timestamptz not null default now(),
  created_at  timestamptz not null default now(),
  primary key (device_id, kind, item_key)
);
create index on public.remediation_tracking (tenant_id, status);
create index on public.remediation_tracking (assignee) where assignee is not null;

alter table public.remediation_tracking enable row level security;
grant select on public.remediation_tracking to authenticated;
-- 보기: 구성원. 문서 감사 항목은 소유자·관리자만. 쓰기는 아래 함수(security definer)로만
create policy rt_select on public.remediation_tracking for select to authenticated
  using (tenant_id in (select public.my_tenant_ids())
         and (kind not in ('doc_pii', 'doc_stale') or (select public.has_tenant_role(tenant_id, array['owner', 'admin']))));

-- ---------------------------------------------------------------------
-- 지금의 조치 항목 계산
-- ---------------------------------------------------------------------
create or replace function public.edr_remediation_items(p_tenant uuid, p_with_docs boolean)
returns table (device_id uuid, kind text, item_key text, title text, detail text, severity text, since timestamptz, guidance text)
language sql stable set search_path = public as $$
  -- 보안 점검 실패(점수에 넣은 항목만)
  select dp.device_id, 'posture', dp.check_id, c.title, dp.detail,
         case when c.weight >= 20 then 'high' when c.weight >= 10 then 'medium' else 'low' end,
         coalesce(dp.failing_since, dp.changed_at), c.remediation
  from device_posture dp
  join devices d on d.id = dp.device_id and d.status = 'active'
  join posture_checks c on c.check_id = dp.check_id
  left join posture_policies pp on pp.tenant_id = dp.tenant_id and pp.check_id = dp.check_id
  where dp.tenant_id = p_tenant and dp.status = 'fail' and coalesce(pp.enabled, c.default_enabled)
  union all
  -- 소프트웨어 정책(이름·버전 묶음으로 한 번만 비교한 뒤 장치로 펼친다)
  select h.device_id, 'software', h.pid::text,
         case when h.kind = 'prohibited' then '금지 프로그램 삭제: ' else '업데이트 필요: ' end || min(h.name),
         string_agg(distinct h.name || coalesce(nullif(' ' || h.version, ' '), ''), ', '),
         max(h.severity), min(h.first_seen_at),
         case when h.kind = 'prohibited' then coalesce(nullif(max(h.reason), ''), '회사에서 허용하지 않은 프로그램입니다') || ' — 프로그램 제거 후 다음 자산 수집(최대 6시간)에서 목록에서 빠집니다.'
              else coalesce(max(h.fixed_version) || ' 이상으로 업데이트하세요.', '지원이 끝난 제품입니다. 대체 프로그램으로 바꾸세요.')
                   || coalesce(' 참고: ' || nullif(max(h.reference), ''), '') end
  from (
    with titles as (
      select s.name, s.version, s.publisher from device_software s where s.tenant_id = p_tenant group by 1, 2, 3
    ), pt as (
      select p.id as pid, p.kind, p.severity, p.reason, p.fixed_version, p.reference, t.name, t.version, t.publisher
      from software_policies p join titles t on edr_sw_matches(t.name, t.version, t.publisher, p)
      where p.tenant_id = p_tenant
    )
    select pt.*, s.device_id, s.first_seen_at
    from pt join device_software s on s.tenant_id = p_tenant and s.name = pt.name and s.version = pt.version
                                   and s.publisher is not distinct from pt.publisher
    join devices d on d.id = s.device_id and d.status = 'active'
  ) h
  group by h.device_id, h.pid, h.kind
  union all
  -- 문서 감사(관리자만)
  select f.device_id, 'doc_pii', 'pii', '개인정보 문서 정리 ' || count(*) || '개',
         '개인정보 ' || sum(f.pii_total) || '건', 'high', min(f.first_seen_at),
         '사용자에게 알려 필요 없는 문서는 지우고, 필요한 문서는 암호를 걸거나 지정 저장소로 옮기게 합니다. 다음 문서 검사에서 다시 보이지 않으면 목록에서 빠집니다.'
  from doc_findings f join devices d on d.id = f.device_id and d.status = 'active'
  where p_with_docs and f.tenant_id = p_tenant and f.pii_total > 0
  group by f.device_id
  union all
  select f.device_id, 'doc_stale', 'stale', '오래된 문서 정리 ' || count(*) || '개',
         pg_size_pretty(coalesce(sum(f.size), 0)), 'low', min(f.first_seen_at),
         '보관 기간이 지난 문서는 지우거나 보관 저장소로 옮기게 합니다. 업무에 계속 쓰는 문서면 예외로 둡니다.'
  from doc_findings f join devices d on d.id = f.device_id and d.status = 'active'
  where p_with_docs and f.tenant_id = p_tenant and f.stale and f.pii_total = 0
  group by f.device_id
$$;
revoke all on function public.edr_remediation_items(uuid, boolean) from public, anon, authenticated;

-- ---------------------------------------------------------------------
-- 콘솔: 목록·요약
--   p_status: active(기본: 대기·진행 중·완료 표시) | open | in_progress | done | exception | resolved(해결 확인됨) | all
-- ---------------------------------------------------------------------
create or replace function public.console_remediation(p_tenant uuid, p_kind text default null, p_status text default 'active',
                                                      p_device uuid default null, p_assignee uuid default null, p_q text default null,
                                                      p_limit int default 50, p_offset int default 0)
returns table (device_id uuid, hostname text, last_seen_at timestamptz, kind text, item_key text, title text, detail text,
               severity text, since timestamptz, guidance text, present boolean, status text, assignee uuid, note text,
               due_date date, updated_at timestamptz, updated_by uuid, total bigint)
language plpgsql stable security definer set search_path = public as $$
declare
  docs boolean := public.has_tenant_role(p_tenant, array['owner', 'admin']);
begin
  if p_tenant is null or p_tenant not in (select public.my_tenant_ids()) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query
    with cur as (select * from edr_remediation_items(p_tenant, docs)),
    rows as (
      select c.device_id, c.kind, c.item_key, c.title, c.detail, c.severity, c.since, c.guidance, true as present,
             coalesce(t.status, 'open') as status, t.assignee, coalesce(t.note, '') as note, t.due_date, t.updated_at, t.updated_by
      from cur c
      left join remediation_tracking t on t.device_id = c.device_id and t.kind = c.kind and t.item_key = c.item_key
      union all
      -- 처리 기록은 있는데 지금 항목이 없음 = 해결 확인됨(90일)
      select t.device_id, t.kind, t.item_key, t.title, null, null, null, null, false,
             t.status, t.assignee, t.note, t.due_date, t.updated_at, t.updated_by
      from remediation_tracking t
      where t.tenant_id = p_tenant and t.updated_at > now() - interval '90 days'
        and (docs or t.kind not in ('doc_pii', 'doc_stale'))
        and not exists (select 1 from cur c where c.device_id = t.device_id and c.kind = t.kind and c.item_key = t.item_key)
    )
    select r.device_id, d.hostname, d.last_seen_at, r.kind, r.item_key, r.title, r.detail, r.severity, r.since, r.guidance, r.present,
           r.status, r.assignee, r.note, r.due_date, r.updated_at, r.updated_by, count(*) over ()
    from rows r join devices d on d.id = r.device_id and d.tenant_id = p_tenant
    where (p_kind is null or p_kind = '' or r.kind = p_kind or (p_kind = 'docs' and r.kind in ('doc_pii', 'doc_stale')))
      and case coalesce(p_status, 'active')
            when 'all' then true
            when 'resolved' then not r.present
            when 'active' then r.present and r.status <> 'exception'
            else r.present and r.status = p_status end
      and (p_device is null or r.device_id = p_device)
      and (p_assignee is null or r.assignee = p_assignee)
      and (coalesce(p_q, '') = '' or d.hostname ilike edr_like(p_q) or r.title ilike edr_like(p_q))
    order by r.present desc, edr_sev_rank(r.severity) desc nulls last, (r.status = 'done') asc, r.since asc nulls last, d.hostname, r.kind, r.item_key
    limit least(greatest(p_limit, 1), 2000) offset greatest(p_offset, 0);
end $$;

create or replace function public.console_remediation_overview(p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path = public as $$
declare
  docs boolean := public.has_tenant_role(p_tenant, array['owner', 'admin']);
  res jsonb;
begin
  if p_tenant is null or p_tenant not in (select public.my_tenant_ids()) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  with cur as (select * from edr_remediation_items(p_tenant, docs)),
  r as (
    select c.*, coalesce(t.status, 'open') as status, t.assignee, t.due_date
    from cur c left join remediation_tracking t on t.device_id = c.device_id and t.kind = c.kind and t.item_key = c.item_key
  ), act as (select * from r where status <> 'exception')
  select jsonb_build_object(
    'items', (select count(*) from act),
    'devices', (select count(distinct device_id) from act),
    'by_kind', (select coalesce(jsonb_object_agg(kind, n), '{}'::jsonb) from (select kind, count(*) n from act group by kind) x),
    'by_status', (select coalesce(jsonb_object_agg(status, n), '{}'::jsonb) from (select status, count(*) n from r group by status) x),
    'high', (select count(*) from act where severity in ('high', 'critical')),
    'unassigned', (select count(*) from act where assignee is null and status <> 'done'),
    'overdue', (select count(*) from act where due_date < current_date and status <> 'done'),
    'resolved_30d', (select count(*) from remediation_tracking t where t.tenant_id = p_tenant and t.updated_at > now() - interval '30 days'
                       and (docs or t.kind not in ('doc_pii', 'doc_stale'))
                       and not exists (select 1 from cur c where c.device_id = t.device_id and c.kind = t.kind and c.item_key = t.item_key)),
    'docs', docs
  ) into res;
  return res;
end $$;

-- ---------------------------------------------------------------------
-- 처리(담당자·상태·메모·기한). 보안 점검·소프트웨어는 분석가 이상, 문서 감사 항목은 소유자·관리자.
--   p_items: [{"device_id": "...", "kind": "posture", "item_key": "firewall", "title": "Windows 방화벽"}, ...] (최대 500)
--   null 인 값은 바꾸지 않는다. 담당자를 비우려면 p_clear_assignee = true
-- ---------------------------------------------------------------------
create or replace function public.console_remediation_update(p_tenant uuid, p_items jsonb, p_status text default null,
                                                             p_assignee uuid default null, p_clear_assignee boolean default false,
                                                             p_note text default null, p_due_date date default null,
                                                             p_clear_due boolean default false)
returns int language plpgsql security definer set search_path = public as $$
declare
  uid uuid := (select auth.uid());
  n   int;
  bad int;
begin
  if uid is null or not public.has_tenant_role(p_tenant, array['owner', 'admin', 'analyst']) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) = 0 or jsonb_array_length(p_items) > 500 then
    raise exception 'bad items';
  end if;
  if p_status is not null and p_status not in ('open', 'in_progress', 'done', 'exception') then
    raise exception 'bad status';
  end if;
  if p_assignee is not null and not exists (select 1 from tenant_members m where m.tenant_id = p_tenant and m.user_id = p_assignee) then
    raise exception '담당자는 이 조직의 구성원이어야 합니다';
  end if;
  if p_note is not null and length(p_note) > 1000 then
    raise exception '메모는 1000자까지입니다';
  end if;
  -- 장치가 이 조직 것인지, 문서 감사 항목이면 관리자인지
  select count(*) into bad
  from jsonb_array_elements(p_items) x
  where not exists (select 1 from devices d where d.id = (x->>'device_id')::uuid and d.tenant_id = p_tenant)
     or coalesce(x->>'kind', '') not in ('posture', 'software', 'doc_pii', 'doc_stale')
     or coalesce(x->>'item_key', '') = ''
     or (x->>'kind' in ('doc_pii', 'doc_stale') and not public.has_tenant_role(p_tenant, array['owner', 'admin']));
  if bad > 0 then
    raise exception '처리할 수 없는 항목이 있습니다(다른 조직 장치이거나, 문서 감사 항목은 소유자·관리자만)' using errcode = '42501';
  end if;

  -- 여러 건이면 행마다 감사 기록을 남기지 않고 대표 한 줄
  if jsonb_array_length(p_items) > 1 then
    perform set_config('edr.audit_cascade', 'on', true);
  end if;
  insert into remediation_tracking as t (tenant_id, device_id, kind, item_key, title, status, assignee, note, due_date, updated_by)
  select p_tenant, (x->>'device_id')::uuid, x->>'kind', left(x->>'item_key', 64), left(coalesce(x->>'title', ''), 300),
         coalesce(p_status, 'open'), case when p_clear_assignee then null else p_assignee end, coalesce(p_note, ''),
         case when p_clear_due then null else p_due_date end, uid
  from (select distinct on (x->>'device_id', x->>'kind', x->>'item_key') x from jsonb_array_elements(p_items) x) s
  on conflict (device_id, kind, item_key) do update set
    title      = case when excluded.title <> '' then excluded.title else t.title end,
    status     = coalesce(p_status, t.status),
    assignee   = case when p_clear_assignee then null else coalesce(p_assignee, t.assignee) end,
    note       = coalesce(p_note, t.note),
    due_date   = case when p_clear_due then null else coalesce(p_due_date, t.due_date) end,
    updated_by = uid, updated_at = now();
  get diagnostics n = row_count;

  if jsonb_array_length(p_items) > 1 then
    perform set_config('edr.audit_cascade', 'off', true);
    insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
    values (p_tenant, uid, (select email from auth.users where id = uid), 'remediation.bulk', 'remediation', null, '조치 항목 ' || n || '건',
            jsonb_strip_nulls(jsonb_build_object('count', n, 'status', p_status, 'assignee', p_assignee,
              'assignee_cleared', case when p_clear_assignee then true end, 'due_date', p_due_date, 'note', p_note)));
  end if;
  return n;
end $$;

-- 한 건씩 바꿀 때의 감사 기록
create or replace function public.edr_audit_remediation()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  uid  uuid := (select auth.uid());
  o    jsonb := case when tg_op = 'UPDATE' then to_jsonb(old) else '{}'::jsonb end;
  diff jsonb;
begin
  if uid is null or current_setting('edr.audit_cascade', true) = 'on' then
    return null;
  end if;
  diff := edr_audit_diff(o, to_jsonb(new), array['status', 'assignee', 'note', 'due_date']);
  if tg_op = 'INSERT' then  -- 처음 기록은 기본값(대기·빈 메모)과 다른 것만
    diff := (select coalesce(jsonb_object_agg(k, v), '{}'::jsonb) from jsonb_each(diff) e(k, v)
             where not (k = 'status' and v->>1 = 'open') and not (k = 'note' and v->>1 = ''));
  end if;
  if diff = '{}'::jsonb then
    return null;
  end if;
  insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
  values (new.tenant_id, uid, (select email from auth.users where id = uid),
          case when diff ? 'status' then 'remediation.status' when diff ? 'assignee' then 'remediation.assign' else 'remediation.update' end,
          'remediation', new.device_id::text, (select hostname from devices where id = new.device_id) || ' · ' || new.title, diff);
  return null;
end $$;
revoke all on function public.edr_audit_remediation() from public, anon, authenticated;
create trigger trg_audit after insert or update on public.remediation_tracking
  for each row execute function public.edr_audit_remediation();

revoke all on function public.console_remediation(uuid, text, text, uuid, uuid, text, int, int),
  public.console_remediation_overview(uuid),
  public.console_remediation_update(uuid, jsonb, text, uuid, boolean, text, date, boolean) from public, anon;
grant execute on function public.console_remediation(uuid, text, text, uuid, uuid, text, int, int),
  public.console_remediation_overview(uuid),
  public.console_remediation_update(uuid, jsonb, text, uuid, boolean, text, date, boolean) to authenticated;
