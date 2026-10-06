-- =====================================================================
-- RLS(Row Level Security)
--
-- 역할 정리
--   authenticated : 대시보드(Next.js) 로그인 사용자. 자기 테넌트 행만 "읽기". 경보 상태만 수정 가능.
--   anon          : 아무 것도 못 봄.
--   edr_ingest    : services/ingest 전용 DB 역할. 텔레메트리 INSERT 만.
--   edr_enricher  : services/enricher 전용. file_hashes 갱신 + alerts 생성.
--   grafana_reader: Grafana 데이터소스 전용 읽기 역할(내부 SOC/운영용).
--   service_role  : Supabase 관리 키(서버 전용). RLS 우회 — 프론트엔드에 절대 노출 금지.
--
-- 텔레메트리는 위·변조 방지를 위해 authenticated 에게 INSERT/UPDATE/DELETE 권한 자체를 주지 않는다.
-- =====================================================================

-- ---------- 전용 DB 역할 (비밀번호는 마이그레이션에 넣지 않는다: 배포 후 ALTER ROLE ... PASSWORD) ----------
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'edr_ingest')     then create role edr_ingest     nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'edr_enricher')   then create role edr_enricher   nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'grafana_reader') then create role grafana_reader nologin; end if;
end $$;

-- ---------- 권한 헬퍼 ----------
-- security definer + search_path 고정: tenant_members 의 RLS 를 재귀 평가하지 않고 빠르게 판정
create or replace function public.my_tenant_ids()
returns setof uuid
language sql stable security definer set search_path = ''
as $$
  select tenant_id from public.tenant_members where user_id = (select auth.uid())
$$;

create or replace function public.has_tenant_role(p_tenant uuid, p_roles text[])
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.tenant_members
    where tenant_id = p_tenant and user_id = (select auth.uid()) and role = any (p_roles)
  )
$$;

revoke all on function public.my_tenant_ids() from public, anon;
revoke all on function public.has_tenant_role(uuid, text[]) from public, anon;
grant execute on function public.my_tenant_ids() to authenticated;
grant execute on function public.has_tenant_role(uuid, text[]) to authenticated;

-- ---------- 기본 권한 정리 ----------
revoke all on all tables in schema public from anon;
revoke insert, update, delete on all tables in schema public from authenticated;
grant select on all tables in schema public to authenticated;

-- ---------- RLS 활성화 ----------
alter table public.tenants             enable row level security;
alter table public.tenant_members      enable row level security;
alter table public.enrollment_keys     enable row level security;
alter table public.devices             enable row level security;
alter table public.file_hashes         enable row level security;
alter table public.tenant_file_hashes  enable row level security;
alter table public.process_events      enable row level security;
alter table public.net_connections     enable row level security;
alter table public.security_events     enable row level security;
alter table public.autoruns            enable row level security;
alter table public.autorun_changes     enable row level security;
alter table public.alerts              enable row level security;

-- ---------- 대시보드 사용자(authenticated) ----------
-- (select ...) 로 감싸면 행마다가 아니라 쿼리당 1회만 평가된다(Supabase 권장 패턴).
create policy tenants_select on public.tenants
  for select to authenticated using (id in (select public.my_tenant_ids()));

create policy members_select on public.tenant_members
  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy members_manage on public.tenant_members
  for all to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner','admin'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner','admin'])));
grant insert, update, delete on public.tenant_members to authenticated;

create policy enroll_select on public.enrollment_keys
  for select to authenticated using ((select public.has_tenant_role(tenant_id, array['owner','admin'])));
create policy enroll_revoke on public.enrollment_keys
  for update to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner','admin'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner','admin'])));
grant update (revoked, label) on public.enrollment_keys to authenticated;

create policy devices_select on public.devices
  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy devices_update on public.devices
  for update to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner','admin'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner','admin'])));
grant update (tags, status) on public.devices to authenticated;   -- 토큰 해시 등은 수정 불가

-- 해시 평판: 자기 조직에서 본 적 있는 해시만 보인다(조직을 나눴을 때 서로의 사용 프로그램 노출 방지).
create policy hashes_select on public.file_hashes
  for select to authenticated using (
    exists (select 1 from public.tenant_file_hashes t
            where t.sha256 = file_hashes.sha256 and t.tenant_id in (select public.my_tenant_ids()))
  );
create policy tenant_hashes_select on public.tenant_file_hashes
  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));

create policy proc_select on public.process_events
  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy net_select on public.net_connections
  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy sec_select on public.security_events
  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy autoruns_select on public.autoruns
  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy autorun_changes_select on public.autorun_changes
  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));

create policy alerts_select on public.alerts
  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy alerts_triage on public.alerts
  for update to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner','admin','analyst'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner','admin','analyst'])));
grant update (status, assigned_to, updated_at) on public.alerts to authenticated;  -- 내용 변조 불가

-- ---------- 등록키 발급 RPC (평문은 이 응답에서 단 한 번만 반환) ----------
create or replace function public.create_enrollment_key(p_tenant uuid, p_label text default null,
                                                       p_max_uses int default 1000, p_days int default 30)
returns text
language plpgsql security definer set search_path = ''
as $$
declare
  plain text := 'edr_enr_' || encode(extensions.gen_random_bytes(24), 'hex');
begin
  if not public.has_tenant_role(p_tenant, array['owner','admin']) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  insert into public.enrollment_keys (tenant_id, key_hash, label, max_uses, expires_at, created_by)
  values (p_tenant, extensions.digest(plain, 'sha256'), p_label, p_max_uses,
          now() + make_interval(days => p_days), auth.uid());
  return plain;
end $$;
revoke all on function public.create_enrollment_key(uuid, text, int, int) from public, anon;
grant execute on function public.create_enrollment_key(uuid, text, int, int) to authenticated;

-- ---------- Ingest 서비스 ----------
grant usage on schema public to edr_ingest, edr_enricher, grafana_reader;
grant select, update on public.enrollment_keys to edr_ingest;
grant select, insert, update on public.devices to edr_ingest;
grant insert on public.process_events, public.net_connections, public.security_events,
               public.autorun_changes to edr_ingest;
grant select, insert, update on public.autoruns, public.tenant_file_hashes to edr_ingest;
grant select, insert on public.file_hashes to edr_ingest;

create policy ingest_all on public.enrollment_keys    for all to edr_ingest using (true) with check (true);
create policy ingest_all on public.devices            for all to edr_ingest using (true) with check (true);
create policy ingest_all on public.process_events     for insert to edr_ingest with check (true);
create policy ingest_all on public.net_connections    for insert to edr_ingest with check (true);
create policy ingest_all on public.security_events    for insert to edr_ingest with check (true);
create policy ingest_all on public.autorun_changes    for insert to edr_ingest with check (true);
create policy ingest_all on public.autoruns           for all to edr_ingest using (true) with check (true);
create policy ingest_all on public.tenant_file_hashes for all to edr_ingest using (true) with check (true);
create policy ingest_all on public.file_hashes        for all to edr_ingest using (true) with check (true);

-- ---------- Enricher 서비스 ----------
grant select, update on public.file_hashes to edr_enricher;
grant select on public.tenant_file_hashes, public.process_events, public.devices to edr_enricher;
grant select, insert on public.alerts to edr_enricher;
create policy enricher_all on public.file_hashes        for all    to edr_enricher using (true) with check (true);
create policy enricher_read on public.tenant_file_hashes for select to edr_enricher using (true);
create policy enricher_read on public.process_events     for select to edr_enricher using (true);
create policy enricher_read on public.devices            for select to edr_enricher using (true);
create policy enricher_alerts on public.alerts           for all    to edr_enricher using (true) with check (true);

-- ---------- Grafana (내부 운영용 읽기 전용) ----------
-- 사내 보안 담당자용: 전 조직 읽기. 계열사별로 Grafana 를 나눠야 하면 아래 using 조건을
-- tenant_id = '<조직 uuid>' 로 바꾼 읽기 역할을 조직마다 따로 만든다.
grant select on public.tenants, public.devices, public.file_hashes, public.process_events,
                public.net_connections, public.security_events, public.autoruns,
                public.autorun_changes, public.alerts to grafana_reader;
create policy grafana_read on public.tenants         for select to grafana_reader using (true);
create policy grafana_read on public.devices         for select to grafana_reader using (true);
create policy grafana_read on public.file_hashes     for select to grafana_reader using (true);
create policy grafana_read on public.process_events  for select to grafana_reader using (true);
create policy grafana_read on public.net_connections for select to grafana_reader using (true);
create policy grafana_read on public.security_events for select to grafana_reader using (true);
create policy grafana_read on public.autoruns        for select to grafana_reader using (true);
create policy grafana_read on public.autorun_changes for select to grafana_reader using (true);
create policy grafana_read on public.alerts          for select to grafana_reader using (true);

-- 새로 생기는 월 파티션은 부모 테이블 권한·정책을 통해서만 접근된다(파티션 직접 접근은 RLS 로 차단).

-- ---------- 실시간 경보(Next.js 대시보드가 Supabase Realtime 으로 구독) ----------
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table public.alerts;
  end if;
end $$;
