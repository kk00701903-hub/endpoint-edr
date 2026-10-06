-- =====================================================================
-- 0007 : 회사 계정(AD) SSO — AD 그룹으로 콘솔 역할을 자동으로 정한다
--   흐름: AD ─LDAP→ Keycloak ─OIDC→ Supabase Auth(keycloak 공급자) → auth.users
--   Supabase Auth 는 Keycloak 로 로그인할 때마다 받은 정보(custom_claims.groups 포함)를 auth.users.raw_user_meta_data 에
--   다시 쓴다(Supabase Auth v2.176 이상). 이 트리거가 그 그룹을 sso_group_roles 대응표로 바꿔 tenant_members 를 맞춘다.
--   (auth.users 트리거는 Supabase 가 공식으로 허용하는 확장 지점이다)
--   * 대응되는 그룹이 있으면 → 가장 높은 역할로 가입·변경 (managed_by = 'sso')
--   * 대응되는 그룹이 없으면 → SSO 로 들어온 구성원은 제거(수동으로 넣은 구성원은 건드리지 않음)
--   * 바뀐 내용은 audit_log 에 'AD 그룹 동기화' 로 남긴다
-- =====================================================================

alter table public.tenant_members
  add column if not exists managed_by text not null default 'manual'
  check (managed_by in ('manual', 'sso'));

create table public.sso_group_roles (
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  provider    text not null default 'keycloak',        -- Supabase Auth 공급자 이름
  idp_group   text not null,                            -- AD 그룹 이름(Keycloak 의 groups 클레임 값), 예: EDR-Admins
  role        text not null check (role in ('admin', 'analyst', 'viewer')),  -- 소유자(owner)는 SSO 로 주지 않는다
  created_at  timestamptz not null default now(),
  primary key (tenant_id, provider, idp_group)
);
alter table public.sso_group_roles enable row level security;
create policy sso_map_read on public.sso_group_roles for select to authenticated
  using (tenant_id in (select public.my_tenant_ids()));
create policy sso_map_manage on public.sso_group_roles for all to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])));
grant select, insert, update, delete on public.sso_group_roles to authenticated;

create or replace function public.edr_role_rank(r text)
returns int language sql immutable as $$
  select case r when 'owner' then 0 when 'admin' then 1 when 'analyst' then 2 when 'viewer' then 3 else 9 end
$$;

-- 로그인할 때마다(=raw_user_meta_data 가 새로 쓰일 때마다) 실행
create or replace function public.edr_sync_sso_membership()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  groups   text[];
  t        uuid;
  p        text;
  best     text;
  cur      record;
  email    text := new.email;
begin
  -- 이 사용자가 쓴 로그인 공급자 중 대응표가 있는 것(예: keycloak)만 처리. 이메일·비밀번호 계정은 그대로.
  select s.provider into p from sso_group_roles s
   where coalesce(new.raw_app_meta_data -> 'providers', '[]'::jsonb) ? s.provider
      or new.raw_app_meta_data ->> 'provider' = s.provider
   limit 1;
  if p is null then
    return null;
  end if;

  -- Keycloak 은 그룹을 "/EDR-Admins" 처럼 경로로 줄 수도 있다 → 앞 '/' 제거, 대소문자 무시
  select coalesce(array_agg(lower(trim(leading '/' from g))), '{}')
    into groups
    from jsonb_array_elements_text(
           case jsonb_typeof(new.raw_user_meta_data -> 'custom_claims' -> 'groups')
             when 'array' then new.raw_user_meta_data -> 'custom_claims' -> 'groups'
             else '[]'::jsonb end) as g;

  for t in select distinct tenant_id from sso_group_roles where provider = p loop
    select s.role into best
      from sso_group_roles s
     where s.tenant_id = t and s.provider = p and lower(s.idp_group) = any (groups)
     order by edr_role_rank(s.role)
     limit 1;
    select m.role, m.managed_by into cur from tenant_members m where m.tenant_id = t and m.user_id = new.id;

    if best is not null then
      if cur.role is null then
        insert into tenant_members (tenant_id, user_id, role, managed_by) values (t, new.id, best, 'sso');
        insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
        values (t, null, 'AD 그룹 동기화', 'member.sso_add', 'member', new.id::text, email,
                jsonb_build_object('role', best, 'groups', to_jsonb(groups)));
      elsif cur.managed_by = 'sso' and cur.role <> best then
        update tenant_members set role = best where tenant_id = t and user_id = new.id;
        insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
        values (t, null, 'AD 그룹 동기화', 'member.sso_role', 'member', new.id::text, email,
                jsonb_build_object('role', jsonb_build_array(cur.role, best), 'groups', to_jsonb(groups)));
      end if;
      -- 수동 구성원(managed_by = 'manual')은 관리자가 직접 정한 역할을 유지
    elsif cur.managed_by = 'sso' then
      delete from tenant_members where tenant_id = t and user_id = new.id;
      insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
      values (t, null, 'AD 그룹 동기화', 'member.sso_remove', 'member', new.id::text, email,
              jsonb_build_object('role', jsonb_build_array(cur.role, null), 'groups', to_jsonb(groups)));
    end if;
  end loop;
  return null;
end $$;
revoke all on function public.edr_sync_sso_membership() from public, anon, authenticated;

drop trigger if exists trg_edr_sso_membership on auth.users;
create trigger trg_edr_sso_membership
  after insert or update of raw_user_meta_data, raw_app_meta_data on auth.users
  for each row execute function public.edr_sync_sso_membership();

-- 대응표 변경도 감사 기록에
create or replace function public.edr_audit_sso_map()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  uid uuid := (select auth.uid());
  r   public.sso_group_roles := coalesce(new, old);
begin
  if uid is null then return null; end if;
  insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
  values (r.tenant_id, uid, (select email from auth.users where id = uid),
          case tg_op when 'INSERT' then 'sso_map.create' when 'DELETE' then 'sso_map.delete' else 'sso_map.update' end,
          'sso_map', r.idp_group, r.provider || ' · ' || r.idp_group,
          case tg_op when 'UPDATE' then jsonb_build_object('role', jsonb_build_array(old.role, new.role))
                     else jsonb_build_object('role', r.role) end);
  return null;
end $$;
revoke all on function public.edr_audit_sso_map() from public, anon, authenticated;
create trigger trg_audit after insert or update or delete on public.sso_group_roles
  for each row execute function public.edr_audit_sso_map();

-- 구성원 목록에 "어디서 온 계정인지"(수동 / AD 그룹) 추가
drop function if exists public.console_members(uuid);
create function public.console_members(p_tenant uuid)
returns table (user_id uuid, email text, role text, created_at timestamptz, managed_by text)
language sql stable security definer set search_path = '' as $$
  select m.user_id, u.email::text, m.role, m.created_at, m.managed_by
  from public.tenant_members m join auth.users u on u.id = m.user_id
  where m.tenant_id = p_tenant
    and p_tenant in (select public.my_tenant_ids())
  order by m.created_at
$$;
revoke all on function public.console_members(uuid) from public, anon;
grant execute on function public.console_members(uuid) to authenticated;
