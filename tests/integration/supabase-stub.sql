-- 통합 테스트용 Supabase 흉내(빈 PostgreSQL 에 마이그레이션을 적용하기 전에 실행)
--   * Supabase 기본 역할(anon, authenticated, service_role)
--   * auth.users 와 auth.uid() — PostgREST 가 넘겨 준 JWT 의 sub 를 읽는다
-- 실제 Supabase 프로젝트에는 절대 실행하지 말 것.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon')          then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role')  then create role service_role nologin bypassrls; end if;
end $$;

create schema if not exists auth;
create table if not exists auth.users (id uuid primary key, email text);
-- 실제 Supabase Auth 의 auth.users 에 있는 열 중 마이그레이션이 쓰는 것
alter table auth.users add column if not exists raw_app_meta_data jsonb default '{}'::jsonb;
alter table auth.users add column if not exists raw_user_meta_data jsonb default '{}'::jsonb;
create or replace function auth.uid() returns uuid language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claim.sub', true), ''),
                  (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub'))::uuid
$$;
grant usage on schema auth to anon, authenticated, service_role;
grant execute on function auth.uid() to anon, authenticated;
grant usage on schema public to anon, authenticated, service_role;
