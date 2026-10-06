-- =====================================================================
-- Endpoint EDR : 핵심 스키마
--   * 조직(tenant) 단위: 사내 기본은 회사 1개. 계열사·법인 분리가 필요하면 tenant 를 추가한다.
--   * 대용량 텔레메트리 테이블은 월 단위 파티션(PostgreSQL 기본 기능만 사용, 확장 불필요).
--   * 에이전트는 이 DB 에 직접 쓰지 않는다. services/ingest 만 edr_ingest 역할로 쓴다.
-- =====================================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;  -- Supabase 는 extensions 스키마에 기본 설치됨

-- ---------- 테넌트 / 사용자 ----------
create table public.tenants (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  plan        text not null default 'free',
  settings    jsonb not null default '{}'::jsonb,   -- 예: {"retention_days": 90}
  created_at  timestamptz not null default now()
);

create table public.tenant_members (
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  role        text not null check (role in ('owner','admin','analyst','viewer')),
  created_at  timestamptz not null default now(),
  primary key (tenant_id, user_id)
);
create index on public.tenant_members (user_id);

-- ---------- 장치 / 등록 ----------
create table public.enrollment_keys (
  id          uuid primary key default gen_random_uuid(),
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  key_hash    bytea not null unique,                 -- sha256(평문 키). 평문은 저장하지 않는다.
  label       text,
  max_uses    int  not null default 1000,
  used_count  int  not null default 0,
  expires_at  timestamptz not null default now() + interval '30 days',
  revoked     boolean not null default false,
  created_by  uuid references auth.users(id),
  created_at  timestamptz not null default now()
);

create table public.devices (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid not null references public.tenants(id) on delete cascade,
  hostname       text not null,
  os_version     text,
  agent_version  text,
  token_hash     bytea not null unique,              -- sha256(장치 토큰)
  status         text not null default 'active' check (status in ('active','disabled','retired')),
  tags           text[] not null default '{}',
  last_ip        inet,
  enrolled_at    timestamptz not null default now(),
  last_seen_at   timestamptz
);
create index on public.devices (tenant_id, last_seen_at desc);

-- ---------- 파일 해시 평판 (전역 캐시: 같은 해시는 한 번만 외부 조회) ----------
create table public.file_hashes (
  sha256         text primary key check (sha256 ~ '^[0-9a-f]{64}$'),
  verdict        text not null default 'pending'
                 check (verdict in ('pending','clean','unknown','suspicious','malicious','error')),
  vt_malicious   int,
  vt_suspicious  int,
  vt_total       int,
  sources        jsonb not null default '{}'::jsonb,  -- 공급자별 원본 요약
  first_seen_at  timestamptz not null default now(),
  checked_at     timestamptz,
  next_check_at  timestamptz not null default now()
);
create index on public.file_hashes (next_check_at) where verdict in ('pending','unknown','clean');

-- 테넌트가 실제로 본 해시(권한 판단 + "몇 대에서 실행됐나" 집계용)
create table public.tenant_file_hashes (
  tenant_id      uuid not null references public.tenants(id) on delete cascade,
  sha256         text not null references public.file_hashes(sha256),
  sample_path    text,
  first_seen_at  timestamptz not null default now(),
  last_seen_at   timestamptz not null default now(),
  primary key (tenant_id, sha256)
);
create index on public.tenant_file_hashes (sha256);

-- ---------- 텔레메트리 (월 파티션) ----------
create table public.process_events (
  id            bigint generated always as identity,
  tenant_id     uuid not null,
  device_id     uuid not null,
  observed_at   timestamptz not null,
  ingested_at   timestamptz not null default now(),
  pid           int not null,
  ppid          int,
  create_time   timestamptz,
  name          text not null,
  path          text,
  command_line  text,
  username      text,
  sha256        text,
  is_snapshot   boolean not null default false,
  primary key (id, observed_at)
) partition by range (observed_at);
create index on public.process_events (tenant_id, device_id, observed_at desc);
create index on public.process_events (sha256, observed_at desc) where sha256 is not null;

create table public.net_connections (
  id            bigint generated always as identity,
  tenant_id     uuid not null,
  device_id     uuid not null,
  observed_at   timestamptz not null,
  ingested_at   timestamptz not null default now(),
  proto         text not null,
  direction     text not null,
  local_ip      inet,
  local_port    int,
  remote_ip     inet,
  remote_port   int,
  state         text,
  pid           int,
  process_name  text,
  is_external   boolean not null default false,
  primary key (id, observed_at)
) partition by range (observed_at);
create index on public.net_connections (tenant_id, device_id, observed_at desc);
create index on public.net_connections (remote_ip, observed_at desc) where is_external;

create table public.security_events (
  id             bigint generated always as identity,
  tenant_id      uuid not null,
  device_id      uuid not null,
  channel        text not null,
  record_id      bigint not null,
  event_id       int not null,
  event_time     timestamptz not null,
  ingested_at    timestamptz not null default now(),
  provider       text,
  target_user    text,
  target_domain  text,
  logon_type     int,
  src_ip         inet,
  src_port       int,
  workstation    text,
  status         text,
  sub_status     text,
  process_name   text,
  data           jsonb,
  primary key (id, event_time),
  unique (device_id, channel, record_id, event_time)  -- 재전송 중복 제거
) partition by range (event_time);
create index on public.security_events (tenant_id, event_id, event_time desc);
create index on public.security_events (src_ip, event_time desc) where src_ip is not null;
create index on public.security_events (ingested_at);

-- ---------- 지속성 (현재 상태 + 변경 이력) ----------
create table public.autoruns (
  tenant_id      uuid not null,
  device_id      uuid not null references public.devices(id) on delete cascade,
  location       text not null,
  entry_name     text not null,
  command        text,
  image_path     text,
  sha256         text,
  first_seen_at  timestamptz not null default now(),
  last_seen_at   timestamptz not null default now(),
  removed_at     timestamptz,
  primary key (device_id, location, entry_name)
);
create index on public.autoruns (tenant_id);

create table public.autorun_changes (
  id            bigint generated always as identity primary key,
  tenant_id     uuid not null,
  device_id     uuid not null references public.devices(id) on delete cascade,
  change        text not null check (change in ('baseline','added','modified','removed')),
  location      text not null,
  entry_name    text not null,
  command       text,
  image_path    text,
  sha256        text,
  observed_at   timestamptz not null,
  ingested_at   timestamptz not null default now()
);
create index on public.autorun_changes (tenant_id, observed_at desc);
create index on public.autorun_changes (ingested_at) where change in ('added','modified');

-- ---------- 경보 ----------
create table public.alerts (
  id           bigint generated always as identity primary key,
  tenant_id    uuid not null references public.tenants(id) on delete cascade,
  device_id    uuid references public.devices(id) on delete set null,
  rule_id      text not null,
  severity     text not null check (severity in ('low','medium','high','critical')),
  title        text not null,
  details      jsonb not null default '{}'::jsonb,
  dedup_key    text not null,
  status       text not null default 'open' check (status in ('open','acknowledged','closed')),
  assigned_to  uuid references auth.users(id),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  unique (tenant_id, dedup_key)
);
create index on public.alerts (tenant_id, status, created_at desc);

-- ---------- 파티션 관리 (pg_partman 없이) ----------
-- 이번 달 - 1 ~ 이번 달 + months_ahead 의 월 파티션을 만든다. 매일 실행해도 안전(idempotent).
create or replace function public.edr_ensure_partitions(months_ahead int default 2)
returns void language plpgsql as $$
declare
  t text;
  m date;
  part text;
begin
  foreach t in array array['process_events','net_connections','security_events'] loop
    for i in -1..months_ahead loop
      m := (date_trunc('month', now()) + make_interval(months => i))::date;
      part := format('%s_%s', t, to_char(m, 'YYYYMM'));
      if to_regclass('public.' || part) is null then
        execute format('create table public.%I partition of public.%I for values from (%L) to (%L)',
                       part, t, m, (m + interval '1 month')::date);
        execute format('alter table public.%I enable row level security', part);
      end if;
    end loop;
  end loop;
end $$;

-- 보존 기간이 지난 파티션을 통째로 삭제(DELETE 보다 훨씬 가볍다).
create or replace function public.edr_drop_old_partitions(retention_months int default 3)
returns void language plpgsql as $$
declare
  r record;
  cutoff text := to_char(date_trunc('month', now()) - make_interval(months => retention_months), 'YYYYMM');
begin
  for r in
    select c.relname from pg_inherits i
    join pg_class c on c.oid = i.inhrelid
    join pg_class p on p.oid = i.inhparent
    where p.relname in ('process_events','net_connections','security_events')
      and right(c.relname, 6) ~ '^\d{6}$' and right(c.relname, 6) < cutoff
  loop
    execute format('drop table public.%I', r.relname);
  end loop;
end $$;

select public.edr_ensure_partitions(2);
