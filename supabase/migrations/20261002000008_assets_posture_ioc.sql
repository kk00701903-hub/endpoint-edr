-- =====================================================================
-- 0008 : 자산 인벤토리 · 보안 상태 점검 · 소프트웨어 정책(취약·금지) · 위협 지표(IOC)
--   벤치마크(docs/BENCHMARK.md)
--     CrowdStrike Falcon : Discover(자산·앱 목록), Spotlight(취약 소프트웨어), Zero Trust Assessment(보안 상태 점수), Custom IOC
--     Genians            : 단말 정보 수집, 정책 준수(백신·패치·화면보호기 등), 미인가 소프트웨어 탐지
--   모두 "보기" 기능이다. PC 를 바꾸는 대응(격리·차단·설치 제거·설정 변경)은 만들지 않는다(수동형 원칙).
--
--   1) 참조표: posture_checks(점검 항목), os_lifecycle(Windows 지원 종료일)
--   2) 장치 자산: device_inventory(OS·하드웨어·네트워크), device_software(설치 프로그램), software_changes(설치·삭제·업데이트 이력)
--   3) 보안 상태: device_posture(장치 × 점검 항목), posture_policies(조직별 점수 포함 여부)
--   4) 소프트웨어 정책: software_policies(취약 버전·금지 소프트웨어). 기본 제공 목록은 조직마다 복사해 넣는다(고치거나 지울 수 있게)
--   5) 위협 지표: iocs(해시·IP). 등록하면 최근 7일을 소급해 찾고, 이후 들어오는 데이터는 탐지 실행 때마다 찾는다
--   6) 수집 서버(edr_ingest)가 부르는 저장 함수: edr_apply_inventory / edr_apply_posture
--   7) 탐지 규칙 4개(EDR-IOC-001/002, EDR-SW-001, EDR-POS-001), 유지보수·장치 타임라인 확장
--   8) 콘솔 조회 함수, 권한(RLS), 감사 기록
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0) 공통 도우미
-- ---------------------------------------------------------------------

-- 버전 비교: 숫자 부분만 차례로 비교한다("6.23.0" < "6.24", "24.09" > "24.8" 는 아님 — 24.9 로 본다). -1 / 0 / 1
create or replace function public.edr_version_cmp(a text, b text)
returns int language plpgsql immutable as $$
declare
  x numeric[] := array(select m[1]::numeric from regexp_matches(coalesce(a, ''), '(\d{1,30})', 'g') with ordinality as t(m, i) order by i);
  y numeric[] := array(select m[1]::numeric from regexp_matches(coalesce(b, ''), '(\d{1,30})', 'g') with ordinality as t(m, i) order by i);
  i int;
begin
  for i in 1 .. greatest(cardinality(x), cardinality(y)) loop
    if coalesce(x[i], 0) < coalesce(y[i], 0) then return -1; end if;
    if coalesce(x[i], 0) > coalesce(y[i], 0) then return 1; end if;
  end loop;
  return 0;
end $$;

-- 관리자가 적는 이름 조건 → ILIKE 패턴. '*' 는 아무 글자, 나머지는 "포함" 으로 본다(대소문자 무시)
create or replace function public.edr_like(p text)
returns text language sql immutable as $$
  select '%' || replace(replace(replace(replace(coalesce(p, ''), '\', '\\'), '%', '\%'), '_', '\_'), '*', '%') || '%'
$$;

create or replace function public.edr_try_inet(v text)
returns inet language plpgsql immutable as $$
begin
  return v::inet;
exception when others then
  return null;
end $$;

create or replace function public.edr_try_date(v text)
returns date language plpgsql immutable as $$
begin
  if v is null or v !~ '^\d{8}$' then return null; end if;
  return to_date(v, 'YYYYMMDD');
exception when others then
  return null;
end $$;

create or replace function public.edr_try_int(v text)
returns bigint language plpgsql immutable as $$
begin
  return v::numeric::bigint;
exception when others then
  return null;
end $$;

-- ---------------------------------------------------------------------
-- 1) 참조표
-- ---------------------------------------------------------------------
create table public.posture_checks (
  check_id         text primary key check (check_id ~ '^[a-z0-9_]{2,40}$'),
  title            text not null,
  description      text not null,
  remediation      text not null,
  category         text not null,
  weight           int  not null default 10 check (weight between 1 and 100),
  default_enabled  boolean not null default true,   -- 보안 점수에 넣을지(조직별로 posture_policies 에서 바꿀 수 있음)
  drift_alert      boolean not null default false,  -- 통과 → 실패로 바뀌면 경보(EDR-POS-001)
  source           text not null default 'agent' check (source in ('agent', 'server')),
  sort             int  not null default 100
);

insert into public.posture_checks (check_id, title, description, remediation, category, weight, default_enabled, drift_alert, source, sort) values
 ('av_realtime', '악성코드 실시간 검사', 'Microsoft Defender 실시간 보호가 켜져 있거나, 다른 백신의 실시간 감시 서비스가 실행 중인지 봅니다.',
  'Windows 보안 → 바이러스 및 위협 방지 → 실시간 보호 켜기. 회사 백신을 쓰면 그 서비스가 실행 중인지 확인합니다.', '악성코드 방어', 25, true, true, 'agent', 10),
 ('firewall', 'Windows 방화벽', '도메인·개인·공용 세 프로필 모두 방화벽이 켜져 있고 방화벽 서비스가 실행 중인지 봅니다(그룹 정책 값 우선).',
  '제어판 → Windows Defender 방화벽 → 세 프로필 모두 켜기. 그룹 정책으로 꺼 두었다면 정책을 확인합니다.', '네트워크', 20, true, true, 'agent', 20),
 ('os_supported', '지원되는 Windows 버전', 'Microsoft 보안 업데이트를 아직 받는 Windows 버전인지 봅니다(서버가 수명 주기 표로 판단). 90일 안에 끝나면 주의로 표시합니다.',
  'Windows 업데이트로 최신 기능 업데이트(예: Windows 11 25H2)를 설치합니다. 확장 보안 업데이트(ESU)에 가입한 PC 는 예외로 둘 수 있습니다.', '업데이트', 20, true, false, 'server', 30),
 ('auto_update', '자동 업데이트', 'Windows Update 서비스가 꺼져 있거나 그룹 정책으로 자동 업데이트를 막지 않았는지 봅니다.',
  'services.msc 에서 Windows Update 시작 유형을 "수동" 이상으로, 그룹 정책의 "자동 업데이트 구성"을 확인합니다.', '업데이트', 10, true, false, 'agent', 40),
 ('uac', '사용자 계정 컨트롤(UAC)', '관리자 권한 실행 전에 확인을 받는 UAC 가 켜져 있는지 봅니다.',
  '제어판 → 사용자 계정 → 사용자 계정 컨트롤 설정 변경 → 기본값 이상으로.', '계정·인증', 10, true, false, 'agent', 50),
 ('wdigest', '평문 자격 증명 저장 안 함', 'WDigest 가 로그온 비밀번호를 메모리에 평문으로 남기도록 설정되지 않았는지 봅니다(공격 도구가 자주 켜는 설정).',
  'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest 의 UseLogonCredential 을 0 으로(또는 값 삭제). 바뀐 경위를 함께 조사합니다.', '계정·인증', 10, true, true, 'agent', 60),
 ('smb1', 'SMBv1 꺼짐', '랜섬웨어 확산에 쓰였던 옛 파일 공유 방식(SMBv1)이 꺼져 있는지 봅니다.',
  'Windows 기능 켜기/끄기에서 "SMB 1.0/CIFS 파일 공유 지원" 해제.', '네트워크', 10, true, false, 'agent', 70),
 ('rdp_nla', '원격 데스크톱 보안', '원격 데스크톱이 꺼져 있거나, 켜져 있다면 연결 전에 계정 인증(NLA)을 요구하는지 봅니다.',
  '설정 → 시스템 → 원격 데스크톱 → "네트워크 수준 인증 필요" 켜기. 쓰지 않으면 원격 데스크톱 끄기.', '네트워크', 10, true, false, 'agent', 80),
 ('autologon', '자동 로그온 비밀번호 없음', '자동 로그온용 비밀번호가 레지스트리에 저장돼 있지 않은지 봅니다(값 이름만 확인하고 내용은 읽지 않음).',
  'netplwiz 에서 자동 로그온 해제, Winlogon 의 DefaultPassword 값 삭제.', '계정·인증', 5, true, false, 'agent', 90),
 ('screen_lock', '화면 잠금 15분 이내', '자리를 비웠을 때 15분 안에 화면이 잠기는지 봅니다(컴퓨터 비활성 한도 정책 또는 로그온한 사용자의 암호 보호 화면 보호기).',
  '그룹 정책 "대화형 로그온: 컴퓨터 비활성 한도"를 900초 이하로, 또는 화면 보호기 대기 15분 이하 + "다시 시작할 때 로그온 화면 표시".', '계정·인증', 5, true, false, 'agent', 100),
 ('lsa_protection', 'LSA 보호', '로그온 정보를 다루는 LSA 프로세스가 보호 모드(RunAsPPL)로 실행되는지 봅니다. 호환성 확인이 필요해 기본은 점수에서 뺍니다.',
  'HKLM\SYSTEM\CurrentControlSet\Control\Lsa 의 RunAsPPL 을 1 로(재부팅 필요). 먼저 호환성 감사 모드로 확인합니다.', '계정·인증', 5, false, false, 'agent', 110),
 ('ps_logging', 'PowerShell 스크립트 기록', 'PowerShell 스크립트 블록 기록이 켜져 있어 사고 조사 때 실행 내용을 볼 수 있는지 봅니다. 기본은 점수에서 뺍니다.',
  '그룹 정책 → Windows PowerShell → "PowerShell 스크립트 블록 로깅 설정" 사용.', '가시성', 5, false, false, 'agent', 120);

alter table public.posture_checks enable row level security;
grant select on public.posture_checks to authenticated, grafana_reader, edr_enricher, edr_ingest;
create policy checks_read  on public.posture_checks for select to authenticated using (true);
create policy grafana_read on public.posture_checks for select to grafana_reader using (true);
create policy service_read on public.posture_checks for select to edr_enricher, edr_ingest using (true);

-- Windows 수명 주기(Microsoft 공개 일정). servicing: consumer(Home·Pro 등) / enterprise(Enterprise·Education) / ltsc / any(서버)
-- 새 버전이 나오거나 일정이 바뀌면 새 마이그레이션으로 행을 추가·수정한다.
create table public.os_lifecycle (
  product         text not null check (product in ('client', 'server')),
  build           int  not null,
  servicing       text not null check (servicing in ('consumer', 'enterprise', 'ltsc', 'any')),
  version_label   text not null,
  end_of_support  date not null,
  primary key (product, build, servicing)
);
insert into public.os_lifecycle values
 ('client', 14393, 'ltsc',       'Windows 10 Enterprise LTSB 2016', '2026-10-13'),
 ('client', 17763, 'ltsc',       'Windows 10 Enterprise LTSC 2019', '2029-01-09'),
 ('client', 19044, 'consumer',   'Windows 10 21H2',                 '2023-06-13'),
 ('client', 19044, 'enterprise', 'Windows 10 21H2',                 '2024-06-11'),
 ('client', 19044, 'ltsc',       'Windows 10 Enterprise LTSC 2021', '2027-01-12'),
 ('client', 19045, 'consumer',   'Windows 10 22H2',                 '2025-10-14'),
 ('client', 19045, 'enterprise', 'Windows 10 22H2',                 '2025-10-14'),
 ('client', 22000, 'consumer',   'Windows 11 21H2',                 '2023-10-10'),
 ('client', 22000, 'enterprise', 'Windows 11 21H2',                 '2024-10-08'),
 ('client', 22621, 'consumer',   'Windows 11 22H2',                 '2024-10-08'),
 ('client', 22621, 'enterprise', 'Windows 11 22H2',                 '2025-10-14'),
 ('client', 22631, 'consumer',   'Windows 11 23H2',                 '2025-11-11'),
 ('client', 22631, 'enterprise', 'Windows 11 23H2',                 '2026-11-10'),
 ('client', 26100, 'consumer',   'Windows 11 24H2',                 '2026-10-13'),
 ('client', 26100, 'enterprise', 'Windows 11 24H2',                 '2027-10-12'),
 ('client', 26100, 'ltsc',       'Windows 11 Enterprise LTSC 2024', '2029-10-09'),
 ('client', 26200, 'consumer',   'Windows 11 25H2',                 '2027-10-12'),
 ('client', 26200, 'enterprise', 'Windows 11 25H2',                 '2028-10-10'),
 ('server',  9200, 'any',        'Windows Server 2012',             '2023-10-10'),
 ('server',  9600, 'any',        'Windows Server 2012 R2',          '2023-10-10'),
 ('server', 14393, 'any',        'Windows Server 2016',             '2027-01-12'),
 ('server', 17763, 'any',        'Windows Server 2019',             '2029-01-09'),
 ('server', 20348, 'any',        'Windows Server 2022',             '2031-10-14'),
 ('server', 26100, 'any',        'Windows Server 2025',             '2034-11-14');

alter table public.os_lifecycle enable row level security;
grant select on public.os_lifecycle to authenticated, grafana_reader;
create policy lifecycle_read on public.os_lifecycle for select to authenticated using (true);
create policy grafana_read   on public.os_lifecycle for select to grafana_reader using (true);

-- EditionID(레지스트리) → 수명 주기 구분
create or replace function public.edr_os_servicing(p_product text, p_edition text)
returns text language sql immutable as $$
  select case
    when p_product = 'server' then 'any'
    when p_edition ilike '%EnterpriseS%' then 'ltsc'
    when p_edition ilike 'Enterprise%' or p_edition ilike 'Education%' or p_edition ilike 'IoTEnterprise%' then 'enterprise'
    else 'consumer' end
$$;

-- ---------------------------------------------------------------------
-- 2) 장치 자산
-- ---------------------------------------------------------------------
create table public.device_inventory (
  device_id           uuid primary key references public.devices(id) on delete cascade,
  tenant_id           uuid not null references public.tenants(id) on delete cascade,
  os_name             text,             -- 예: Windows 11 Pro
  os_edition          text,             -- EditionID 예: Professional, Enterprise
  os_display_version  text,             -- 예: 24H2
  os_build            int,
  os_ubr              int,              -- 누적 업데이트 번호(빌드 26100.4061 의 4061)
  os_product          text check (os_product in ('client', 'server')),
  os_arch             text,
  os_installed_at     timestamptz,
  os_label            text,             -- 수명 주기 표의 이름(예: Windows 11 24H2)
  os_end_of_support   date,
  manufacturer        text,
  model               text,
  serial_number       text,
  bios_version        text,
  cpu                 text,
  cpu_cores           int,
  memory_mb           int,
  disk_total_gb       numeric(10, 1),
  disk_free_gb        numeric(10, 1),
  domain              text,
  domain_joined       boolean,
  last_user           text,
  adapters            jsonb not null default '[]'::jsonb,   -- [{name, mac, ips[]}]
  software_count      int not null default 0,
  collected_at        timestamptz,
  first_seen_at       timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);
create index on public.device_inventory (tenant_id);

create table public.device_software (
  tenant_id      uuid not null references public.tenants(id) on delete cascade,
  device_id      uuid not null references public.devices(id) on delete cascade,
  name           text not null,
  version        text not null default '',
  publisher      text,
  install_date   date,
  scope          text not null default 'machine' check (scope in ('machine', 'user')),
  arch           text,
  first_seen_at  timestamptz not null default now(),
  last_seen_at   timestamptz not null default now(),
  primary key (device_id, name, version)
);
create index device_software_title on public.device_software (tenant_id, name, version);
create index device_software_first_seen on public.device_software (first_seen_at);

create table public.software_changes (
  id            bigint generated always as identity primary key,
  tenant_id     uuid not null references public.tenants(id) on delete cascade,
  device_id     uuid not null references public.devices(id) on delete cascade,
  change        text not null check (change in ('installed', 'removed', 'updated')),
  name          text not null,
  version       text,
  prev_version  text,
  publisher     text,
  observed_at   timestamptz not null default now()
);
create index on public.software_changes (tenant_id, observed_at desc);
create index on public.software_changes (device_id, observed_at desc);

-- ---------------------------------------------------------------------
-- 3) 보안 상태
-- ---------------------------------------------------------------------
create table public.device_posture (
  tenant_id      uuid not null references public.tenants(id) on delete cascade,
  device_id      uuid not null references public.devices(id) on delete cascade,
  check_id       text not null references public.posture_checks(check_id),
  status         text not null check (status in ('pass', 'warn', 'fail', 'unknown')),
  detail         text,
  prev_status    text,                 -- 바로 전 상태(바뀌었을 때만 갱신)
  changed_at     timestamptz not null default now(),
  failing_since  timestamptz,          -- 실패가 이어진 시작 시각
  checked_at     timestamptz not null default now(),
  primary key (device_id, check_id)
);
create index on public.device_posture (tenant_id, check_id, status);
create index device_posture_changed on public.device_posture (changed_at) where status = 'fail';

create table public.posture_policies (
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  check_id    text not null references public.posture_checks(check_id),
  enabled     boolean not null,            -- 보안 점수·경보에 포함
  updated_by  uuid references auth.users(id),
  updated_at  timestamptz not null default now(),
  primary key (tenant_id, check_id)
);

-- 장치 보안 점수(0~100): 조직에서 켠 항목만, 가중치 합 대비 통과(주의 포함) 비율. 판단할 항목이 없으면 null
create or replace function public.edr_posture_score(p_device uuid)
returns int language sql stable set search_path = public as $$
  select case when coalesce(sum(c.weight) filter (where dp.status <> 'unknown'), 0) = 0 then null
              else round(100.0 * coalesce(sum(c.weight) filter (where dp.status in ('pass', 'warn')), 0)
                         / sum(c.weight) filter (where dp.status <> 'unknown'))::int end
  from device_posture dp
  join posture_checks c on c.check_id = dp.check_id
  left join posture_policies pp on pp.tenant_id = dp.tenant_id and pp.check_id = dp.check_id
  where dp.device_id = p_device and coalesce(pp.enabled, c.default_enabled)
$$;

-- ---------------------------------------------------------------------
-- 4) 소프트웨어 정책: 취약 버전(vulnerable) · 금지(prohibited)
-- ---------------------------------------------------------------------
create table public.software_policies (
  id                 bigint generated always as identity primary key,
  tenant_id          uuid not null references public.tenants(id) on delete cascade,
  kind               text not null check (kind in ('vulnerable', 'prohibited')),
  name_pattern       text not null check (length(trim(name_pattern)) between 2 and 120),
  publisher_pattern  text check (length(publisher_pattern) <= 120),
  fixed_version      text check (length(fixed_version) <= 40),   -- vulnerable: 이 버전 미만이 취약. 비우면 모든 버전(지원 종료 제품 등)
  severity           text not null default 'medium' check (severity in ('low', 'medium', 'high', 'critical')),
  reference          text check (length(reference) <= 300),       -- CVE 번호·공지 주소
  reason             text not null default '' check (length(reason) <= 500),
  enabled            boolean not null default true,
  builtin            boolean not null default false,   -- 기본 제공 목록에서 복사된 항목
  created_by         uuid references auth.users(id),
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);
create index on public.software_policies (tenant_id);

create or replace function public.edr_sw_matches(p_name text, p_version text, p_publisher text, p public.software_policies)
returns boolean language sql immutable as $$
  select p.enabled
     and p_name ilike public.edr_like(p.name_pattern)
     and (p.publisher_pattern is null or p.publisher_pattern = '' or coalesce(p_publisher, '') ilike public.edr_like(p.publisher_pattern))
     and (p.kind = 'prohibited' or p.fixed_version is null or p.fixed_version = '' or public.edr_version_cmp(p_version, p.fixed_version) < 0)
$$;

-- 기본 제공 목록(널리 알려진 것만. 회사 사정에 맞게 콘솔에서 끄거나 지우고, 필요한 항목을 더한다)
create or replace function public.edr_seed_tenant_defaults(p_tenant uuid)
returns void language sql security definer set search_path = public as $$
  insert into software_policies (tenant_id, kind, name_pattern, publisher_pattern, fixed_version, severity, reference, reason, builtin)
  select p_tenant, v.kind, v.name_pattern, v.publisher_pattern, v.fixed_version, v.severity, v.reference, v.reason, true
  from (values
    ('vulnerable', 'WinRAR', 'win.rar', '6.23', 'high', 'CVE-2023-38831',
     '압축 파일을 열기만 해도 악성 코드가 실행될 수 있는 취약점(실제 공격에 쓰임). 6.23 이상으로 업데이트'),
    ('vulnerable', '7-Zip', 'Igor Pavlov', '24.09', 'medium', 'CVE-2025-0411',
     '압축을 풀 때 인터넷에서 받은 파일 표시(MotW)가 빠지는 취약점(실제 공격에 쓰임). 24.09 이상으로 업데이트'),
    ('vulnerable', 'Adobe Flash Player', null, null, 'high', 'https://www.adobe.com/products/flashplayer/end-of-life.html',
     '2020년 12월 31일 지원 종료. 보안 업데이트가 없으므로 삭제'),
    ('vulnerable', 'Microsoft Silverlight', null, null, 'medium', 'https://learn.microsoft.com/lifecycle/products/silverlight-5',
     '2021년 10월 12일 지원 종료. 보안 업데이트가 없으므로 삭제'),
    ('vulnerable', 'Python 2.7', null, null, 'low', 'https://www.python.org/doc/sunset-python-2/',
     '2020년 1월 1일 지원 종료. Python 3 으로 옮기고 삭제')
  ) as v(kind, name_pattern, publisher_pattern, fixed_version, severity, reference, reason)
  where not exists (select 1 from software_policies s where s.tenant_id = p_tenant and s.builtin)
$$;
revoke all on function public.edr_seed_tenant_defaults(uuid) from public, anon, authenticated;

create or replace function public.edr_on_tenant_created()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  perform edr_seed_tenant_defaults(new.id);
  return null;
end $$;
revoke all on function public.edr_on_tenant_created() from public, anon, authenticated;
create trigger trg_tenant_defaults after insert on public.tenants
  for each row execute function public.edr_on_tenant_created();

select public.edr_seed_tenant_defaults(id) from public.tenants;

-- ---------------------------------------------------------------------
-- 5) 위협 지표(IOC)
-- ---------------------------------------------------------------------
create table public.iocs (
  id           bigint generated always as identity primary key,
  tenant_id    uuid not null references public.tenants(id) on delete cascade,
  type         text not null check (type in ('sha256', 'ip')),
  value        text not null,
  severity     text not null default 'high' check (severity in ('low', 'medium', 'high', 'critical')),
  description  text not null default '' check (length(description) <= 500),
  source       text check (length(source) <= 200),     -- 예: KISA 공지, 사내 분석
  enabled      boolean not null default true,
  expires_at   timestamptz,
  hit_count    bigint not null default 0,
  last_hit_at  timestamptz,
  created_by   uuid references auth.users(id),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  unique (tenant_id, type, value),
  -- IP 는 단일 주소 또는 대역. 경보가 쏟아지지 않도록 너무 넓은 대역(IPv4 /16 미만, IPv6 /48 미만)은 받지 않는다
  check ((type = 'sha256' and value ~ '^[0-9a-f]{64}$')
      or (type = 'ip' and public.edr_try_inet(value) is not null
          and masklen(public.edr_try_inet(value)) >= case family(public.edr_try_inet(value)) when 4 then 16 else 48 end))
);
create index on public.iocs (tenant_id, type) where enabled;

-- 값 정리: 해시는 소문자, IP 는 표준 표기(단일 주소는 /32·/128 표기 없이)
create or replace function public.edr_normalize_ioc()
returns trigger language plpgsql as $$
declare a inet;
begin
  new.value := lower(trim(new.value));
  if new.type = 'ip' then
    a := public.edr_try_inet(new.value);
    if a is not null then
      new.value := case when masklen(a) = case family(a) when 4 then 32 else 128 end then host(a) else network(a)::text end;
    end if;
  end if;
  if tg_op = 'UPDATE' then new.updated_at := now(); end if;
  return new;
end $$;
create trigger trg_ioc_normalize before insert or update on public.iocs
  for each row execute function public.edr_normalize_ioc();

-- 소프트웨어 정책 수정 시각
create or replace function public.edr_touch_policy()
returns trigger language plpgsql as $$
begin new.updated_at := now(); return new; end $$;
create trigger trg_sw_policy_touch before update on public.software_policies
  for each row execute function public.edr_touch_policy();

-- ---------------------------------------------------------------------
-- 6) 수집 서버가 부르는 저장 함수 (edr_ingest 만 실행 가능)
-- ---------------------------------------------------------------------

-- 장치 1대의 점검 결과 한 줄을 반영. 상태가 바뀌면 이전 상태·바뀐 시각·실패 시작 시각을 남긴다
create or replace function public.edr_set_posture(p_tenant uuid, p_device uuid, p_check text, p_status text, p_detail text)
returns void language sql security definer set search_path = public as $$
  insert into device_posture as d (tenant_id, device_id, check_id, status, detail, changed_at, failing_since, checked_at)
  values (p_tenant, p_device, p_check, p_status, left(p_detail, 500), now(), case when p_status = 'fail' then now() end, now())
  on conflict (device_id, check_id) do update set
    prev_status   = case when d.status <> excluded.status then d.status else d.prev_status end,
    changed_at    = case when d.status <> excluded.status then now() else d.changed_at end,
    failing_since = case when excluded.status <> 'fail' then null
                         when d.status = 'fail' then d.failing_since else now() end,
    status        = excluded.status,
    detail        = excluded.detail,
    checked_at    = now()
$$;
revoke all on function public.edr_set_posture(uuid, uuid, text, text, text) from public, anon, authenticated;

-- 장치가 보낸 보안 점검 결과(에이전트가 판단하는 항목만 받는다)
create or replace function public.edr_apply_posture(p_tenant uuid, p_device uuid, p_checks jsonb)
returns int language plpgsql security definer set search_path = public as $$
declare
  e jsonb;
  n int := 0;
begin
  if not exists (select 1 from devices where id = p_device and tenant_id = p_tenant) then
    raise exception 'device % not in tenant', p_device using errcode = '42501';
  end if;
  for e in select x from jsonb_array_elements(case jsonb_typeof(p_checks) when 'array' then p_checks else '[]'::jsonb end) as t(x) limit 100 loop
    if e->>'status' in ('pass', 'warn', 'fail', 'unknown')
       and exists (select 1 from posture_checks c where c.check_id = e->>'id' and c.source = 'agent') then
      perform edr_set_posture(p_tenant, p_device, e->>'id', e->>'status', e->>'detail');
      n := n + 1;
    end if;
  end loop;
  return n;
end $$;

-- 장치가 보낸 자산 정보(전체 목록). 설치 프로그램은 현재 목록과 비교해 설치·삭제·업데이트 이력을 남긴다.
-- 이 장치의 첫 자산 정보면(기준선) 이력은 남기지 않는다.
create or replace function public.edr_apply_inventory(p_tenant uuid, p_device uuid, p jsonb)
returns int language plpgsql security definer set search_path = public as $$
declare
  os        jsonb := coalesce(p->'os', '{}'::jsonb);
  hw        jsonb := coalesce(p->'hardware', '{}'::jsonb);
  baseline  boolean;
  v_product text := case when coalesce(os->>'install_type', '') ilike 'server%' then 'server' else 'client' end;
  v_build   int := edr_try_int(os->>'build');
  v_serv    text;
  lc        record;
  st        text;
  dt        text;
  n_sw      int;
begin
  if not exists (select 1 from devices where id = p_device and tenant_id = p_tenant) then
    raise exception 'device % not in tenant', p_device using errcode = '42501';
  end if;
  baseline := not exists (select 1 from device_inventory where device_id = p_device);
  v_serv := edr_os_servicing(v_product, os->>'edition');

  -- 지원 종료 판단(서버 측 점검 항목 os_supported)
  select l.version_label, l.end_of_support into lc
    from os_lifecycle l
   where l.product = v_product and l.build = v_build and l.servicing in (v_serv, 'any')
   order by (l.servicing = v_serv) desc limit 1;
  if lc.end_of_support is not null then
    if lc.end_of_support < current_date then
      st := 'fail'; dt := format('%s — %s 지원 종료', lc.version_label, to_char(lc.end_of_support, 'YYYY-MM-DD'));
    elsif lc.end_of_support < current_date + 90 then
      st := 'warn'; dt := format('%s — %s 지원 종료 예정(%s일 남음)', lc.version_label, to_char(lc.end_of_support, 'YYYY-MM-DD'), lc.end_of_support - current_date);
    else
      st := 'pass'; dt := format('%s — %s 까지 지원', lc.version_label, to_char(lc.end_of_support, 'YYYY-MM-DD'));
    end if;
  elsif v_build is null then
    st := 'unknown'; dt := 'OS 빌드 정보 없음';
  elsif v_build > (select max(build) from os_lifecycle where product = v_product) then
    st := 'pass'; dt := format('최신 빌드 %s (수명 주기 표에 아직 없음)', v_build);
  elsif (v_product = 'client' and v_build < 19044) or (v_product = 'server' and v_build < 14393) then
    st := 'fail'; dt := format('지원이 끝난 옛 버전 (빌드 %s)', v_build);
  else
    st := 'unknown'; dt := format('수명 주기 표에 없는 빌드 %s (%s)', v_build, coalesce(os->>'edition', '에디션 미상'));
  end if;

  insert into device_inventory as i (device_id, tenant_id, os_name, os_edition, os_display_version, os_build, os_ubr, os_product,
      os_arch, os_installed_at, os_label, os_end_of_support, manufacturer, model, serial_number, bios_version, cpu, cpu_cores,
      memory_mb, disk_total_gb, disk_free_gb, domain, domain_joined, last_user, adapters, collected_at, updated_at)
  values (p_device, p_tenant, left(os->>'name', 128), left(os->>'edition', 64), left(os->>'display_version', 32), v_build,
      edr_try_int(os->>'ubr'), v_product, left(os->>'arch', 16),
      case when (os->>'installed_at') ~ '^(19[89]\d|2\d{3})-' then (os->>'installed_at')::timestamptz end,  -- Go 의 0001-01-01(값 없음) 제외
      lc.version_label, lc.end_of_support,
      left(nullif(trim(hw->>'manufacturer'), ''), 128), left(nullif(trim(hw->>'model'), ''), 128),
      left(nullif(trim(hw->>'serial'), ''), 128), left(nullif(trim(hw->>'bios_version'), ''), 128),
      left(nullif(trim(hw->>'cpu'), ''), 160), edr_try_int(hw->>'cores'), edr_try_int(hw->>'memory_mb'),
      round(nullif(hw->>'disk_total_gb', '')::numeric, 1), round(nullif(hw->>'disk_free_gb', '')::numeric, 1),
      left(nullif(p->>'domain', ''), 255), (p->>'domain_joined')::boolean, left(nullif(p->>'last_user', ''), 256),
      coalesce((select jsonb_agg(jsonb_build_object('name', left(a->>'name', 128), 'mac', left(a->>'mac', 32),
                                                    'ips', coalesce(a->'ips', '[]'::jsonb)))
                  from (select a from jsonb_array_elements(case jsonb_typeof(p->'adapters') when 'array' then p->'adapters' else '[]'::jsonb end) a limit 16) x),
               '[]'::jsonb),
      case when (p->>'collected_at') ~ '^(19[89]\d|2\d{3})-' then least((p->>'collected_at')::timestamptz, now()) else now() end,
      now())
  on conflict (device_id) do update set
      os_name = excluded.os_name, os_edition = excluded.os_edition, os_display_version = excluded.os_display_version,
      os_build = excluded.os_build, os_ubr = excluded.os_ubr, os_product = excluded.os_product, os_arch = excluded.os_arch,
      os_installed_at = excluded.os_installed_at, os_label = excluded.os_label, os_end_of_support = excluded.os_end_of_support,
      manufacturer = excluded.manufacturer, model = excluded.model, serial_number = excluded.serial_number,
      bios_version = excluded.bios_version, cpu = excluded.cpu, cpu_cores = excluded.cpu_cores, memory_mb = excluded.memory_mb,
      disk_total_gb = excluded.disk_total_gb, disk_free_gb = excluded.disk_free_gb, domain = excluded.domain,
      domain_joined = excluded.domain_joined, last_user = excluded.last_user, adapters = excluded.adapters,
      collected_at = excluded.collected_at, updated_at = now();

  perform edr_set_posture(p_tenant, p_device, 'os_supported', st, dt);

  -- 설치 프로그램: 이름+버전이 같은 것은 하나로, 최대 5000개
  if jsonb_typeof(p->'software') = 'array' then
    with inc as (
      select distinct on (name, version) name, version, publisher, install_date, scope, arch from (
        select left(trim(s->>'name'), 256) as name, left(coalesce(trim(s->>'version'), ''), 64) as version,
               left(nullif(trim(s->>'publisher'), ''), 256) as publisher, edr_try_date(s->>'install_date') as install_date,
               case when s->>'scope' = 'user' then 'user' else 'machine' end as scope, left(nullif(s->>'arch', ''), 8) as arch
        from (select s from jsonb_array_elements(p->'software') s limit 5000) x
      ) y
      where coalesce(name, '') <> ''
      order by name, version, scope
    ), gone as (
      delete from device_software d
       where d.device_id = p_device
         and not exists (select 1 from inc i where i.name = d.name and i.version = d.version)
      returning d.name, d.version, d.publisher
    ), added as (
      insert into device_software as d (tenant_id, device_id, name, version, publisher, install_date, scope, arch)
      select p_tenant, p_device, name, version, publisher, install_date, scope, arch from inc
      on conflict (device_id, name, version) do update
        set publisher = excluded.publisher, install_date = excluded.install_date, scope = excluded.scope,
            arch = excluded.arch, last_seen_at = now()
      returning d.name, d.version, d.publisher, (xmax = 0) as is_new
    ), news as (
      select name, version, publisher from added where is_new
    )
    insert into software_changes (tenant_id, device_id, change, name, version, prev_version, publisher)
    select p_tenant, p_device, c.change, c.name, c.version, c.prev_version, c.publisher
    from (
      -- 같은 이름이 빠지고 새 버전이 들어왔으면 업데이트 1건
      (select distinct on (n.name) 'updated' as change, n.name, n.version, g.version as prev_version, n.publisher
         from news n join gone g on g.name = n.name
        order by n.name, g.version)
      union all
      select 'installed', n.name, n.version, null, n.publisher from news n where not exists (select 1 from gone g where g.name = n.name)
      union all
      select 'removed', g.name, g.version, null, g.publisher from gone g where not exists (select 1 from news n where n.name = g.name)
    ) c
    where not baseline;

    select count(*) into n_sw from device_software where device_id = p_device;
    update device_inventory set software_count = n_sw where device_id = p_device;
  end if;
  return coalesce(n_sw, 0);
end $$;

revoke all on function public.edr_apply_posture(uuid, uuid, jsonb), public.edr_apply_inventory(uuid, uuid, jsonb) from public, anon, authenticated;
grant execute on function public.edr_apply_posture(uuid, uuid, jsonb), public.edr_apply_inventory(uuid, uuid, jsonb) to edr_ingest;


-- ---------------------------------------------------------------------
-- 7-1) 위협 지표 찾기 (탐지 실행 + 등록 시 소급이 함께 쓴다)
--   p_since : 발생 시각이 이 뒤인 데이터만 / p_after : 이 시각 뒤에 들어온(수집된) 데이터만 / p_ioc : 한 지표만(소급)
--   같은 장치·같은 지표·같은 파일은 경보 1건, IP 는 장치·지표·주소·시간(hour)마다 1건
-- ---------------------------------------------------------------------
create or replace function public.edr_match_iocs(p_since timestamptz, p_after timestamptz, p_ioc bigint default null)
returns int language plpgsql security definer set search_path = public as $$
declare
  n   int := 0;
  cnt int;
begin
  -- 해시: 실행된 프로세스 + 자동 실행 항목
  with active as (
    select * from iocs
     where enabled and type = 'sha256' and (expires_at is null or expires_at > now()) and (p_ioc is null or id = p_ioc)
  ), obs as (
    select p.tenant_id, p.device_id, i.id as ioc_id, i.severity, i.value, i.description,
           p.name, p.path, p.command_line, p.username, p.observed_at, 'process' as src
      from active i join process_events p on p.tenant_id = i.tenant_id and p.sha256 = i.value
     where p.observed_at > p_since and p.ingested_at > p_after
    union all
    select a.tenant_id, a.device_id, i.id, i.severity, i.value, i.description,
           a.entry_name, a.image_path, a.command, null, a.observed_at, 'autorun'
      from active i join autorun_changes a on a.tenant_id = i.tenant_id and a.sha256 = i.value
     where a.change <> 'removed' and a.observed_at > p_since and a.ingested_at > p_after
  ), hits as (
    select distinct on (device_id, ioc_id) * from obs order by device_id, ioc_id, observed_at desc
  ), ins as (
    insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
    select h.tenant_id, h.device_id, 'EDR-IOC-001', h.severity,
           case h.src when 'process' then '위협 지표(해시)와 같은 파일 실행: ' else '위협 지표(해시)와 같은 파일이 자동 실행에 등록됨: ' end || h.name,
           jsonb_build_object('ioc_id', h.ioc_id, 'ioc_type', 'sha256', 'ioc_value', h.value, 'ioc_description', nullif(h.description, ''),
                              'sha256', h.value, 'process', h.name, 'path', h.path, 'command_line', h.command_line,
                              'user', h.username, 'observed_at', h.observed_at, 'source', h.src),
           format('IOC001:%s:%s', h.device_id, h.ioc_id)
      from hits h
    on conflict (tenant_id, dedup_key) do nothing
    returning (details->>'ioc_id')::bigint as ioc_id
  ), upd as (
    update iocs set hit_count = hit_count + x.k, last_hit_at = now()
      from (select ioc_id, count(*) as k from ins group by ioc_id) x
     where iocs.id = x.ioc_id
    returning 1
  )
  select count(*) into cnt from ins;
  n := n + cnt;

  -- IP: 통신(원격지) + 로그온 시도 출발지
  with active as (
    select *, value::inet as net from iocs
     where enabled and type = 'ip' and (expires_at is null or expires_at > now()) and (p_ioc is null or id = p_ioc)
  ), obs as (
    select c.tenant_id, c.device_id, i.id as ioc_id, i.severity, i.value, i.description, c.remote_ip as ip,
           c.process_name as what, c.remote_port as port, c.direction, c.observed_at, 'connection' as src
      from active i join net_connections c on c.tenant_id = i.tenant_id and c.remote_ip <<= i.net
     where c.observed_at > p_since and c.ingested_at > p_after
    union all
    select s.tenant_id, s.device_id, i.id, i.severity, i.value, i.description, s.src_ip,
           coalesce(s.target_user, '') , null, 'logon ' || s.event_id, s.event_time, 'logon'
      from active i join security_events s on s.tenant_id = i.tenant_id and s.src_ip <<= i.net
     where s.event_time > p_since and s.ingested_at > p_after
  ), hits as (
    select distinct on (device_id, ioc_id, ip, date_trunc('hour', observed_at)) *
      from obs order by device_id, ioc_id, ip, date_trunc('hour', observed_at), observed_at desc
  ), ins as (
    insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
    select h.tenant_id, h.device_id, 'EDR-IOC-002', h.severity,
           case h.src when 'connection' then '위협 지표(IP)와 통신: ' else '위협 지표(IP)에서 로그온 시도: ' end || host(h.ip),
           jsonb_build_object('ioc_id', h.ioc_id, 'ioc_type', 'ip', 'ioc_value', h.value, 'ioc_description', nullif(h.description, ''),
                              case h.src when 'connection' then 'remote_ip' else 'src_ip' end, host(h.ip),
                              case h.src when 'connection' then 'process' else 'user' end, nullif(h.what, ''),
                              'remote_port', h.port, 'direction', h.direction, 'observed_at', h.observed_at, 'source', h.src),
           format('IOC002:%s:%s:%s:%s', h.device_id, h.ioc_id, host(h.ip), to_char(h.observed_at at time zone 'UTC', 'YYYYMMDDHH24'))
      from hits h
    on conflict (tenant_id, dedup_key) do nothing
    returning (details->>'ioc_id')::bigint as ioc_id
  ), upd as (
    update iocs set hit_count = hit_count + x.k, last_hit_at = now()
      from (select ioc_id, count(*) as k from ins group by ioc_id) x
     where iocs.id = x.ioc_id
    returning 1
  )
  select count(*) into cnt from ins;
  return n + cnt;
end $$;
revoke all on function public.edr_match_iocs(timestamptz, timestamptz, bigint) from public, anon, authenticated;

-- 지표를 등록하거나 다시 켜면 최근 7일을 소급해 찾는다
create or replace function public.edr_on_ioc_change()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.enabled and (tg_op = 'INSERT' or not old.enabled or old.value is distinct from new.value) then
    perform edr_match_iocs(now() - interval '7 days', '-infinity', new.id);
  end if;
  return null;
end $$;
revoke all on function public.edr_on_ioc_change() from public, anon, authenticated;
create trigger trg_ioc_retro after insert or update of enabled, value on public.iocs
  for each row execute function public.edr_on_ioc_change();


-- ---------------------------------------------------------------------
-- 7) 탐지 함수 교체 — 0006 과 같고, 끝에 EDR-IOC-001/002 · EDR-SW-001 · EDR-POS-001 블록 추가
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

  -- EDR-IOC-001 / EDR-IOC-002 : 위협 지표(해시·IP) — 이번에 새로 들어온 데이터만 (등록 시 7일 소급은 iocs 트리거)
  n := n + edr_match_iocs(v_to - interval '2 days', v_from);

  -- EDR-SW-001 : 금지 소프트웨어 — 새로 설치된 것, 또는 정책이 새로 생기거나 바뀌었을 때 이미 설치된 것
  --   장치·정책마다 경보 1건(해당 프로그램 이름은 details 에 모음). 너무 넓은 정책이 경보를 쏟아내지 않도록
  --   한 번 실행에 500건까지만 만들고 나머지는 다음 실행(1분 뒤)에 이어서 만든다(이미 만든 것은 dedup 으로 건너뜀).
  --   비교는 장치×프로그램 행이 아니라 "이름·버전·게시자 묶음"으로 한 번만 한 뒤 장치로 펼친다(수십만 행에서도 가볍게).
  with pol as (
    select * from software_policies where kind = 'prohibited' and enabled
  ), titles as (
    -- 새로 설치된 묶음(모든 정책과 비교) + 최근 하루 안에 만들거나 바꾼 정책(모든 묶음과 비교)
    select distinct p.id as policy_id, s.tenant_id, s.name, s.version, s.publisher, false as all_devices
      from device_software s join pol p on p.tenant_id = s.tenant_id
     where s.first_seen_at > v_from
    union
    select distinct p.id, s.tenant_id, s.name, s.version, s.publisher, true
      from pol p join device_software s on s.tenant_id = p.tenant_id
     where p.updated_at > v_from - interval '1 day'
  ), matched as (
    select t.* from titles t join pol p on p.id = t.policy_id
     where edr_sw_matches(t.name, t.version, t.publisher, p)
  ), hit as (
    select s.tenant_id, s.device_id, p.id as policy_id, p.severity, p.name_pattern, p.reason,
           array_agg(s.name order by s.name) as names, array_agg(nullif(s.version, '') order by s.name) as versions,
           min(s.publisher) as publisher, min(s.install_date) as install_date, min(s.first_seen_at) as first_seen_at
    from matched m
    join device_software s on s.tenant_id = m.tenant_id and s.name = m.name and s.version = m.version
                          and s.publisher is not distinct from m.publisher
                          and (m.all_devices or s.first_seen_at > v_from)
    join pol p on p.id = m.policy_id
    where not exists (select 1 from alerts a where a.tenant_id = s.tenant_id
                      and a.dedup_key = format('SW001:%s:%s', s.device_id, p.id))
    group by s.tenant_id, s.device_id, p.id, p.severity, p.name_pattern, p.reason
    order by min(s.first_seen_at) desc
    limit 500
  )
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
  select h.tenant_id, h.device_id, 'EDR-SW-001', h.severity,
         '허용되지 않은 소프트웨어 설치: ' || h.names[1] || case when cardinality(h.names) > 1 then format(' 외 %s개', cardinality(h.names) - 1) else '' end,
         jsonb_build_object('software', h.names[1], 'software_all', to_jsonb(h.names[1:20]), 'version', h.versions[1],
                            'publisher', h.publisher, 'policy_id', h.policy_id, 'policy', h.name_pattern, 'reason', nullif(h.reason, ''),
                            'install_date', h.install_date, 'first_seen_at', h.first_seen_at),
         format('SW001:%s:%s', h.device_id, h.policy_id)
  from hit h
  on conflict (tenant_id, dedup_key) do nothing;
  get diagnostics c = row_count; n := n + c;

  -- EDR-POS-001 : 보안 기능이 꺼짐 — 경보 대상 점검 항목이 통과(또는 주의) → 실패로 바뀐 순간 1건
  --   처음부터 꺼져 있던 PC 는 경보 대신 "보안 상태" 화면의 점수·목록으로 관리한다
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
  select dp.tenant_id, dp.device_id, 'EDR-POS-001',
         case dp.check_id when 'firewall' then 'medium' else 'high' end,
         '보안 기능 꺼짐: ' || ck.title,
         jsonb_build_object('check_id', dp.check_id, 'check', ck.title, 'detail', dp.detail,
                            'previous', dp.prev_status, 'changed_at', dp.changed_at),
         format('POS001:%s:%s:%s', dp.device_id, dp.check_id, extract(epoch from dp.failing_since)::bigint)
  from device_posture dp
  join posture_checks ck on ck.check_id = dp.check_id
  left join posture_policies pp on pp.tenant_id = dp.tenant_id and pp.check_id = dp.check_id
  where dp.status = 'fail' and dp.prev_status in ('pass', 'warn') and dp.changed_at > v_from
    and ck.drift_alert and coalesce(pp.enabled, ck.default_enabled)
  on conflict (tenant_id, dedup_key) do nothing;
  get diagnostics c = row_count; n := n + c;

  insert into detection_state (name, last_run) values ('main', v_to)
  on conflict (name) do update set last_run = excluded.last_run;
  return n;
end $$;

revoke all on function public.edr_run_detections() from public, anon, authenticated;
grant execute on function public.edr_run_detections() to edr_enricher;

-- ---------------------------------------------------------------------
-- 7-2) 탐지 규칙 카탈로그
-- ---------------------------------------------------------------------
insert into public.detection_rules values
 ('EDR-IOC-001', '위협 지표(해시) 일치', '등록한 위협 지표(SHA-256)와 같은 파일이 실행되거나 자동 실행 항목으로 등록됨. 지표를 등록하면 최근 7일을 소급해 찾음', 'high', 'Execution', 'T1204.002', 'User Execution: Malicious File', '프로세스 + 자동 실행 + 위협 지표', true, now()),
 ('EDR-IOC-002', '위협 지표(IP) 통신', '등록한 위협 지표 IP·대역과 통신하거나 그 주소에서 로그온 시도. 지표를 등록하면 최근 7일을 소급해 찾음', 'high', 'Command and Control', 'T1071', 'Application Layer Protocol', '네트워크 + 보안 이벤트 + 위협 지표', true, now()),
 ('EDR-SW-001', '허용되지 않은 소프트웨어 설치', '관리자가 금지한 소프트웨어(예: 승인되지 않은 원격 제어 도구)가 설치되어 있음. 정책을 새로 만들면 이미 설치된 PC 도 찾음', 'medium', 'Command and Control', 'T1219', 'Remote Access Software', '자산(설치 프로그램)', true, now()),
 ('EDR-POS-001', '보안 기능 꺼짐', '실시간 악성코드 검사·Windows 방화벽이 꺼지거나 평문 자격 증명 저장(WDigest)이 켜짐 — 통과에서 실패로 바뀐 순간', 'high', 'Defense Evasion', 'T1562.001', 'Impair Defenses: Disable or Modify Tools', '보안 상태 점검', true, now())
on conflict (rule_id) do nothing;

-- ---------------------------------------------------------------------
-- 7-3) 유지보수: 소프트웨어 이력은 1년 보관 (동작은 0006 과 같고 한 줄 추가)
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
  insert into detection_state (name, last_run) values ('maintenance', now())
  on conflict (name) do update set last_run = excluded.last_run;
end $$;
revoke all on function public.edr_maintenance(int, int) from public, anon, authenticated;
grant execute on function public.edr_maintenance(int, int) to edr_enricher;

-- ---------------------------------------------------------------------
-- 7-4) 장치 타임라인에 소프트웨어 설치·삭제·업데이트 추가 (나머지는 0004 와 같음)
-- ---------------------------------------------------------------------
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
  union all
  (select observed_at, 'software', case change when 'installed' then 'low' else 'info' end,
          case change when 'installed' then '설치: ' when 'removed' then '삭제: ' else '업데이트: ' end || name
            || coalesce(' ' || nullif(version, ''), ''),
          jsonb_build_object('change', change, 'version', version, 'prev_version', prev_version, 'publisher', publisher)
     from software_changes where device_id = p_device and observed_at > now() - make_interval(hours => p_hours))
  order by 1 desc limit p_limit
$$;

-- ---------------------------------------------------------------------
-- 8-1) 콘솔 조회 함수 (security invoker → 호출한 사용자의 RLS 그대로)
-- ---------------------------------------------------------------------

-- 자산 현황 카드
create or replace function public.console_asset_overview(p_tenant uuid)
returns jsonb language sql stable security invoker set search_path = public as $$
  with inv as (
    select i.* from device_inventory i join devices d on d.id = i.device_id
     where i.tenant_id = p_tenant and d.status = 'active'
  )
  select jsonb_build_object(
    'devices', (select count(*) from devices where tenant_id = p_tenant and status = 'active'),
    'inventoried', (select count(*) from inv),
    'software_titles', (select count(distinct name) from device_software where tenant_id = p_tenant),
    'installs_7d', (select count(*) from software_changes where tenant_id = p_tenant and change = 'installed' and observed_at > now() - interval '7 days'),
    'unsupported', (select count(*) from inv where os_end_of_support < current_date
                      or (os_end_of_support is null and os_build is not null
                          and ((os_product = 'client' and os_build < 19044) or (os_product = 'server' and os_build < 14393)))),
    'ending_90d', (select count(*) from inv where os_end_of_support between current_date and current_date + 90),
    'domain_joined', (select count(*) from inv where domain_joined),
    'low_disk', (select count(*) from inv where disk_free_gb < 10),   -- 시스템 드라이브 남은 공간 10GB 미만
    'os', (select coalesce(jsonb_agg(x order by (x->>'n')::int desc, x->>'label'), '[]'::jsonb) from (
        select jsonb_build_object('label', coalesce(os_label, os_name, '알 수 없음'), 'product', os_product,
                                  'end_of_support', os_end_of_support, 'n', count(*)) x
        from inv group by coalesce(os_label, os_name, '알 수 없음'), os_product, os_end_of_support) y),
    'manufacturers', (select coalesce(jsonb_agg(x order by (x->>'n')::int desc), '[]'::jsonb) from (
        select jsonb_build_object('label', coalesce(manufacturer, '알 수 없음'), 'n', count(*)) x
        from inv group by coalesce(manufacturer, '알 수 없음') order by count(*) desc limit 6) y)
  )
$$;

-- 소프트웨어 목록(이름별, 설치 대수 순). 페이지·검색은 서버에서
create or replace function public.console_software_catalog(p_tenant uuid, p_q text default null, p_limit int default 50, p_offset int default 0)
returns table (name text, publisher text, versions text[], devices bigint, first_seen_at timestamptz, total bigint)
language sql stable security invoker set search_path = public as $$
  select s.name, max(s.publisher), (array_agg(distinct s.version))[1:20], count(distinct s.device_id), min(s.first_seen_at),
         count(*) over ()
  from device_software s
  where s.tenant_id = p_tenant
    and (coalesce(p_q, '') = '' or s.name ilike edr_like(p_q) or coalesce(s.publisher, '') ilike edr_like(p_q))
  group by s.name
  order by count(distinct s.device_id) desc, s.name
  limit least(greatest(p_limit, 1), 200) offset greatest(p_offset, 0)
$$;

-- 한 소프트웨어가 깔린 장치
create or replace function public.console_software_devices(p_tenant uuid, p_name text)
returns table (device_id uuid, hostname text, version text, publisher text, scope text, install_date date, first_seen_at timestamptz)
language sql stable security invoker set search_path = public as $$
  select s.device_id, d.hostname, s.version, s.publisher, s.scope, s.install_date, s.first_seen_at
  from device_software s join devices d on d.id = s.device_id
  where s.tenant_id = p_tenant and s.name = p_name
  order by d.hostname, s.version
  limit 1000
$$;

-- 소프트웨어 정책별 노출(취약 버전·금지 소프트웨어가 깔린 장치 수)
--   장치×프로그램 행(수십만)마다 비교하지 않고, 같은 이름·버전·게시자 묶음(수천)으로 한 번만 비교한다
create or replace function public.console_software_exposure(p_tenant uuid)
returns table (policy_id bigint, kind text, severity text, name_pattern text, publisher_pattern text, fixed_version text,
               reference text, reason text, builtin boolean, enabled boolean, created_at timestamptz,
               software text[], versions text[], devices bigint, device_ids uuid[])
language sql stable security invoker set search_path = public as $$
  with titles as (
    select s.name, s.version, s.publisher, array_agg(s.device_id) as ids
    from device_software s where s.tenant_id = p_tenant
    group by s.name, s.version, s.publisher
  ), hits as (
    select p.id as pid, t.name, t.version, unnest(t.ids) as device_id
    from software_policies p
    join titles t on edr_sw_matches(t.name, t.version, t.publisher, p)
    where p.tenant_id = p_tenant
  )
  select p.id, p.kind, p.severity, p.name_pattern, p.publisher_pattern, p.fixed_version, p.reference, p.reason, p.builtin, p.enabled,
         p.created_at,
         coalesce((array_agg(distinct h.name) filter (where h.name is not null))[1:10], '{}'),
         coalesce((array_agg(distinct h.version) filter (where h.name is not null))[1:10], '{}'),
         count(distinct h.device_id),
         coalesce((array_agg(distinct h.device_id) filter (where h.device_id is not null))[1:200], '{}')
  from software_policies p
  left join hits h on h.pid = p.id
  where p.tenant_id = p_tenant
  group by p.id
  order by count(distinct h.device_id) desc, edr_sev_rank(p.severity) desc, p.id
$$;

-- 보안 상태 요약: 전체 점수, 점수 분포, 항목별 통과·실패, 점수가 낮은 장치
create or replace function public.console_posture_overview(p_tenant uuid)
returns jsonb language sql stable security invoker set search_path = public as $$
  with dev as (
    select d.id, d.hostname, public.edr_posture_score(d.id) as score
    from devices d where d.tenant_id = p_tenant and d.status = 'active'
  ), pol as (
    select c.*, coalesce(pp.enabled, c.default_enabled) as enabled
    from posture_checks c left join posture_policies pp on pp.tenant_id = p_tenant and pp.check_id = c.check_id
  )
  select jsonb_build_object(
    'score', (select round(avg(score))::int from dev where score is not null),
    'devices', (select count(*) from dev),
    'scored', (select count(*) from dev where score is not null),
    'buckets', (select jsonb_build_array(
        count(*) filter (where score < 50), count(*) filter (where score >= 50 and score < 70),
        count(*) filter (where score >= 70 and score < 90), count(*) filter (where score >= 90)) from dev),
    'checks', (select coalesce(jsonb_agg(jsonb_build_object(
        'check_id', pol.check_id, 'title', pol.title, 'description', pol.description, 'remediation', pol.remediation,
        'category', pol.category, 'weight', pol.weight, 'enabled', pol.enabled, 'drift_alert', pol.drift_alert,
        'default_enabled', pol.default_enabled, 'source', pol.source,
        'pass', coalesce(x.pass, 0), 'warn', coalesce(x.warn, 0), 'fail', coalesce(x.fail, 0), 'unknown', coalesce(x.unknown, 0))
        order by pol.sort), '[]'::jsonb)
      from pol left join (
        select dp.check_id,
               count(*) filter (where dp.status = 'pass') as pass, count(*) filter (where dp.status = 'warn') as warn,
               count(*) filter (where dp.status = 'fail') as fail, count(*) filter (where dp.status = 'unknown') as unknown
        from device_posture dp join devices d on d.id = dp.device_id
        where dp.tenant_id = p_tenant and d.status = 'active'
        group by dp.check_id) x on x.check_id = pol.check_id),
    'worst', (select coalesce(jsonb_agg(w order by (w->>'score')::int, w->>'hostname'), '[]'::jsonb) from (
        select jsonb_build_object('device_id', dev.id, 'hostname', dev.hostname, 'score', dev.score,
                 'fails', (select coalesce(jsonb_agg(pol.title order by pol.sort), '[]'::jsonb)
                             from device_posture dp join pol on pol.check_id = dp.check_id
                            where dp.device_id = dev.id and dp.status = 'fail' and pol.enabled)) w
        from dev where dev.score is not null order by dev.score, dev.hostname limit 8) z)
  )
$$;

-- 보안 상태 장치 목록: 항목을 고르면 그 항목이 해당 상태인 장치, 안 고르면 점수가 낮은 순
create or replace function public.console_posture_devices(p_tenant uuid, p_check text default null, p_status text default 'fail',
                                                          p_limit int default 50, p_offset int default 0)
returns table (device_id uuid, hostname text, score int, status text, detail text, checked_at timestamptz,
               fails text[], total bigint)
language sql stable security invoker set search_path = public as $$
  with base as (
    select d.id, d.hostname, public.edr_posture_score(d.id) as score, dp.status, dp.detail, dp.checked_at
    from devices d
    left join device_posture dp on dp.device_id = d.id and dp.check_id = p_check
    where d.tenant_id = p_tenant and d.status = 'active'
      and (p_check is null or dp.status = coalesce(p_status, 'fail'))
  )
  select b.id, b.hostname, b.score, b.status, b.detail, b.checked_at,
         array(select c.title from device_posture x join posture_checks c on c.check_id = x.check_id
                left join posture_policies pp on pp.tenant_id = p_tenant and pp.check_id = x.check_id
               where x.device_id = b.id and x.status = 'fail' and coalesce(pp.enabled, c.default_enabled) order by c.sort),
         count(*) over ()
  from base b
  order by b.score nulls last, b.hostname
  limit least(greatest(p_limit, 1), 200) offset greatest(p_offset, 0)
$$;

-- 장치 1대의 점검 결과(모든 항목, 아직 보고 안 된 항목은 status 없음)
create or replace function public.console_device_posture(p_device uuid)
returns table (check_id text, title text, description text, remediation text, category text, weight int, enabled boolean,
               drift_alert boolean, status text, detail text, changed_at timestamptz, failing_since timestamptz, checked_at timestamptz)
language sql stable security invoker set search_path = public as $$
  select c.check_id, c.title, c.description, c.remediation, c.category, c.weight, coalesce(pp.enabled, c.default_enabled),
         c.drift_alert, dp.status, dp.detail, dp.changed_at, dp.failing_since, dp.checked_at
  from devices d
  cross join posture_checks c
  left join device_posture dp on dp.device_id = d.id and dp.check_id = c.check_id
  left join posture_policies pp on pp.tenant_id = d.tenant_id and pp.check_id = c.check_id
  where d.id = p_device
  order by c.sort
$$;

revoke all on function public.console_asset_overview(uuid), public.console_software_catalog(uuid, text, int, int),
  public.console_software_devices(uuid, text), public.console_software_exposure(uuid), public.console_posture_overview(uuid),
  public.console_posture_devices(uuid, text, text, int, int), public.console_device_posture(uuid),
  public.edr_posture_score(uuid) from public, anon;
grant execute on function public.console_asset_overview(uuid), public.console_software_catalog(uuid, text, int, int),
  public.console_software_devices(uuid, text), public.console_software_exposure(uuid), public.console_posture_overview(uuid),
  public.console_posture_devices(uuid, text, text, int, int), public.console_device_posture(uuid),
  public.edr_posture_score(uuid) to authenticated;
grant execute on function public.edr_posture_score(uuid) to grafana_reader;

-- ---------------------------------------------------------------------
-- 8-2) 권한(RLS)
-- ---------------------------------------------------------------------
alter table public.device_inventory  enable row level security;
alter table public.device_software   enable row level security;
alter table public.software_changes  enable row level security;
alter table public.device_posture    enable row level security;
alter table public.posture_policies  enable row level security;
alter table public.software_policies enable row level security;
alter table public.iocs              enable row level security;

-- 텔레메트리(자산·보안 상태): 조직 구성원은 읽기만. 쓰기는 수집 서버의 저장 함수(security definer)만
grant select on public.device_inventory, public.device_software, public.software_changes, public.device_posture
  to authenticated, grafana_reader;
create policy inv_select    on public.device_inventory for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy sw_select     on public.device_software  for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy swc_select    on public.software_changes for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy pos_select    on public.device_posture   for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy grafana_read  on public.device_inventory for select to grafana_reader using (true);
create policy grafana_read  on public.device_software  for select to grafana_reader using (true);
create policy grafana_read  on public.software_changes for select to grafana_reader using (true);
create policy grafana_read  on public.device_posture   for select to grafana_reader using (true);

-- 점검 항목 사용 여부: 구성원은 보기, 소유자·관리자만 바꾸기
grant select, insert, update, delete on public.posture_policies to authenticated;
grant select on public.posture_policies to grafana_reader;
create policy pp_select on public.posture_policies for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy pp_manage on public.posture_policies for all to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])) and updated_by = (select auth.uid()));
create policy grafana_read on public.posture_policies for select to grafana_reader using (true);

-- 소프트웨어 정책: 구성원은 보기, 소유자·관리자만 만들기·바꾸기·지우기
grant select on public.software_policies to authenticated, grafana_reader;
grant insert (tenant_id, kind, name_pattern, publisher_pattern, fixed_version, severity, reference, reason, enabled, created_by)
  on public.software_policies to authenticated;
grant update (name_pattern, publisher_pattern, fixed_version, severity, reference, reason, enabled) on public.software_policies to authenticated;
grant delete on public.software_policies to authenticated;
create policy swp_select on public.software_policies for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy swp_insert on public.software_policies for insert to authenticated
  with check ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])) and created_by = (select auth.uid()));
create policy swp_update on public.software_policies for update to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])));
create policy swp_delete on public.software_policies for delete to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])));
create policy grafana_read on public.software_policies for select to grafana_reader using (true);

-- 위협 지표: 구성원은 보기, 분석가 이상이 등록·수정·삭제(상용 EDR 과 같은 권한)
grant select on public.iocs to authenticated, grafana_reader;
grant insert (tenant_id, type, value, severity, description, source, enabled, expires_at, created_by) on public.iocs to authenticated;
grant update (severity, description, source, enabled, expires_at) on public.iocs to authenticated;
grant delete on public.iocs to authenticated;
create policy ioc_select on public.iocs for select to authenticated using (tenant_id in (select public.my_tenant_ids()));
create policy ioc_insert on public.iocs for insert to authenticated
  with check ((select public.has_tenant_role(tenant_id, array['owner', 'admin', 'analyst'])) and created_by = (select auth.uid()));
create policy ioc_update on public.iocs for update to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin', 'analyst'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner', 'admin', 'analyst'])));
create policy ioc_delete on public.iocs for delete to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin', 'analyst'])));
create policy grafana_read on public.iocs for select to grafana_reader using (true);

-- ---------------------------------------------------------------------
-- 8-3) 감사 기록: 위협 지표 · 소프트웨어 정책 · 점검 항목 사용 여부
--   탐지가 바꾸는 적중 횟수 같은 시스템 갱신은 남기지 않는다(바뀐 항목이 없으면 기록 안 함)
-- ---------------------------------------------------------------------
create or replace function public.edr_audit_config()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  uid   uuid := (select auth.uid());
  o     jsonb := case when tg_op in ('UPDATE', 'DELETE') then to_jsonb(old) end;
  nw    jsonb := case when tg_op in ('INSERT', 'UPDATE') then to_jsonb(new) end;
  r     jsonb := coalesce(nw, o);
  diff  jsonb;
  act   text;
  ttype text;
  label text;
  tid   text;
  verb  text := case tg_op when 'INSERT' then 'create' when 'DELETE' then 'delete' else 'update' end;
begin
  if uid is null then
    return null;
  end if;
  case tg_table_name
  when 'iocs' then
    ttype := 'ioc'; tid := r->>'id'; label := (case r->>'type' when 'ip' then 'IP ' else '해시 ' end) || (r->>'value');
    diff := case tg_op when 'UPDATE' then edr_audit_diff(o, nw, array['enabled', 'severity', 'description', 'source', 'expires_at'])
                       else jsonb_build_object('severity', r->'severity', 'description', r->'description', 'expires_at', r->'expires_at') end;
  when 'software_policies' then
    ttype := 'sw_policy'; tid := r->>'id';
    label := (case r->>'kind' when 'prohibited' then '금지: ' else '취약: ' end) || (r->>'name_pattern');
    diff := case tg_op when 'UPDATE' then edr_audit_diff(o, nw, array['enabled', 'name_pattern', 'publisher_pattern', 'fixed_version', 'severity', 'reference', 'reason'])
                       else jsonb_build_object('kind', r->'kind', 'fixed_version', r->'fixed_version', 'severity', r->'severity') end;
  when 'posture_policies' then
    ttype := 'posture_policy'; tid := r->>'check_id';
    select title into label from posture_checks where check_id = r->>'check_id';
    diff := case tg_op when 'UPDATE' then edr_audit_diff(o, nw, array['enabled']) else jsonb_build_object('enabled', r->'enabled') end;
    verb := case when tg_op = 'DELETE' then 'reset' when (r->>'enabled')::boolean then 'enable' else 'disable' end;
  else
    return null;
  end case;
  if tg_op = 'UPDATE' and diff = '{}'::jsonb then
    return null;
  end if;
  act := ttype || '.' || verb;
  insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
  values ((r->>'tenant_id')::uuid, uid, (select email from auth.users where id = uid), act, ttype, tid, label, diff);
  return null;
end $$;
revoke all on function public.edr_audit_config() from public, anon, authenticated;

create trigger trg_audit after insert or update or delete on public.iocs
  for each row execute function public.edr_audit_config();
create trigger trg_audit after insert or update or delete on public.software_policies
  for each row execute function public.edr_audit_config();
create trigger trg_audit after insert or update or delete on public.posture_policies
  for each row execute function public.edr_audit_config();
