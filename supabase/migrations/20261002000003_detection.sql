-- =====================================================================
-- 탐지 규칙(서버 측) — 에이전트는 수집만, 판단은 DB 에서 한다.
--   * pg_cron 이 1분마다 public.edr_run_detections() 실행
--   * 워터마크(detection_state)로 "마지막 실행 이후 들어온 데이터"만 본다 → 늦게 도착한 데이터도 놓치지 않음
--   * dedup_key 유니크 제약으로 같은 경보를 중복 생성하지 않는다
--   * 악성 해시 판정은 트리거로 즉시 경보
-- 규칙 ID 체계: EDR-<영역>-<번호>  (docs/ARCHITECTURE.md 의 규칙표와 일치시킬 것)
-- =====================================================================

create table if not exists public.detection_state (
  name      text primary key,
  last_run  timestamptz not null
);
alter table public.detection_state enable row level security;   -- 정책 없음 = 소유자 외 접근 불가

-- 공인 IP 여부 (사설·루프백·링크로컬·CGNAT 제외)
create or replace function public.edr_is_public_ip(ip inet)
returns boolean language sql immutable as $$
  select ip is not null and not (
       ip << '10.0.0.0/8' or ip << '172.16.0.0/12' or ip << '192.168.0.0/16'
    or ip << '127.0.0.0/8' or ip << '169.254.0.0/16' or ip << '100.64.0.0/10'
    or ip <<= '::1/128' or ip << 'fc00::/7' or ip << 'fe80::/10'
  )
$$;

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

  -- EDR-AUTH-001 : 무차별 대입(4625) — 같은 장치·같은 출발지에서 10분 내 10회 이상 실패
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
  select s.tenant_id, s.device_id, 'EDR-AUTH-001', 'high',
         '로그온 무차별 대입 의심 (' || coalesce(host(s.src_ip), '출발지 미상') || ')',
         jsonb_build_object('src_ip', host(s.src_ip), 'failures', count(*),
                            'users', jsonb_agg(distinct s.target_user),
                            'logon_types', jsonb_agg(distinct s.logon_type),
                            'window_minutes', 10),
         format('AUTH001:%s:%s:%s', s.device_id, coalesce(host(s.src_ip), '-'),
                to_char(date_trunc('hour', v_to), 'YYYYMMDDHH24'))
  from security_events s
  where s.event_id = 4625 and s.event_time > v_to - interval '10 minutes'
  group by s.tenant_id, s.device_id, s.src_ip
  having count(*) >= 10
     and max(s.ingested_at) > v_from
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

  -- EDR-LOG-001 : 감사/시스템 로그 삭제 (흔적 지우기)
  -- EDR-PERSIST-001 : 새 서비스 설치(7045)
  -- EDR-PERSIST-003 : 예약 작업 생성/변경(4698/4702)
  -- EDR-ACCT-001 : 계정 생성(4720), EDR-ACCT-002 : 보안 그룹 구성원 추가(4728/4732/4756)
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
                to_char(a.observed_at, 'YYYYMMDDHH24MISS'))  -- 재전송된 같은 변경은 1건
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

-- EDR-MAL-001 : 해시 평판이 악성/의심으로 바뀌면, 최근 7일 내 그 파일을 실행한 장치마다 경보
create or replace function public.edr_on_hash_verdict()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if new.verdict in ('malicious', 'suspicious') and new.verdict is distinct from old.verdict then
    insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
    select distinct on (p.tenant_id, p.device_id)
           p.tenant_id, p.device_id, 'EDR-MAL-001',
           case new.verdict when 'malicious' then 'critical' else 'medium' end,
           '평판 ' || case new.verdict when 'malicious' then '악성' else '의심' end || ' 파일 실행: ' || p.name,
           jsonb_build_object('sha256', new.sha256, 'path', p.path, 'vt_malicious', new.vt_malicious,
                              'vt_total', new.vt_total, 'sources', new.sources),
           format('MAL001:%s:%s', p.device_id, new.sha256)
    from process_events p
    where p.sha256 = new.sha256 and p.observed_at > now() - interval '7 days'
    order by p.tenant_id, p.device_id, p.observed_at desc
    on conflict (tenant_id, dedup_key) do nothing;
  end if;
  return new;
end $$;

drop trigger if exists trg_hash_verdict on public.file_hashes;
create trigger trg_hash_verdict after update of verdict on public.file_hashes
  for each row execute function public.edr_on_hash_verdict();

revoke all on function public.edr_run_detections() from public, anon, authenticated;
revoke all on function public.edr_on_hash_verdict() from public, anon, authenticated;
grant execute on function public.edr_run_detections() to edr_enricher;  -- pg_cron 이 없을 때 enricher 가 대신 호출

-- ---------- 스케줄 (pg_cron: Supabase 대시보드 > Database > Extensions 에서 활성화) ----------
do $$
begin
  begin
    create extension if not exists pg_cron;
  exception when others then
    raise notice 'pg_cron 을 사용할 수 없습니다. 탐지는 services/enricher 의 주기 호출로 대체하세요.';
  end;
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('edr-detections',  '* * * * *',  'select public.edr_run_detections()');
    perform cron.schedule('edr-partitions',  '10 0 * * *', 'select public.edr_ensure_partitions(2)');
    perform cron.schedule('edr-retention',   '20 0 * * *', 'select public.edr_drop_old_partitions(3)');
  end if;
end $$;
