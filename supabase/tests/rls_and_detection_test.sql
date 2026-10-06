-- 로컬 검증용: supabase 스텁 위에서 RLS 격리·탐지 규칙·해시 트리거를 확인한다.
-- 실행: psql -v ON_ERROR_STOP=1 -f tests/rls_and_detection_test.sql  (테스트 DB 에서만!)
\set QUIET 1
begin;
insert into auth.users values ('11111111-1111-1111-1111-111111111111'), ('22222222-2222-2222-2222-222222222222');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사'), ('bbbbbbbb-0000-0000-0000-000000000002', 'B사');
insert into tenant_members values
  ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'analyst'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '22222222-2222-2222-2222-222222222222', 'viewer');

-- ingest 역할로 텔레메트리 입력
set local role edr_ingest;
insert into devices (id, tenant_id, hostname, token_hash) values
  ('d0000000-0000-0000-0000-00000000000a', 'aaaaaaaa-0000-0000-0000-000000000001', 'PC-A', '\x01'),
  ('d0000000-0000-0000-0000-00000000000b', 'bbbbbbbb-0000-0000-0000-000000000002', 'PC-B', '\x02');
-- 무차별 대입 12회 + 성공 1회 (A사)
insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time, target_user, logon_type, src_ip)
select 'aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', 'Security', g, 4625,
       now() - interval '3 minutes' + g * interval '5 seconds', 'administrator', 10, '203.0.113.7'
from generate_series(1, 12) g;
insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time, target_user, logon_type, src_ip)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', 'Security', 100, 4624, now(), 'administrator', 10, '203.0.113.7');
-- 재전송 중복은 무시되어야 함
insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time, logon_type, src_ip)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', 'Security', 100, 4624,
        now(), 10, '203.0.113.7')  -- now() 는 트랜잭션 안에서 동일
on conflict do nothing;
-- B사: 로그 삭제
insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time)
values ('bbbbbbbb-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-00000000000b', 'Security', 5, 1102, now());
-- 프로세스 + 해시
insert into file_hashes (sha256) values (repeat('ab', 32));
insert into tenant_file_hashes (tenant_id, sha256) values ('aaaaaaaa-0000-0000-0000-000000000001', repeat('ab', 32));
insert into process_events (tenant_id, device_id, observed_at, pid, name, path, sha256)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', now(), 4321, 'evil.exe', 'C:\Users\x\AppData\evil.exe', repeat('ab', 32));
insert into net_connections (tenant_id, device_id, observed_at, proto, direction, local_ip, local_port, remote_ip, remote_port, is_external)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', now(), 'tcp4', 'inbound', '10.0.0.5', 3389, '198.51.100.9', 50123, true);
insert into autorun_changes (tenant_id, device_id, change, location, entry_name, command, image_path, observed_at)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', 'added', 'HKCU\Run', 'updater',
        'C:\Users\x\AppData\Roaming\upd.exe', 'C:\Users\x\AppData\Roaming\upd.exe', now());
reset role;

-- 탐지 실행 (pg_cron 대신 수동)
select 'detections created' as step, public.edr_run_detections() as n;
-- 두 번째 실행은 중복을 만들지 않아야 함
select 'second run (expect 0)' as step, public.edr_run_detections() as n;

-- enricher 가 악성 판정 → 트리거로 경보
set local role edr_enricher;
update file_hashes set verdict = 'malicious', vt_malicious = 41, vt_total = 70 where sha256 = repeat('ab', 32);
reset role;

select rule_id, severity, title from alerts order by rule_id;

-- RLS: A사 analyst 는 A사만 본다
set local role authenticated;
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true);
select 'A analyst sees alerts' as check, count(*) , string_agg(distinct tenant_id::text, ',') from alerts;
select 'A analyst sees hashes' as check, count(*) from file_hashes;
update alerts set status = 'acknowledged' where rule_id = 'EDR-AUTH-001';
select 'A ack ok' as check, count(*) from alerts where status = 'acknowledged';
-- 경보 내용(title) 변조 시도 → 권한 오류여야 함
do $$ begin
  update alerts set title = 'hacked';
  raise exception 'FAIL: title update allowed';
exception when insufficient_privilege then raise notice 'OK: title update denied';
end $$;
-- 텔레메트리 삽입 시도 → 거부
do $$ begin
  insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time)
  values ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', 'Security', 999, 1102, now());
  raise exception 'FAIL: insert allowed';
exception when insufficient_privilege then raise notice 'OK: telemetry insert denied';
end $$;
-- 파티션 직접 조회 우회 시도 → 0행
do $$ declare n int; begin
  execute format('select count(*) from public.%I', 'security_events_' || to_char(now(), 'YYYYMM')) into n;
  if n <> 0 then raise exception 'FAIL: partition bypass (% rows)', n; end if;
  raise notice 'OK: direct partition access returns 0 rows';
end $$;

-- B사 viewer: B사 경보만, 해시 0개, 경보 수정 불가
select set_config('request.jwt.claim.sub', '22222222-2222-2222-2222-222222222222', true);
select 'B viewer sees alerts' as check, count(*), string_agg(distinct rule_id, ',') from alerts;
select 'B viewer sees hashes (expect 0)' as check, count(*) from file_hashes;
update alerts set status = 'closed';
select 'B closed (expect 0)' as check, count(*) from alerts where status = 'closed';

-- anon: 아무것도 못 봄
reset role;
set local role anon;
do $$ begin
  perform count(*) from alerts;
  raise exception 'FAIL: anon read';
exception when insufficient_privilege then raise notice 'OK: anon denied';
end $$;
rollback;

-- =====================================================================
-- 0004: 규칙 끄기 · 예외(억제) · 콘솔 집계 함수 · 현재 프로세스 RLS
-- =====================================================================
begin;
insert into auth.users values ('11111111-1111-1111-1111-111111111111'), ('22222222-2222-2222-2222-222222222222');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사'), ('bbbbbbbb-0000-0000-0000-000000000002', 'B사');
insert into tenant_members values
  ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'admin'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '22222222-2222-2222-2222-222222222222', 'viewer');
insert into devices (id, tenant_id, hostname, token_hash, last_seen_at, health) values
  ('d0000000-0000-0000-0000-00000000000a', 'aaaaaaaa-0000-0000-0000-000000000001', 'PC-A', '\x01', now(), '{"cpu_percent":0.4,"working_set_mb":38.5}'),
  ('d0000000-0000-0000-0000-00000000000b', 'bbbbbbbb-0000-0000-0000-000000000002', 'PC-B', '\x02', now(), null);

-- 규칙 끄기: EDR-LOG-001 비활성화 후 로그 삭제 이벤트 → 경보 없어야 함
update detection_rules set enabled = false where rule_id = 'EDR-LOG-001';
-- 예외: A사 OneDrive 자동실행은 억제
insert into alert_suppressions (tenant_id, rule_id, match, reason)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'EDR-PERSIST-002', '{"entry":"OneDrive"}', '정상 업데이트');

set local role edr_ingest;
insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', 'Security', 1, 1102, now());
insert into autorun_changes (tenant_id, device_id, change, location, entry_name, command, observed_at) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', 'added', 'HKCU\Run', 'OneDrive', 'C:\x\OneDrive.exe', now()),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', 'added', 'HKCU\Run', 'evil', 'C:\Temp\e.exe', now());
insert into processes_current (tenant_id, device_id, pid, name) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-00000000000a', 100, 'a.exe'),
  ('bbbbbbbb-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-00000000000b', 200, 'b.exe');
reset role;
select public.edr_run_detections() \g /dev/null

do $$ declare n int; begin
  select count(*) into n from alerts where rule_id = 'EDR-LOG-001';
  if n <> 0 then raise exception 'FAIL: disabled rule created % alerts', n; end if;
  raise notice 'OK: disabled rule suppressed';
  select count(*) into n from alerts where rule_id = 'EDR-PERSIST-002' and status = 'closed' and resolution = 'suppressed';
  if n <> 1 then raise exception 'FAIL: suppression expected 1 closed, got %', n; end if;
  select count(*) into n from alerts where rule_id = 'EDR-PERSIST-002' and status = 'open';
  if n <> 1 then raise exception 'FAIL: non-matching alert should stay open, got %', n; end if;
  select hit_count into n from alert_suppressions limit 1;
  if n <> 1 then raise exception 'FAIL: hit_count %', n; end if;
  raise notice 'OK: suppression closes matching alert only';
end $$;

set local role authenticated;
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true) \g /dev/null
do $$ declare j jsonb; n int; begin
  j := public.console_overview('aaaaaaaa-0000-0000-0000-000000000001');
  if (j->'devices'->>'total')::int <> 1 or (j->'devices'->>'avg_cpu')::numeric <> 0.4 then raise exception 'FAIL: overview %', j; end if;
  raise notice 'OK: console_overview %', j->'devices';
  -- 다른 조직 id 로 호출해도 RLS 때문에 0
  j := public.console_overview('bbbbbbbb-0000-0000-0000-000000000002');
  if (j->'devices'->>'total')::int <> 0 then raise exception 'FAIL: cross-tenant overview leak'; end if;
  raise notice 'OK: console_overview respects RLS';
  select count(*) into n from processes_current;
  if n <> 1 then raise exception 'FAIL: processes_current visible %', n; end if;
  select count(*) into n from public.console_device_timeline('d0000000-0000-0000-0000-00000000000a');
  if n < 3 then raise exception 'FAIL: timeline rows %', n; end if;
  raise notice 'OK: timeline % rows, processes_current isolated', n;
  perform * from public.console_alert_trend('aaaaaaaa-0000-0000-0000-000000000001', 14);
  perform * from public.console_logon_failures('aaaaaaaa-0000-0000-0000-000000000001', 24);
  -- admin 은 규칙 토글 가능, 경보 판정 기록 가능
  update detection_rules set enabled = true where rule_id = 'EDR-LOG-001';
  update alerts set resolution = 'true_positive', status = 'closed' where rule_id = 'EDR-PERSIST-002' and status = 'open';
  insert into alert_comments (tenant_id, alert_id, author_id, body)
  select tenant_id, id, '11111111-1111-1111-1111-111111111111', '확인 완료' from alerts where resolution = 'true_positive';
  raise notice 'OK: admin toggles rule, triages and comments';
end $$;

-- viewer 는 규칙 토글 불가 (행 0건 갱신)
select set_config('request.jwt.claim.sub', '22222222-2222-2222-2222-222222222222', true) \g /dev/null
do $$ declare n int; begin
  update detection_rules set enabled = false where rule_id = 'EDR-AUTH-001';
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL: viewer toggled rule'; end if;
  raise notice 'OK: viewer cannot toggle rules';
end $$;
rollback;

-- =====================================================================
-- 0005: 인시던트 자동 묶음 · 종결 연쇄 · 엔터티 · ATT&CK 매트릭스 · 저장 쿼리
-- =====================================================================
begin;
insert into auth.users (id) values ('11111111-1111-1111-1111-111111111111'), ('22222222-2222-2222-2222-222222222222');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사'), ('bbbbbbbb-0000-0000-0000-000000000002', 'B사');
insert into tenant_members values
  ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'analyst'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '22222222-2222-2222-2222-222222222222', 'analyst');
insert into devices (id, tenant_id, hostname, token_hash) values
  ('d0000000-0000-0000-0000-00000000000a', 'aaaaaaaa-0000-0000-0000-000000000001', 'WEB-01', '\x01'),
  ('d0000000-0000-0000-0000-00000000000c', 'aaaaaaaa-0000-0000-0000-000000000001', 'DB-01',  '\x03'),
  ('d0000000-0000-0000-0000-00000000000e', 'aaaaaaaa-0000-0000-0000-000000000001', 'HR-PC',  '\x05');

-- WEB-01: 무차별 대입 → 성공 → 자동 실행 (같은 장치 2시간 안 → 1건)
insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key, created_at) values
 ('aaaaaaaa-0000-0000-0000-000000000001','d0000000-0000-0000-0000-00000000000a','EDR-AUTH-001','high','무차별 대입','{"src_ip":"45.1.1.1","users":["administrator"]}','t1', now() - interval '90 minutes'),
 ('aaaaaaaa-0000-0000-0000-000000000001','d0000000-0000-0000-0000-00000000000a','EDR-AUTH-002','critical','로그온 성공','{"src_ip":"45.1.1.1","user":"administrator"}','t2', now() - interval '80 minutes'),
 ('aaaaaaaa-0000-0000-0000-000000000001','d0000000-0000-0000-0000-00000000000a','EDR-PERSIST-002','high','자동 실행','{"entry":"x"}','t3', now() - interval '70 minutes'),
-- DB-01: 같은 출발지 IP → 다른 장치지만 같은 인시던트(확산)
 ('aaaaaaaa-0000-0000-0000-000000000001','d0000000-0000-0000-0000-00000000000c','EDR-AUTH-001','high','무차별 대입','{"src_ip":"45.1.1.1"}','t4', now() - interval '60 minutes'),
-- HR-PC: 관계없는 경보 → 별도 인시던트
 ('aaaaaaaa-0000-0000-0000-000000000001','d0000000-0000-0000-0000-00000000000e','EDR-PERSIST-001','medium','서비스 설치','{"event_id":7045}','t5', now() - interval '30 minutes');
-- 중복(dedup) 경보는 인시던트 개수를 늘리지 않아야 함
insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
values ('aaaaaaaa-0000-0000-0000-000000000001','d0000000-0000-0000-0000-00000000000a','EDR-AUTH-001','high','중복','{}','t1')
on conflict (tenant_id, dedup_key) do nothing;

do $$ declare n int; i record; begin
  select count(*) into n from incidents;
  if n <> 2 then raise exception 'FAIL: expected 2 incidents, got %', n; end if;
  select * into i from incidents where 'd0000000-0000-0000-0000-00000000000a' = any (device_ids);
  if i.alert_count <> 4 or i.severity <> 'critical' or cardinality(i.device_ids) <> 2 or not ('45.1.1.1' = any (i.ips))
     or cardinality(i.tactics) < 2 or i.title not like '다단계 공격 의심:%' and cardinality(i.tactics) >= 3 then
    raise exception 'FAIL: incident aggregate %', row_to_json(i);
  end if;
  raise notice 'OK: grouped by device + shared IP (alerts %, devices %, tactics %, title "%")', i.alert_count, cardinality(i.device_ids), i.tactics, i.title;
  select count(*) into n from alerts where incident_id is null;
  if n <> 0 then raise exception 'FAIL: % alerts not attached', n; end if;
  raise notice 'OK: every alert attached, dedup did not inflate';
end $$;

set local role authenticated;
select set_config('request.jwt.claim.sub', '11111111-1111-1111-1111-111111111111', true) \g /dev/null
do $$ declare inc bigint; n int; j jsonb; begin
  select id into inc from incidents where 'd0000000-0000-0000-0000-00000000000a' = any (device_ids);
  perform public.console_close_incident(inc, 'true_positive');
  select count(*) into n from alerts where incident_id = inc and status <> 'closed';
  if n <> 0 then raise exception 'FAIL: % alerts still open after incident close', n; end if;
  raise notice 'OK: closing incident closes its alerts';
  j := public.console_entity('aaaaaaaa-0000-0000-0000-000000000001', 'ip', '45.1.1.1', 30);
  if j is null or (j ? 'devices') is false then raise exception 'FAIL: entity %', j; end if;
  perform * from public.console_attack_matrix('aaaaaaaa-0000-0000-0000-000000000001', 30);
  select count(*) into n from public.console_attack_matrix('aaaaaaaa-0000-0000-0000-000000000001', 30) where hits > 0;
  if n < 3 then raise exception 'FAIL: matrix hits %', n; end if;
  raise notice 'OK: entity profile + attack matrix (% techniques hit)', n;
  insert into saved_queries (tenant_id, name, query, created_by) values ('aaaaaaaa-0000-0000-0000-000000000001', 'enc ps', 'process.cmdline ~ "-enc"', '11111111-1111-1111-1111-111111111111');
end $$;

-- B사 분석가는 A사 인시던트를 보거나 닫을 수 없다
select set_config('request.jwt.claim.sub', '22222222-2222-2222-2222-222222222222', true) \g /dev/null
do $$ declare n int; inc bigint; begin
  select count(*) into n from incidents;
  if n <> 0 then raise exception 'FAIL: cross-tenant incidents visible'; end if;
  select count(*) into n from saved_queries;
  if n <> 0 then raise exception 'FAIL: cross-tenant saved queries visible'; end if;
  begin
    perform public.console_close_incident(1, 'benign');
    raise exception 'FAIL: cross-tenant close allowed';
  exception when insufficient_privilege then raise notice 'OK: cross-tenant incident isolated';
  end;
end $$;
rollback;

-- =====================================================================
-- 0006: 늦게 도착한 무차별 대입, 유지보수 작업, 시스템 상태, 감사 기록
-- =====================================================================
begin;
insert into auth.users (id, email) values
  ('55555555-5555-5555-5555-555555555555', 'admin@a.example'),
  ('66666666-6666-6666-6666-666666666666', 'analyst@a.example'),
  ('77777777-7777-7777-7777-777777777777', 'admin@b.example');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사'), ('bbbbbbbb-0000-0000-0000-000000000002', 'B사');
insert into tenant_members values
  ('aaaaaaaa-0000-0000-0000-000000000001', '55555555-5555-5555-5555-555555555555', 'admin'),
  ('aaaaaaaa-0000-0000-0000-000000000001', '66666666-6666-6666-6666-666666666666', 'analyst'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '77777777-7777-7777-7777-777777777777', 'admin');
insert into devices (id, tenant_id, hostname, token_hash) values
  ('d0000000-0000-0000-0000-0000000000f1', 'aaaaaaaa-0000-0000-0000-000000000001', 'LATE-PC', '\xf1'),
  ('d0000000-0000-0000-0000-0000000000f2', 'aaaaaaaa-0000-0000-0000-000000000001', 'SLOW-PC', '\xf2'),
  ('d0000000-0000-0000-0000-0000000000f3', 'aaaaaaaa-0000-0000-0000-000000000001', 'NINE-PC', '\xf3');
insert into detection_state (name, last_run) values ('main', now()) on conflict (name) do update set last_run = excluded.last_run;

-- 40분 전에 일어난 12회 실패가 이제야 들어옴(스풀 재전송) → 탐지되어야 함
insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time, target_user, logon_type, src_ip)
select 'aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-0000000000f1', 'Security', 9000 + g, 4625,
       now() - interval '40 minutes' + g * interval '10 seconds', 'administrator', 10, '198.51.100.77'
from generate_series(1, 12) g;
-- 2시간에 걸쳐 띄엄띄엄 12회(10분 창 안에 10회 미만) → 탐지 안 됨
insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time, target_user, logon_type, src_ip)
select 'aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-0000000000f2', 'Security', 9100 + g, 4625,
       now() - interval '2 hours' + g * interval '10 minutes', 'kim', 3, '198.51.100.78'
from generate_series(1, 12) g;
-- 10분 안에 9회 → 탐지 안 됨
insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time, target_user, logon_type, src_ip)
select 'aaaaaaaa-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-0000000000f3', 'Security', 9200 + g, 4625,
       now() - interval '5 minutes' + g * interval '10 seconds', 'lee', 3, '198.51.100.79'
from generate_series(1, 9) g;

do $$ declare n int; d jsonb; begin
  perform public.edr_run_detections();
  select count(*), max(details::text)::jsonb into n, d from alerts
   where rule_id = 'EDR-AUTH-001' and device_id = 'd0000000-0000-0000-0000-0000000000f1';
  if n <> 1 or (d->>'delayed')::boolean is not true or (d->>'failures')::int < 10 then
    raise exception 'FAIL: late brute force (n=%, details=%)', n, d;
  end if;
  select count(*) into n from alerts where rule_id = 'EDR-AUTH-001'
     and device_id in ('d0000000-0000-0000-0000-0000000000f2', 'd0000000-0000-0000-0000-0000000000f3');
  if n <> 0 then raise exception 'FAIL: % false brute-force alerts (spread / 9 times)', n; end if;
  perform public.edr_run_detections();  -- 다시 돌려도 중복 없음
  select count(*) into n from alerts where rule_id = 'EDR-AUTH-001';
  if n <> 1 then raise exception 'FAIL: AUTH-001 duplicated (%)', n; end if;
  raise notice 'OK: late-arriving brute force detected once, spread/9-time bursts ignored';
end $$;

-- 유지보수: enricher 역할로 실행 가능, 파티션 2개월 앞까지 준비, 실행 시각 기록
set local role edr_enricher;
select public.edr_maintenance() \g /dev/null
reset role;
do $$ declare t timestamptz; m text := to_char(date_trunc('month', now()) + interval '2 months', 'YYYYMM'); begin
  select last_run into t from detection_state where name = 'maintenance';
  if t is null then raise exception 'FAIL: maintenance not recorded'; end if;
  if to_regclass('public.security_events_' || m) is null or to_regclass('public.process_events_' || m) is null then
    raise exception 'FAIL: partition % missing', m;
  end if;
  raise notice 'OK: maintenance by enricher (partitions through %)', m;
end $$;

-- 시스템 상태: 구성원은 조회, 다른 조직은 거부
set local role authenticated;
select set_config('request.jwt.claim.sub', '66666666-6666-6666-6666-666666666666', true) \g /dev/null
do $$ declare j jsonb; begin
  j := public.console_system_status('aaaaaaaa-0000-0000-0000-000000000001');
  if j->>'detections_at' is null or j->>'maintenance_at' is null or (j->>'partitions_until')::date <= current_date then
    raise exception 'FAIL: system status %', j;
  end if;
  begin
    perform public.console_system_status('bbbbbbbb-0000-0000-0000-000000000002');
    raise exception 'FAIL: other tenant status allowed';
  exception when insufficient_privilege then null;
  end;
  raise notice 'OK: system status (scheduler %, partitions until %)', j->>'scheduler', j->>'partitions_until';
end $$;

-- 감사 기록: 분석가가 인시던트를 조사 중으로 → 종결(경보 일괄 종결은 한 줄로)
do $$ declare inc bigint; begin
  select id into inc from incidents where 'd0000000-0000-0000-0000-0000000000f1' = any (device_ids);
  perform public.console_update_incident(inc, 'acknowledged', true);
  if exists (select 1 from alerts where incident_id = inc and (status <> 'acknowledged' or assigned_to is distinct from '66666666-6666-6666-6666-666666666666')) then
    raise exception 'FAIL: incident ack did not cascade to alerts';
  end if;
  perform public.console_close_incident(inc, 'true_positive');
end $$;
-- 관리자가 규칙 끄기 + 등록키 발급
select set_config('request.jwt.claim.sub', '55555555-5555-5555-5555-555555555555', true) \g /dev/null
update detection_rules set enabled = false where rule_id = 'EDR-PERSIST-003';
select public.create_enrollment_key('aaaaaaaa-0000-0000-0000-000000000001', '감사 테스트', 5, 7) \g /dev/null

do $$ declare acts text; n int; begin
  -- 관리자는 조회 가능
  select string_agg(action || ':' || coalesce(actor_email, '?'), ',' order by id) into acts from audit_log;
  if acts is distinct from 'incident.update:analyst@a.example,incident.close:analyst@a.example,rule.disable:admin@a.example,enrollment_key.create:admin@a.example' then
    raise exception 'FAIL: audit trail %', acts;
  end if;
  -- 아무도 고치거나 지울 수 없음
  begin
    delete from audit_log;
    raise exception 'FAIL: audit delete allowed';
  exception when insufficient_privilege then null;
  end;
  begin
    update audit_log set action = 'x';
    raise exception 'FAIL: audit update allowed';
  exception when insufficient_privilege then null;
  end;
  raise notice 'OK: audit trail recorded (%), immutable', acts;
end $$;

-- 분석가·다른 조직 관리자는 A사 감사 기록을 볼 수 없음, 시스템 동작(경보 생성)은 기록 안 됨
select set_config('request.jwt.claim.sub', '66666666-6666-6666-6666-666666666666', true) \g /dev/null
do $$ declare n int; begin
  select count(*) into n from audit_log;
  if n <> 0 then raise exception 'FAIL: analyst sees % audit rows', n; end if;
end $$;
select set_config('request.jwt.claim.sub', '77777777-7777-7777-7777-777777777777', true) \g /dev/null
do $$ declare n int; begin
  select count(*) into n from audit_log;
  if n <> 0 then raise exception 'FAIL: other tenant admin sees % audit rows', n; end if;
  raise notice 'OK: audit visible to tenant admins only';
end $$;
reset role;
do $$ declare n int; begin
  select count(*) into n from audit_log where action like 'alert.%';
  if n <> 0 then raise exception 'FAIL: system/cascade alert changes audited (%)', n; end if;
  raise notice 'OK: system actions and incident cascade not duplicated in audit';
end $$;
rollback;

-- =====================================================================
-- 0007: 회사 계정(AD) SSO — Supabase Auth 가 Keycloak 로그인 때 쓰는 모양 그대로 auth.users 를 흉내 낸다
--   raw_app_meta_data = {"provider": "keycloak", "providers": ["keycloak"]}
--   raw_user_meta_data.custom_claims.groups = Keycloak 의 groups 클레임(AD 그룹 → 역할)
-- =====================================================================
begin;
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사'), ('bbbbbbbb-0000-0000-0000-000000000002', 'B사');
insert into sso_group_roles (tenant_id, idp_group, role) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'EDR-Admins', 'admin'),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'EDR-Analysts', 'analyst'),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'EDR-Viewers', 'viewer');

-- 로그인 흉내: 처음이면 INSERT, 다시 로그인하면 메타데이터 UPDATE
create function pg_temp.sso_login(uid uuid, mail text, groups jsonb) returns void language sql as $$
  insert into auth.users (id, email, raw_app_meta_data, raw_user_meta_data)
  values (uid, mail, '{"provider":"keycloak","providers":["keycloak"]}',
          jsonb_build_object('iss', 'http://host.docker.internal:8080/realms/bing', 'email', mail,
                             'custom_claims', jsonb_build_object('groups', groups, 'preferred_username', split_part(mail, '@', 1))))
  on conflict (id) do update set raw_user_meta_data = excluded.raw_user_meta_data, raw_app_meta_data = excluded.raw_app_meta_data
$$;
create function pg_temp.role_of(uid uuid) returns text language sql as $$
  select coalesce((select role || '/' || managed_by from tenant_members where user_id = uid and tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001'), '-')
$$;

select pg_temp.sso_login('5a000000-0000-0000-0000-000000000001', 'kim.admin@bing.test', '["default-roles-bing","offline_access","EDR-Admins"]');
select pg_temp.sso_login('5a000000-0000-0000-0000-000000000002', 'lee.analyst@bing.test', '["/EDR-Analysts"]');
select pg_temp.sso_login('5a000000-0000-0000-0000-000000000003', 'park.viewer@bing.test', '["edr-viewers","EDR-Analysts"]');
select pg_temp.sso_login('5a000000-0000-0000-0000-000000000004', 'choi.none@bing.test', '["default-roles-bing"]');
-- 이메일·비밀번호 계정은 SSO 동기화 대상이 아님
insert into auth.users (id, email, raw_app_meta_data, raw_user_meta_data)
values ('5a000000-0000-0000-0000-000000000005', 'pw.user@bing.test', '{"provider":"email","providers":["email"]}', '{"custom_claims":{"groups":["EDR-Admins"]}}');

do $$ begin
  if pg_temp.role_of('5a000000-0000-0000-0000-000000000001') <> 'admin/sso' then raise exception 'FAIL: kim %', pg_temp.role_of('5a000000-0000-0000-0000-000000000001'); end if;
  if pg_temp.role_of('5a000000-0000-0000-0000-000000000002') <> 'analyst/sso' then raise exception 'FAIL: lee (group path) %', pg_temp.role_of('5a000000-0000-0000-0000-000000000002'); end if;
  if pg_temp.role_of('5a000000-0000-0000-0000-000000000003') <> 'analyst/sso' then raise exception 'FAIL: park (highest of two, case-insensitive) %', pg_temp.role_of('5a000000-0000-0000-0000-000000000003'); end if;
  if pg_temp.role_of('5a000000-0000-0000-0000-000000000004') <> '-' then raise exception 'FAIL: choi (no group) got access'; end if;
  if pg_temp.role_of('5a000000-0000-0000-0000-000000000005') <> '-' then raise exception 'FAIL: email account synced from metadata'; end if;
  raise notice 'OK: AD groups → console roles (admin/analyst/highest-of-many/none/email ignored)';
end $$;

-- 다시 로그인: 그룹 변경 → 역할 변경, 그룹에서 빠짐 → 접근 제거
select pg_temp.sso_login('5a000000-0000-0000-0000-000000000001', 'kim.admin@bing.test', '["EDR-Viewers"]');
select pg_temp.sso_login('5a000000-0000-0000-0000-000000000002', 'lee.analyst@bing.test', '[]');
-- Supabase Auth 가 custom_claims 를 안 주는 옛 버전이면 = 그룹 없음 → 닫힌 쪽으로 동작
update auth.users set raw_user_meta_data = '{"email":"park.viewer@bing.test"}' where id = '5a000000-0000-0000-0000-000000000003';
do $$ declare acts text; begin
  if pg_temp.role_of('5a000000-0000-0000-0000-000000000001') <> 'viewer/sso' then raise exception 'FAIL: kim downgrade %', pg_temp.role_of('5a000000-0000-0000-0000-000000000001'); end if;
  if pg_temp.role_of('5a000000-0000-0000-0000-000000000002') <> '-' then raise exception 'FAIL: lee not removed'; end if;
  if pg_temp.role_of('5a000000-0000-0000-0000-000000000003') <> '-' then raise exception 'FAIL: missing claims kept access'; end if;
  select string_agg(action || ':' || target_label, ',' order by id) into acts from audit_log where actor_email = 'AD 그룹 동기화';
  if acts not like 'member.sso_add:kim.admin@bing.test,member.sso_add:lee.analyst@bing.test,member.sso_add:park.viewer@bing.test,member.sso_role:kim.admin@bing.test,member.sso_remove:lee.analyst@bing.test,member.sso_remove:park.viewer@bing.test' then
    raise exception 'FAIL: sso audit %', acts;
  end if;
  raise notice 'OK: re-login syncs role changes/removals, audited as "AD 그룹 동기화"';
end $$;

-- 수동으로 넣은 구성원(소유자 등)은 SSO 로 로그인해도 역할이 바뀌지 않는다
insert into auth.users (id, email) values ('5a000000-0000-0000-0000-000000000006', 'owner@bing.test');
insert into tenant_members values ('aaaaaaaa-0000-0000-0000-000000000001', '5a000000-0000-0000-0000-000000000006', 'owner', now(), 'manual');
select pg_temp.sso_login('5a000000-0000-0000-0000-000000000006', 'owner@bing.test', '["EDR-Viewers"]');
select pg_temp.sso_login('5a000000-0000-0000-0000-000000000006', 'owner@bing.test', '[]');
do $$ begin
  if pg_temp.role_of('5a000000-0000-0000-0000-000000000006') <> 'owner/manual' then raise exception 'FAIL: manual member changed %', pg_temp.role_of('5a000000-0000-0000-0000-000000000006'); end if;
  raise notice 'OK: manual members untouched by SSO sync';
end $$;

-- 대응표 권한: 구성원은 보기, 관리자만 바꾸기, 바꾸면 감사 기록
set local role authenticated;
select set_config('request.jwt.claim.sub', '5a000000-0000-0000-0000-000000000001', true) \g /dev/null  -- kim: 지금 viewer
do $$ declare n int; begin
  select count(*) into n from sso_group_roles;
  if n <> 3 then raise exception 'FAIL: member cannot read mapping (%)', n; end if;
  begin
    insert into sso_group_roles (tenant_id, idp_group, role) values ('aaaaaaaa-0000-0000-0000-000000000001', 'Domain Users', 'viewer');
    raise exception 'FAIL: viewer changed mapping';
  exception when insufficient_privilege then null;
  end;
  select count(*) into n from public.console_members('aaaaaaaa-0000-0000-0000-000000000001') where managed_by = 'sso';
  if n <> 1 then raise exception 'FAIL: console_members managed_by (%)', n; end if;
end $$;
select set_config('request.jwt.claim.sub', '5a000000-0000-0000-0000-000000000006', true) \g /dev/null  -- 소유자
insert into sso_group_roles (tenant_id, idp_group, role) values ('aaaaaaaa-0000-0000-0000-000000000001', 'EDR-Auditors', 'viewer');
reset role;
do $$ begin
  if not exists (select 1 from audit_log where action = 'sso_map.create' and actor_email = 'owner@bing.test') then
    raise exception 'FAIL: mapping change not audited';
  end if;
  raise notice 'OK: mapping readable by members, editable by owner/admin only, audited';
end $$;
rollback;

-- =====================================================================
-- 0008: 자산 인벤토리 · 보안 상태 · 소프트웨어 정책 · 위협 지표(IOC)
-- =====================================================================
begin;
insert into auth.users (id, email) values
  ('6a000000-0000-0000-0000-000000000001', 'admin@a.example'),
  ('6a000000-0000-0000-0000-000000000002', 'analyst@a.example'),
  ('6a000000-0000-0000-0000-000000000003', 'viewer@a.example'),
  ('6a000000-0000-0000-0000-000000000004', 'owner@b.example');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사'), ('bbbbbbbb-0000-0000-0000-000000000002', 'B사');
insert into tenant_members (tenant_id, user_id, role) values
  ('aaaaaaaa-0000-0000-0000-000000000001', '6a000000-0000-0000-0000-000000000001', 'admin'),
  ('aaaaaaaa-0000-0000-0000-000000000001', '6a000000-0000-0000-0000-000000000002', 'analyst'),
  ('aaaaaaaa-0000-0000-0000-000000000001', '6a000000-0000-0000-0000-000000000003', 'viewer'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '6a000000-0000-0000-0000-000000000004', 'owner');
insert into devices (id, tenant_id, hostname, token_hash) values
  ('d8000000-0000-0000-0000-00000000000a', 'aaaaaaaa-0000-0000-0000-000000000001', 'PC-A1', '\x81'),
  ('d8000000-0000-0000-0000-00000000000c', 'aaaaaaaa-0000-0000-0000-000000000001', 'PC-A2', '\x83'),
  ('d8000000-0000-0000-0000-00000000000b', 'bbbbbbbb-0000-0000-0000-000000000002', 'PC-B1', '\x82');

do $$ begin
  if edr_version_cmp('6.22', '6.23') <> -1 or edr_version_cmp('6.23.0', '6.23') <> 0 or edr_version_cmp('24.09', '24.8') <> 1
     or edr_version_cmp('10.0.19045.1', '10.0.9999') <> 1 or edr_version_cmp('', '1') <> -1 then
    raise exception 'FAIL: version compare';
  end if;
  if (select count(*) from software_policies where builtin) <> 10 then raise exception 'FAIL: builtin policies per tenant'; end if;
  raise notice 'OK: version compare, builtin software policies seeded per tenant';
end $$;

-- 수집 서버 역할로 자산 정보(기준선) 저장
set local role edr_ingest;
select edr_apply_inventory('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000a', '{
  "collected_at": "2026-10-01T09:00:00Z",
  "os": {"name": "Windows 11 Pro", "edition": "Professional", "display_version": "23H2", "build": 22631, "ubr": 4602, "install_type": "Client", "arch": "x64"},
  "hardware": {"manufacturer": "LENOVO", "model": "20XW", "serial": "PF3ABC12", "cpu": "Intel(R) Core(TM) i5", "cores": 8, "memory_mb": 16384, "disk_total_gb": 476.3, "disk_free_gb": 21.4},
  "domain": "BING", "domain_joined": true, "last_user": "BING\\kim",
  "adapters": [{"name": "Ethernet", "mac": "00:11:22:33:44:55", "ips": ["10.0.0.21"]}],
  "software": [
    {"name": "WinRAR 6.22 (64-bit)", "version": "6.22.0", "publisher": "win.rar GmbH", "install_date": "20240105"},
    {"name": "7-Zip 24.09 (x64)", "version": "24.09", "publisher": "Igor Pavlov"},
    {"name": "Old Viewer", "version": "1.0", "publisher": "X"},
    {"name": "Old Viewer", "version": "1.0", "publisher": "X"},
    {"name": "", "version": "9"}
  ]}'::jsonb);
select edr_apply_inventory('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000c', '{
  "os": {"name": "Windows 11 Enterprise", "edition": "Enterprise", "build": 26100, "install_type": "Client"},
  "software": [{"name": "Notepad++", "version": "8.6"}]}'::jsonb);
do $$ begin
  begin
    perform edr_apply_inventory('bbbbbbbb-0000-0000-0000-000000000002', 'd8000000-0000-0000-0000-00000000000a', '{}'::jsonb);
    raise exception 'FAIL: inventory accepted for device of another tenant';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;
do $$ declare r record; begin
  select * into r from device_inventory where device_id = 'd8000000-0000-0000-0000-00000000000a';
  if r.software_count <> 3 or r.os_label <> 'Windows 11 23H2' or r.os_end_of_support <> '2025-11-11' or r.serial_number <> 'PF3ABC12' then
    raise exception 'FAIL: inventory row % % % %', r.software_count, r.os_label, r.os_end_of_support, r.serial_number;
  end if;
  if (select count(*) from software_changes) <> 0 then raise exception 'FAIL: baseline recorded as changes'; end if;
  select status, detail into r from device_posture where device_id = 'd8000000-0000-0000-0000-00000000000a' and check_id = 'os_supported';
  if r.status <> 'fail' then raise exception 'FAIL: 23H2 Pro should be unsupported (%)', r.status; end if;
  select status into r from device_posture where device_id = 'd8000000-0000-0000-0000-00000000000c' and check_id = 'os_supported';
  if r.status <> 'pass' then raise exception 'FAIL: 24H2 Enterprise should be supported (%)', r.status; end if;
  raise notice 'OK: inventory baseline (dedupe, empty names dropped, no change history), OS lifecycle by edition, tenant check';
end $$;

-- 두 번째 자산 정보: WinRAR 업데이트, Old Viewer 삭제, AnyDesk 설치
set local role edr_ingest;
select edr_apply_inventory('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000a', '{
  "os": {"name": "Windows 11 Pro", "edition": "Professional", "build": 26200, "install_type": "Client"},
  "software": [
    {"name": "WinRAR 6.22 (64-bit)", "version": "6.24.0", "publisher": "win.rar GmbH"},
    {"name": "7-Zip 24.09 (x64)", "version": "24.09", "publisher": "Igor Pavlov"},
    {"name": "AnyDesk", "version": "9.0.1", "publisher": "AnyDesk Software GmbH", "scope": "user"}
  ]}'::jsonb);
reset role;
do $$ declare acts text; begin
  select string_agg(change || ':' || name || ':' || coalesce(prev_version, '') || '>' || coalesce(version, ''), ',' order by change, name) into acts from software_changes;
  if acts <> 'installed:AnyDesk:>9.0.1,removed:Old Viewer:>1.0,updated:WinRAR 6.22 (64-bit):6.22.0>6.24.0' then
    raise exception 'FAIL: software changes %', acts;
  end if;
  if (select status from device_posture where device_id = 'd8000000-0000-0000-0000-00000000000a' and check_id = 'os_supported') <> 'pass' then
    raise exception 'FAIL: upgrade to 25H2 not reflected';
  end if;
  raise notice 'OK: software install/remove/update history, OS upgrade re-evaluated';
end $$;

-- 보안 상태: 통과 → 실패로 바뀐 순간만 경보, 처음부터 실패·점수 제외 항목은 경보 없음
set local role edr_ingest;
select edr_apply_posture('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000a',
  '[{"id":"av_realtime","status":"pass","detail":"Microsoft Defender"},{"id":"firewall","status":"pass"},{"id":"uac","status":"pass"},
    {"id":"wdigest","status":"pass"},{"id":"smb1","status":"fail","detail":"SMB1=1"},{"id":"os_supported","status":"fail"},
    {"id":"no_such_check","status":"fail"},{"id":"lsa_protection","status":"fail"}]'::jsonb);
select edr_apply_posture('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000c',
  '[{"id":"av_realtime","status":"fail","detail":"실시간 감시 꺼짐"},{"id":"firewall","status":"pass"}]'::jsonb);
reset role;
do $$ declare s int; begin
  -- 가중치: av 25 + firewall 20 + os 20 + uac 10 + wdigest 10 + smb1 10(실패) → 85/95 (lsa_protection 은 기본 제외, 모르는 항목·서버 항목은 무시)
  s := edr_posture_score('d8000000-0000-0000-0000-00000000000a');
  if s <> 89 then raise exception 'FAIL: posture score % (expect 89)', s; end if;
  if (select status from device_posture where device_id = 'd8000000-0000-0000-0000-00000000000a' and check_id = 'os_supported') <> 'pass' then
    raise exception 'FAIL: agent overwrote server-side check';
  end if;
  raise notice 'OK: posture score (weights, disabled-by-default excluded, unknown/server checks ignored from agent)';
end $$;
select 'posture drift baseline (expect 0 POS)' as step, public.edr_run_detections();
set local role edr_ingest;
select edr_apply_posture('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000a',
  '[{"id":"av_realtime","status":"fail","detail":"실시간 보호 꺼짐(DisableRealtimeMonitoring=1)"},{"id":"firewall","status":"pass"},{"id":"smb1","status":"fail"}]'::jsonb);
select edr_apply_posture('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000c',
  '[{"id":"av_realtime","status":"fail"}]'::jsonb);
reset role;
select 'posture drift' as step, public.edr_run_detections();
select 'posture drift rerun (expect 0)' as step, public.edr_run_detections();
do $$ declare r record; begin
  if (select count(*) from alerts where rule_id = 'EDR-POS-001') <> 1 then
    raise exception 'FAIL: POS-001 count %', (select count(*) from alerts where rule_id = 'EDR-POS-001');
  end if;
  select * into r from alerts where rule_id = 'EDR-POS-001';
  if r.device_id <> 'd8000000-0000-0000-0000-00000000000a' or r.severity <> 'high' or r.details->>'previous' <> 'pass' or r.incident_id is null then
    raise exception 'FAIL: POS-001 alert %', row_to_json(r);
  end if;
  raise notice 'OK: EDR-POS-001 only on pass→fail drift, once, grouped into incident';
end $$;

-- 소프트웨어 노출 + 금지 소프트웨어(관리자가 정책을 만들면 이미 설치된 PC 도 경보)
set local role authenticated;
select set_config('request.jwt.claim.sub', '6a000000-0000-0000-0000-000000000003', true) \g /dev/null  -- 뷰어
do $$ begin
  begin
    insert into software_policies (tenant_id, kind, name_pattern, created_by) values ('aaaaaaaa-0000-0000-0000-000000000001', 'prohibited', 'AnyDesk', '6a000000-0000-0000-0000-000000000003');
    raise exception 'FAIL: viewer created software policy';
  exception when insufficient_privilege then null;
  end;
  begin
    insert into iocs (tenant_id, type, value, created_by) values ('aaaaaaaa-0000-0000-0000-000000000001', 'ip', '203.0.113.9', '6a000000-0000-0000-0000-000000000003');
    raise exception 'FAIL: viewer created IOC';
  exception when insufficient_privilege then null;
  end;
  if (select count(*) from device_software) <> 4 then raise exception 'FAIL: viewer software rows %', (select count(*) from device_software); end if;
end $$;
select set_config('request.jwt.claim.sub', '6a000000-0000-0000-0000-000000000004', true) \g /dev/null  -- 다른 조직
do $$ begin
  if (select count(*) from device_inventory) + (select count(*) from device_software) + (select count(*) from device_posture)
     + (select count(*) from software_changes) <> 0 then
    raise exception 'FAIL: other tenant sees asset data';
  end if;
  if (select count(*) from public.console_software_catalog('aaaaaaaa-0000-0000-0000-000000000001')) <> 0 then raise exception 'FAIL: catalog leak'; end if;
end $$;
select set_config('request.jwt.claim.sub', '6a000000-0000-0000-0000-000000000001', true) \g /dev/null  -- 관리자
insert into software_policies (tenant_id, kind, name_pattern, severity, reason, created_by)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'prohibited', 'anydesk', 'high', '승인되지 않은 원격 제어 도구', '6a000000-0000-0000-0000-000000000001');
insert into posture_policies (tenant_id, check_id, enabled, updated_by)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'smb1', false, '6a000000-0000-0000-0000-000000000001');
do $$ declare r record; n int; begin
  select * into r from public.console_software_exposure('aaaaaaaa-0000-0000-0000-000000000001') where name_pattern = 'WinRAR';
  if r.devices <> 0 then raise exception 'FAIL: WinRAR 6.24 flagged vulnerable'; end if;
  select * into r from public.console_software_exposure('aaaaaaaa-0000-0000-0000-000000000001') where name_pattern = 'anydesk';
  if r.devices <> 1 or r.software <> '{AnyDesk}' then raise exception 'FAIL: prohibited exposure %', row_to_json(r); end if;
  if public.edr_posture_score('d8000000-0000-0000-0000-00000000000a') <> 71 then
    raise exception 'FAIL: score after disabling smb1 % (expect 71 = 60/85)', public.edr_posture_score('d8000000-0000-0000-0000-00000000000a');
  end if;
  select count(*) into n from public.console_posture_devices('aaaaaaaa-0000-0000-0000-000000000001', 'av_realtime', 'fail');
  if n <> 2 then raise exception 'FAIL: posture devices by check %', n; end if;
  if (public.console_posture_overview('aaaaaaaa-0000-0000-0000-000000000001')->>'scored')::int <> 2 then raise exception 'FAIL: posture overview'; end if;
  if (public.console_asset_overview('aaaaaaaa-0000-0000-0000-000000000001')->>'inventoried')::int <> 2 then raise exception 'FAIL: asset overview'; end if;
  if (select count(*) from public.console_device_posture('d8000000-0000-0000-0000-00000000000a')) <> (select count(*) from posture_checks) then
    raise exception 'FAIL: device posture rows';
  end if;
  if not exists (select 1 from public.console_device_timeline('d8000000-0000-0000-0000-00000000000a', 72) where kind = 'software' and title like '설치: AnyDesk%') then
    raise exception 'FAIL: software change not in device timeline';
  end if;
end $$;
reset role;
select 'prohibited software' as step, public.edr_run_detections();
do $$ begin
  if (select count(*) from alerts where rule_id = 'EDR-SW-001') <> 1 then raise exception 'FAIL: SW-001 count'; end if;
  if (select severity from alerts where rule_id = 'EDR-SW-001') <> 'high' then raise exception 'FAIL: SW-001 severity from policy'; end if;
  if (select string_agg(action, ',' order by id) from audit_log where actor_email = 'admin@a.example') <> 'sw_policy.create,posture_policy.disable' then
    raise exception 'FAIL: config audit %', (select string_agg(action, ',' order by id) from audit_log);
  end if;
  raise notice 'OK: software exposure (fixed versions, prohibited), EDR-SW-001 from new policy, posture policy, RLS, audit';
end $$;

-- 위협 지표: 등록하면 7일 소급, 이후 새 데이터는 탐지 실행 때. 너무 넓은 대역 거부, 값 정리
set local role edr_ingest;
insert into process_events (tenant_id, device_id, observed_at, pid, name, path, sha256)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000a', now() - interval '3 days', 800, 'dropper.exe', 'C:\Users\kim\Downloads\dropper.exe', repeat('cd', 32));
insert into net_connections (tenant_id, device_id, observed_at, proto, direction, local_ip, local_port, remote_ip, remote_port, process_name, is_external)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000a', now() - interval '1 day', 'tcp4', 'outbound', '10.0.0.21', 50000, '198.51.100.77', 443, 'dropper.exe', true);
reset role;
set local role authenticated;
select set_config('request.jwt.claim.sub', '6a000000-0000-0000-0000-000000000002', true) \g /dev/null  -- 분석가
insert into iocs (tenant_id, type, value, severity, description, created_by)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'sha256', upper(repeat('cd', 32)), 'critical', '피싱 메일 첨부 드로퍼', '6a000000-0000-0000-0000-000000000002'),
       ('aaaaaaaa-0000-0000-0000-000000000001', 'ip', '198.51.100.0/24', 'high', 'C2 대역', '6a000000-0000-0000-0000-000000000002'),
       ('aaaaaaaa-0000-0000-0000-000000000001', 'ip', '203.0.113.50/32', 'medium', '', '6a000000-0000-0000-0000-000000000002');
do $$ begin
  begin
    insert into iocs (tenant_id, type, value, created_by) values ('aaaaaaaa-0000-0000-0000-000000000001', 'ip', '10.0.0.0/8', '6a000000-0000-0000-0000-000000000002');
    raise exception 'FAIL: too broad range accepted';
  exception when check_violation then null;
  end;
  begin
    insert into iocs (tenant_id, type, value, created_by) values ('aaaaaaaa-0000-0000-0000-000000000001', 'sha256', 'not-a-hash', '6a000000-0000-0000-0000-000000000002');
    raise exception 'FAIL: bad hash accepted';
  exception when check_violation then null;
  end;
  if (select string_agg(value, ',' order by id) from iocs) <> repeat('cd', 32) || ',198.51.100.0/24,203.0.113.50' then
    raise exception 'FAIL: ioc normalize %', (select string_agg(value, ',' order by id) from iocs);
  end if;
  if (select string_agg(rule_id || ':' || severity, ',' order by rule_id) from alerts where rule_id like 'EDR-IOC-%') <> 'EDR-IOC-001:critical,EDR-IOC-002:high' then
    raise exception 'FAIL: IOC retro alerts %', (select string_agg(rule_id || ':' || severity, ',') from alerts where rule_id like 'EDR-IOC-%');
  end if;
  if (select hit_count from iocs where type = 'sha256') <> 1 then raise exception 'FAIL: ioc hit_count'; end if;
end $$;
reset role;
-- 이후 들어온 데이터: 다른 장치에서 같은 해시 실행 + 지표 IP 에서 로그온 시도
set local role edr_ingest;
insert into process_events (tenant_id, device_id, observed_at, pid, name, sha256)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000c', now(), 900, 'invoice.exe', repeat('cd', 32)),
       ('bbbbbbbb-0000-0000-0000-000000000002', 'd8000000-0000-0000-0000-00000000000b', now(), 901, 'invoice.exe', repeat('cd', 32));
insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time, target_user, logon_type, src_ip)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000c', 'Security', 77, 4625, now(), 'admin', 3, '203.0.113.50');
reset role;
select 'ioc new data' as step, public.edr_run_detections();
select 'ioc rerun (expect 0)' as step, public.edr_run_detections();
do $$ declare r record; begin
  if (select count(*) from alerts where rule_id = 'EDR-IOC-001') <> 2 then raise exception 'FAIL: IOC-001 on new device'; end if;
  if exists (select 1 from alerts where rule_id like 'EDR-IOC-%' and tenant_id = 'bbbbbbbb-0000-0000-0000-000000000002') then
    raise exception 'FAIL: IOC matched another tenant';
  end if;
  select * into r from alerts where rule_id = 'EDR-IOC-002' and details->>'src_ip' = '203.0.113.50';
  if r.id is null or r.severity <> 'medium' then raise exception 'FAIL: IOC-002 logon source'; end if;
  if (select hit_count from iocs where type = 'sha256') <> 2 then raise exception 'FAIL: ioc hit_count after detection'; end if;
  if (select count(*) from audit_log where action = 'ioc.create' and actor_email = 'analyst@a.example') <> 3 then raise exception 'FAIL: ioc audit'; end if;
  if exists (select 1 from audit_log where action = 'ioc.update') then raise exception 'FAIL: hit_count update audited'; end if;
  raise notice 'OK: IOC retro 7d on create, new data on detection run, tenant isolation, CIDR/logon match, hit counts, audit';
end $$;
-- 지표를 끄면 더 이상 찾지 않는다
update iocs set enabled = false where type = 'sha256';
set local role edr_ingest;
insert into process_events (tenant_id, device_id, observed_at, pid, name, sha256)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd8000000-0000-0000-0000-00000000000a', now(), 901, 'again.exe', repeat('cd', 32));
reset role;
do $$ begin
  perform public.edr_run_detections();
  if (select count(*) from alerts where rule_id = 'EDR-IOC-001') <> 2 then raise exception 'FAIL: disabled IOC still matched'; end if;
  raise notice 'OK: disabled IOC ignored';
end $$;
rollback;

-- =====================================================================
-- 0009: 문서 감사(보안 관리자의 PC 감사) — 위치·건수만 저장, 관리자만, 고지 확인, 감사 기록
-- =====================================================================
begin;
insert into auth.users (id, email) values
  ('6b000000-0000-0000-0000-000000000001', 'admin@a.example'),
  ('6b000000-0000-0000-0000-000000000002', 'analyst@a.example'),
  ('6b000000-0000-0000-0000-000000000004', 'owner@b.example');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사'), ('bbbbbbbb-0000-0000-0000-000000000002', 'B사');
insert into tenant_members (tenant_id, user_id, role) values
  ('aaaaaaaa-0000-0000-0000-000000000001', '6b000000-0000-0000-0000-000000000001', 'admin'),
  ('aaaaaaaa-0000-0000-0000-000000000001', '6b000000-0000-0000-0000-000000000002', 'analyst'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '6b000000-0000-0000-0000-000000000004', 'owner');
insert into devices (id, tenant_id, hostname, token_hash) values
  ('d9000000-0000-0000-0000-00000000000a', 'aaaaaaaa-0000-0000-0000-000000000001', 'PC-A1', '\x91'),
  ('d9000000-0000-0000-0000-00000000000b', 'bbbbbbbb-0000-0000-0000-000000000002', 'PC-B1', '\x92');

-- 정책이 없으면 꺼짐
set local role edr_ingest;
do $$ begin
  if public.edr_device_policy('d9000000-0000-0000-0000-00000000000a') <> '{"doc_scan": {"enabled": false}}'::jsonb then
    raise exception 'FAIL: default policy %', public.edr_device_policy('d9000000-0000-0000-0000-00000000000a');
  end if;
end $$;
reset role;

set local role authenticated;
-- 분석가
select set_config('request.jwt.claim.sub', '6b000000-0000-0000-0000-000000000002', true) \g /dev/null
do $$ begin
  begin
    insert into doc_scan_policies (tenant_id, updated_by) values ('aaaaaaaa-0000-0000-0000-000000000001', '6b000000-0000-0000-0000-000000000002');
    raise exception 'FAIL: analyst created doc scan policy';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.console_doc_overview('aaaaaaaa-0000-0000-0000-000000000001');
    raise exception 'FAIL: analyst read doc overview';
  exception when insufficient_privilege then null;
  end;
  begin
    perform * from public.console_doc_findings('aaaaaaaa-0000-0000-0000-000000000001', 'pii');
    raise exception 'FAIL: analyst read doc findings';
  exception when insufficient_privilege then null;
  end;
end $$;
-- 관리자
select set_config('request.jwt.claim.sub', '6b000000-0000-0000-0000-000000000001', true) \g /dev/null
do $$ begin
  begin
    insert into doc_scan_policies (tenant_id, enabled, updated_by) values ('aaaaaaaa-0000-0000-0000-000000000001', true, '6b000000-0000-0000-0000-000000000001');
    raise exception 'FAIL: enabled without notice confirmation';
  exception when check_violation then null;
  end;
  begin
    insert into doc_scan_policies (tenant_id, updated_by) values ('aaaaaaaa-0000-0000-0000-000000000001', '6b000000-0000-0000-0000-000000000002');
    raise exception 'FAIL: policy saved under someone else';
  exception when insufficient_privilege then null;
  end;
end $$;
insert into doc_scan_policies (tenant_id, enabled, keywords, notice_confirmed_at, notice_confirmed_by, updated_by)
values ('aaaaaaaa-0000-0000-0000-000000000001', true, '{대외비}', now(), '6b000000-0000-0000-0000-000000000001', '6b000000-0000-0000-0000-000000000001');
insert into doc_scan_requests (tenant_id, device_id, requested_by)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'd9000000-0000-0000-0000-00000000000a', '6b000000-0000-0000-0000-000000000001');
do $$ begin
  begin
    insert into doc_scan_requests (tenant_id, device_id, requested_by)
    values ('aaaaaaaa-0000-0000-0000-000000000001', 'd9000000-0000-0000-0000-00000000000b', '6b000000-0000-0000-0000-000000000001');
    raise exception 'FAIL: request for another tenant device';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;

select id as req_id from doc_scan_requests \gset
-- 에이전트가 정책을 받아 감: 요청 번호 포함, 받은 시각 기록
set local role edr_ingest;
do $$ declare j jsonb; begin
  j := public.edr_device_policy('d9000000-0000-0000-0000-00000000000a')->'doc_scan';
  if not (j->>'enabled')::boolean or j->'keywords' <> '["대외비"]'::jsonb or (j->>'request_id') is null or (j->>'stale_days')::int <> 1095
     or length(j->>'version') <> 32 then
    raise exception 'FAIL: device policy %', j;
  end if;
  if (public.edr_device_policy('d9000000-0000-0000-0000-00000000000b')->'doc_scan'->>'enabled')::boolean then
    raise exception 'FAIL: other tenant gets policy';
  end if;
end $$;
-- 검사 결과: 배치 2개(마지막이 final). 허용되지 않은 검출 종류·0건·빈 경로는 버린다
select public.edr_apply_doc_scan('aaaaaaaa-0000-0000-0000-000000000001', 'd9000000-0000-0000-0000-00000000000a', jsonb_build_object(
  'scan_id', 'aaaa0001', 'trigger', 'request', 'request_id', :req_id, 'started_at', now(), 'final', false,
  'files_scanned', 10, 'files_skipped', 1, 'errors', 0, 'findings', jsonb_build_array(
    jsonb_build_object('path', 'C:\Users\kim\Documents\고객명단.xlsx', 'size', 1000, 'modified_at', now() - interval '10 days',
                       'pii', jsonb_build_object('rrn', 12, 'phone', 3, 'secret', 5, 'card', 0)),
    jsonb_build_object('path', 'C:\Users\kim\Documents\옛날.hwp', 'size', 2000, 'modified_at', now() - interval '5 years', 'stale', true),
    jsonb_build_object('path', '', 'pii', jsonb_build_object('rrn', 1))))) \g /dev/null
select public.edr_apply_doc_scan('aaaaaaaa-0000-0000-0000-000000000001', 'd9000000-0000-0000-0000-00000000000a', jsonb_build_object(
  'scan_id', 'aaaa0001', 'trigger', 'request', 'request_id', :req_id, 'started_at', now(), 'final', true,
  'finished_at', now(), 'files_scanned', 5, 'files_skipped', 0, 'errors', 2, 'findings', jsonb_build_array(
    jsonb_build_object('path', 'C:\Users\kim\Desktop\보고서.docx', 'size', 500, 'modified_at', now(), 'keywords', jsonb_build_object('대외비', 2))))) \g /dev/null
do $$ begin
  begin
    perform public.edr_apply_doc_scan('bbbbbbbb-0000-0000-0000-000000000002', 'd9000000-0000-0000-0000-00000000000a', '{"scan_id":"bbbb0001"}');
    raise exception 'FAIL: doc scan stored for wrong tenant';
  exception when insufficient_privilege then null;
  end;
end $$;
reset role;
do $$ declare s record; begin
  if (select count(*) from doc_findings) <> 3 then raise exception 'FAIL: findings count %', (select count(*) from doc_findings); end if;
  if (select pii::text || pii_total from doc_findings where path like '%고객명단%') <> '{"rrn": 12, "phone": 3}15' then
    raise exception 'FAIL: pii filtered %', (select pii from doc_findings where path like '%고객명단%');
  end if;
  select * into s from doc_scans;
  if s.status <> 'done' or s.files_scanned <> 15 or s.files_skipped <> 1 or s.errors <> 2 or s.findings <> 3 then
    raise exception 'FAIL: scan totals %', row_to_json(s);
  end if;
  if (select completed_at is null or picked_at is null or scan_id <> 'aaaa0001' from doc_scan_requests) then raise exception 'FAIL: request not completed'; end if;
end $$;
-- 다음 정기 검사: 고객명단만 다시 보임 → 중간 배치에서는 지우지 않고, final 에서 나머지를 지운다
set local role edr_ingest;
select public.edr_apply_doc_scan('aaaaaaaa-0000-0000-0000-000000000001', 'd9000000-0000-0000-0000-00000000000a', jsonb_build_object(
  'scan_id', 'aaaa0002', 'trigger', 'schedule', 'started_at', now(), 'final', false, 'findings', jsonb_build_array(
    jsonb_build_object('path', 'C:\Users\kim\Documents\고객명단.xlsx', 'pii', jsonb_build_object('rrn', 13))))) \g /dev/null
reset role;
do $$ begin
  if (select count(*) from doc_findings) <> 3 then raise exception 'FAIL: partial scan removed findings'; end if;
end $$;
set local role edr_ingest;
select public.edr_apply_doc_scan('aaaaaaaa-0000-0000-0000-000000000001', 'd9000000-0000-0000-0000-00000000000a',
  '{"scan_id":"aaaa0002","trigger":"schedule","final":true,"findings":[]}') \g /dev/null
do $$ begin
  if (public.edr_device_policy('d9000000-0000-0000-0000-00000000000a')->'doc_scan'->>'request_id') is not null then
    raise exception 'FAIL: completed request still offered';
  end if;
end $$;
reset role;
do $$ begin
  if (select string_agg(path || ':' || pii_total, ',') from doc_findings) <> 'C:\Users\kim\Documents\고객명단.xlsx:13' then
    raise exception 'FAIL: final cleanup %', (select string_agg(path, ',') from doc_findings);
  end if;
end $$;

-- 콘솔: 관리자만, 조회·내보내기 감사(조회는 10분에 한 번)
set local role authenticated;
select set_config('request.jwt.claim.sub', '6b000000-0000-0000-0000-000000000001', true) \g /dev/null
do $$ declare o jsonb; n int; begin
  o := public.console_doc_overview('aaaaaaaa-0000-0000-0000-000000000001');
  if (o->>'pii_files')::int <> 1 or (o->'pii_by_kind'->>'rrn')::int <> 13 or (o->>'devices_scanned')::int <> 1 or (o->>'stale_files')::int <> 0 then
    raise exception 'FAIL: doc overview %', o;
  end if;
  select count(*) into n from public.console_doc_findings('aaaaaaaa-0000-0000-0000-000000000001', 'pii');
  perform * from public.console_doc_findings('aaaaaaaa-0000-0000-0000-000000000001', 'pii', '고객');
  perform * from public.console_doc_findings('aaaaaaaa-0000-0000-0000-000000000001', 'pii', null, null, null, 5000, 0, 'export');
  if n <> 1 then raise exception 'FAIL: findings rows %', n; end if;
  if (select count(*) from public.console_doc_devices('aaaaaaaa-0000-0000-0000-000000000001') where pii_files = 1 and last_status = 'done') <> 1 then
    raise exception 'FAIL: doc devices';
  end if;
  if (select count(*) from doc_findings) <> 1 then raise exception 'FAIL: admin direct read'; end if;
end $$;
-- 분석가
select set_config('request.jwt.claim.sub', '6b000000-0000-0000-0000-000000000002', true) \g /dev/null
do $$ begin
  if (select count(*) from doc_findings) + (select count(*) from doc_scans) + (select count(*) from doc_scan_requests)
     + (select count(*) from doc_scan_policies) <> 0 then
    raise exception 'FAIL: analyst sees doc audit data';
  end if;
end $$;
-- 다른 조직 소유자
select set_config('request.jwt.claim.sub', '6b000000-0000-0000-0000-000000000004', true) \g /dev/null
do $$ begin
  if (select count(*) from doc_findings) <> 0 then raise exception 'FAIL: other tenant sees findings'; end if;
  begin
    perform public.console_doc_overview('aaaaaaaa-0000-0000-0000-000000000001');
    raise exception 'FAIL: other tenant overview';
  exception when insufficient_privilege then null;
  end;
end $$;
select set_config('request.jwt.claim.sub', '6b000000-0000-0000-0000-000000000001', true) \g /dev/null
update doc_scan_policies set enabled = false, updated_by = '6b000000-0000-0000-0000-000000000001', updated_at = now();
update doc_scan_policies set updated_at = now(), updated_by = '6b000000-0000-0000-0000-000000000001';  -- 바뀐 항목 없음 → 기록 안 함
reset role;
do $$ begin
  if (select string_agg(action, ',' order by id) from audit_log) <> 'doc_scan.enable,doc_scan.request,doc_scan.view,doc_scan.export,doc_scan.disable' then
    raise exception 'FAIL: doc audit log %', (select string_agg(action, ',' order by id) from audit_log);
  end if;
  if exists (select 1 from audit_log where changes::text ~ '\d{6}-\d{7}') then raise exception 'FAIL: PII in audit log'; end if;
  raise notice 'OK: doc audit (notice required, admin-only RLS/functions, request→policy→complete, batch merge, final cleanup, view/export audit)';
end $$;
rollback;

-- =====================================================================
-- 0010: PC 조치 목록 — 지금 데이터에서 계산, 담당자·상태, 권한(문서 감사 항목은 관리자만), 감사 기록
-- =====================================================================
begin;
insert into auth.users (id, email) values
  ('6c000000-0000-0000-0000-000000000001', 'admin@a.example'),
  ('6c000000-0000-0000-0000-000000000002', 'analyst@a.example'),
  ('6c000000-0000-0000-0000-000000000003', 'viewer@a.example'),
  ('6c000000-0000-0000-0000-000000000004', 'owner@b.example');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사'), ('bbbbbbbb-0000-0000-0000-000000000002', 'B사');
insert into tenant_members (tenant_id, user_id, role) values
  ('aaaaaaaa-0000-0000-0000-000000000001', '6c000000-0000-0000-0000-000000000001', 'admin'),
  ('aaaaaaaa-0000-0000-0000-000000000001', '6c000000-0000-0000-0000-000000000002', 'analyst'),
  ('aaaaaaaa-0000-0000-0000-000000000001', '6c000000-0000-0000-0000-000000000003', 'viewer'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '6c000000-0000-0000-0000-000000000004', 'owner');
insert into devices (id, tenant_id, hostname, token_hash) values
  ('da000000-0000-0000-0000-00000000000a', 'aaaaaaaa-0000-0000-0000-000000000001', 'PC-A1', '\xa1'),
  ('da000000-0000-0000-0000-00000000000c', 'aaaaaaaa-0000-0000-0000-000000000001', 'PC-A2', '\xa3'),
  ('da000000-0000-0000-0000-00000000000b', 'bbbbbbbb-0000-0000-0000-000000000002', 'PC-B1', '\xa2');
-- 방화벽 실패(점수 반영) + LSA 보호 실패(기본 점수 제외 → 조치 아님), 취약 WinRAR(기본 제공 정책), 개인정보·오래된 문서
insert into device_posture (tenant_id, device_id, check_id, status, failing_since) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'da000000-0000-0000-0000-00000000000a', 'firewall', 'fail', now() - interval '3 days'),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'da000000-0000-0000-0000-00000000000a', 'lsa_protection', 'fail', now()),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'da000000-0000-0000-0000-00000000000c', 'firewall', 'pass', null),
  ('bbbbbbbb-0000-0000-0000-000000000002', 'da000000-0000-0000-0000-00000000000b', 'firewall', 'fail', now());
insert into device_software (tenant_id, device_id, name, version, publisher) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'da000000-0000-0000-0000-00000000000c', 'WinRAR 6.11 (64-bit)', '6.11.0', 'win.rar GmbH'),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'da000000-0000-0000-0000-00000000000a', 'WinRAR 7.01 (64-bit)', '7.01.0', 'win.rar GmbH');
insert into doc_findings (tenant_id, device_id, path, pii, pii_total, scan_id) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'da000000-0000-0000-0000-00000000000c', 'C:\Users\k\Documents\명단.xlsx', '{"rrn": 5}', 5, 'aaaa0001');
insert into doc_findings (tenant_id, device_id, path, stale, size, scan_id) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'da000000-0000-0000-0000-00000000000c', 'C:\Users\k\Documents\옛날.doc', true, 1000, 'aaaa0001');

set local role authenticated;
-- 분석가: 보안·소프트웨어 항목만(문서 감사 항목은 안 보임)
select set_config('request.jwt.claim.sub', '6c000000-0000-0000-0000-000000000002', true) \g /dev/null
do $$ declare got text; begin
  select string_agg(hostname || ':' || kind || ':' || item_key, ',' order by hostname, kind) into got
  from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001');
  if got is distinct from 'PC-A1:posture:firewall,PC-A2:software:' || (select id from software_policies where tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001' and name_pattern ilike 'WinRAR%')::text then
    raise exception 'FAIL: analyst remediation items %', got;
  end if;
  if (public.console_remediation_overview('aaaaaaaa-0000-0000-0000-000000000001')->>'items')::int <> 2 then raise exception 'FAIL: analyst overview'; end if;
  -- 담당자 지정 + 진행 중
  perform public.console_remediation_update('aaaaaaaa-0000-0000-0000-000000000001',
    '[{"device_id":"da000000-0000-0000-0000-00000000000a","kind":"posture","item_key":"firewall","title":"Windows 방화벽"}]',
    'in_progress', '6c000000-0000-0000-0000-000000000002', false, '사용자에게 연락함', current_date + 3);
  begin
    perform public.console_remediation_update('aaaaaaaa-0000-0000-0000-000000000001',
      '[{"device_id":"da000000-0000-0000-0000-00000000000c","kind":"doc_pii","item_key":"pii"}]', 'done');
    raise exception 'FAIL: analyst updated doc item';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.console_remediation_update('aaaaaaaa-0000-0000-0000-000000000001',
      '[{"device_id":"da000000-0000-0000-0000-00000000000b","kind":"posture","item_key":"firewall"}]', 'done');
    raise exception 'FAIL: other tenant device updated';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.console_remediation_update('aaaaaaaa-0000-0000-0000-000000000001',
      '[{"device_id":"da000000-0000-0000-0000-00000000000a","kind":"posture","item_key":"firewall"}]', null, '6c000000-0000-0000-0000-000000000004');
    raise exception 'FAIL: non-member assignee';
  exception when raise_exception then null;
  end;
end $$;
-- 뷰어: 볼 수는 있지만 바꿀 수 없음
select set_config('request.jwt.claim.sub', '6c000000-0000-0000-0000-000000000003', true) \g /dev/null
do $$ begin
  if (select count(*) from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001')) <> 2 then raise exception 'FAIL: viewer list'; end if;
  begin
    perform public.console_remediation_update('aaaaaaaa-0000-0000-0000-000000000001',
      '[{"device_id":"da000000-0000-0000-0000-00000000000a","kind":"posture","item_key":"firewall"}]', 'done');
    raise exception 'FAIL: viewer updated';
  exception when insufficient_privilege then null;
  end;
  begin
    insert into remediation_tracking (tenant_id, device_id, kind, item_key) values ('aaaaaaaa-0000-0000-0000-000000000001', 'da000000-0000-0000-0000-00000000000a', 'software', 'x');
    raise exception 'FAIL: direct insert';
  exception when insufficient_privilege then null;
  end;
end $$;
-- 다른 조직
select set_config('request.jwt.claim.sub', '6c000000-0000-0000-0000-000000000004', true) \g /dev/null
do $$ begin
  begin
    perform * from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001');
    raise exception 'FAIL: other tenant list';
  exception when insufficient_privilege then null;
  end;
  if (select count(*) from remediation_tracking) <> 0 then raise exception 'FAIL: other tenant sees tracking'; end if;
end $$;
-- 관리자: 문서 감사 항목 포함 4건, 여러 건 한꺼번에 처리 → 감사 기록은 대표 한 줄
select set_config('request.jwt.claim.sub', '6c000000-0000-0000-0000-000000000001', true) \g /dev/null
do $$ declare r record; n int; begin
  if (select count(*) from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001')) <> 4 then raise exception 'FAIL: admin list'; end if;
  select * into r from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001', 'posture');
  if r.status <> 'in_progress' or r.assignee <> '6c000000-0000-0000-0000-000000000002' or r.note <> '사용자에게 연락함' or r.guidance is null then
    raise exception 'FAIL: tracking overlay %', row_to_json(r);
  end if;
  n := public.console_remediation_update('aaaaaaaa-0000-0000-0000-000000000001',
    '[{"device_id":"da000000-0000-0000-0000-00000000000c","kind":"doc_pii","item_key":"pii","title":"개인정보 문서 정리 1개"},
      {"device_id":"da000000-0000-0000-0000-00000000000c","kind":"doc_stale","item_key":"stale","title":"오래된 문서 정리 1개"}]',
    null, '6c000000-0000-0000-0000-000000000001');
  if n <> 2 then raise exception 'FAIL: bulk count %', n; end if;
  -- 예외로 두면 기본 목록에서 빠짐
  perform public.console_remediation_update('aaaaaaaa-0000-0000-0000-000000000001',
    '[{"device_id":"da000000-0000-0000-0000-00000000000c","kind":"doc_stale","item_key":"stale"}]', 'exception', null, false, '보관 필요 문서');
  if (select count(*) from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001')) <> 3
     or (select count(*) from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001', null, 'exception')) <> 1 then
    raise exception 'FAIL: exception filter';
  end if;
  if (select count(*) from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001', null, 'active', null, '6c000000-0000-0000-0000-000000000001')) <> 1 then
    raise exception 'FAIL: assignee filter';
  end if;
end $$;
reset role;
-- 방화벽을 고침 → 목록에서 빠지고 "해결 확인됨"
update device_posture set status = 'pass' where device_id = 'da000000-0000-0000-0000-00000000000a' and check_id = 'firewall';
set local role authenticated;
do $$ declare o jsonb; begin
  if exists (select 1 from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001', 'posture')) then raise exception 'FAIL: fixed item still listed'; end if;
  if (select string_agg(hostname || ':' || title, ',') from public.console_remediation('aaaaaaaa-0000-0000-0000-000000000001', null, 'resolved'))
     <> 'PC-A1:Windows 방화벽' then raise exception 'FAIL: resolved view'; end if;
  o := public.console_remediation_overview('aaaaaaaa-0000-0000-0000-000000000001');
  if (o->>'items')::int <> 2 or (o->>'resolved_30d')::int <> 1 or (o->>'unassigned')::int <> 1 or not (o->>'docs')::boolean then
    raise exception 'FAIL: overview %', o;
  end if;
end $$;
reset role;
do $$ begin
  if (select string_agg(action, ',' order by id) from audit_log) <> 'remediation.status,remediation.bulk,remediation.status' then
    raise exception 'FAIL: remediation audit %', (select string_agg(action || ':' || coalesce(target_label, ''), ',' order by id) from audit_log);
  end if;
  raise notice 'OK: remediation list (posture/software/docs computed, enabled checks only), roles, tenant isolation, tracking, exception/resolved, bulk audit';
end $$;
rollback;

-- =====================================================================
-- 0011: 알림 연동 — 경보 → outbox 적재(심각도·규칙 거르기), RLS, 테스트 발송 권한, 감사
-- =====================================================================
begin;
insert into auth.users (id, email) values
  ('6d000000-0000-0000-0000-000000000001', 'admin@a.example'),
  ('6d000000-0000-0000-0000-000000000002', 'analyst@a.example'),
  ('6d000000-0000-0000-0000-000000000004', 'owner@b.example');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사'), ('bbbbbbbb-0000-0000-0000-000000000002', 'B사');
insert into tenant_members (tenant_id, user_id, role) values
  ('aaaaaaaa-0000-0000-0000-000000000001', '6d000000-0000-0000-0000-000000000001', 'admin'),
  ('aaaaaaaa-0000-0000-0000-000000000001', '6d000000-0000-0000-0000-000000000002', 'analyst'),
  ('bbbbbbbb-0000-0000-0000-000000000002', '6d000000-0000-0000-0000-000000000004', 'owner');
insert into devices (id, tenant_id, hostname, token_hash) values
  ('db000000-0000-0000-0000-00000000000a', 'aaaaaaaa-0000-0000-0000-000000000001', 'PC-A1', '\xb1');
-- 채널: 슬랙(high 이상, 전체), 메일(critical 이상), AUTH 규칙만 받는 슬랙(low 이상)
insert into notification_channels (tenant_id, name, kind, target, secret_ref, min_severity, rule_prefixes, enabled) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'SOC 슬랙', 'slack', '#soc', 'SLACK_WEBHOOK_SOC', 'high', '{}', true),
  ('aaaaaaaa-0000-0000-0000-000000000001', '보안 메일', 'email', 'sec@a.example', '', 'critical', '{}', true),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'AUTH 전용', 'slack', '#auth', 'SLACK_WEBHOOK_SOC', 'low', '{EDR-AUTH}', true),
  ('bbbbbbbb-0000-0000-0000-000000000002', 'B사 채널', 'slack', '#b', 'X', 'low', '{}', true);

do $$ declare n int; begin
  -- high AUTH 경보 → 슬랙(high,전체)+AUTH전용(low,AUTH) 2건. 메일(critical)·B사 채널은 제외
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
    values ('aaaaaaaa-0000-0000-0000-000000000001', 'db000000-0000-0000-0000-00000000000a', 'EDR-AUTH-001', 'high', '무차별 대입', '{}', 'n1');
  select count(*) into n from notification_outbox where tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001';
  if n <> 2 then raise exception 'FAIL: high AUTH 경보 적재 수 = % (기대 2)', n; end if;
  if not exists (select 1 from notification_outbox o join notification_channels c on c.id = o.channel_id
                 where c.name = 'SOC 슬랙' and o.payload->>'tactic' = 'Credential Access') then
    raise exception 'FAIL: 적재 payload 에 MITRE 전술 없음';
  end if;
  -- medium NET 경보 → 아무 채널도 해당 없음(슬랙 high 미만, AUTH전용은 규칙 불일치)
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
    values ('aaaaaaaa-0000-0000-0000-000000000001', 'db000000-0000-0000-0000-00000000000a', 'EDR-NET-001', 'medium', '비정상 통신', '{}', 'n2');
  select count(*) into n from notification_outbox where tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001';
  if n <> 2 then raise exception 'FAIL: medium 경보가 잘못 적재됨, 총 % (기대 2)', n; end if;
  -- critical 경보 → 슬랙+메일+AUTH전용? NET 이므로 AUTH전용 제외 → 슬랙+메일 2건 추가 = 4
  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key)
    values ('aaaaaaaa-0000-0000-0000-000000000001', 'db000000-0000-0000-0000-00000000000a', 'EDR-NET-001', 'critical', '심각 통신', '{}', 'n3');
  select count(*) into n from notification_outbox where tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001';
  if n <> 4 then raise exception 'FAIL: critical 경보 적재 후 총 % (기대 4)', n; end if;
end $$;

-- RLS: A사 관리자는 A사 채널만 보고 B사 채널은 못 본다
set local role authenticated;
select set_config('request.jwt.claim.sub', '6d000000-0000-0000-0000-000000000001', true) \g /dev/null
do $$ declare n int; begin
  select count(*) into n from notification_channels;
  if n <> 3 then raise exception 'FAIL: A사 관리자에게 보이는 채널 % (기대 3)', n; end if;
  select count(*) into n from notification_outbox;
  if n <> 4 then raise exception 'FAIL: A사 관리자에게 보이는 발송 기록 % (기대 4)', n; end if;
end $$;

-- 분석가는 채널을 추가할 수 없다(RLS 관리 정책은 owner/admin)
select set_config('request.jwt.claim.sub', '6d000000-0000-0000-0000-000000000002', true) \g /dev/null
do $$ begin
  begin
    insert into notification_channels (tenant_id, name, kind, target, secret_ref, min_severity)
      values ('aaaaaaaa-0000-0000-0000-000000000001', '분석가채널', 'slack', '#x', 'X', 'low');
    raise exception 'FAIL: 분석가가 채널을 추가할 수 있었음';
  exception when insufficient_privilege or check_violation then null;
  end;
  -- 테스트 발송도 관리자 권한 필요 → 예외
  begin
    perform public.console_notification_test((select id from notification_channels where name = 'SOC 슬랙'));
    raise exception 'FAIL: 분석가가 테스트 발송을 할 수 있었음';
  exception when others then
    if sqlerrm not like '%권한%' then raise; end if;
  end;
end $$;

-- 관리자: 테스트 발송 1건 + 채널 수정·삭제 → 감사 기록
select set_config('request.jwt.claim.sub', '6d000000-0000-0000-0000-000000000001', true) \g /dev/null
do $$ declare cid bigint; before int; got text; begin
  select id into cid from notification_channels where name = 'SOC 슬랙';
  select count(*) into before from notification_outbox;
  perform public.console_notification_test(cid);
  if (select count(*) from notification_outbox) <> before + 1 then raise exception 'FAIL: 테스트 발송 적재 안 됨'; end if;
  update notification_channels set min_severity = 'medium' where id = cid;
  delete from notification_channels where name = 'AUTH 전용';
  select string_agg(action, ',' order by id) into got from audit_log where action like 'notification.%';
  if got <> 'notification.channel.update,notification.channel.delete' then
    raise exception 'FAIL: 알림 채널 감사 기록 = %', got;
  end if;
  raise notice 'OK: notifications (enqueue by severity/rule-prefix, MITRE in payload, tenant RLS, admin-only manage/test, audit)';
end $$;
rollback;

-- =====================================================================
-- 0012: Wazuh 경보 수집 — 심각도 매핑, 장치 매칭, 중복 방지, source='wazuh', 권한, RLS
-- =====================================================================
begin;
insert into auth.users (id, email) values ('6e000000-0000-0000-0000-000000000001', 'owner@a.example');
insert into tenants (id, name) values ('aaaaaaaa-0000-0000-0000-000000000001', 'A사');
insert into tenant_members (tenant_id, user_id, role) values ('aaaaaaaa-0000-0000-0000-000000000001', '6e000000-0000-0000-0000-000000000001', 'owner');
insert into devices (id, tenant_id, hostname, token_hash) values ('de000000-0000-0000-0000-00000000000a', 'aaaaaaaa-0000-0000-0000-000000000001', 'PC-WZ', '\xe1');

do $$ declare id1 bigint; id2 bigint; iddup bigint; begin
  -- level 10 → high, 호스트 매칭, MITRE·incident 묶음
  id1 := public.edr_ingest_wazuh_alert('aaaaaaaa-0000-0000-0000-000000000001',
    '{"id":"9001","rule":{"id":"5710","level":10,"description":"sshd brute force","mitre":{"tactic":["Credential Access"],"id":["T1110"]}},"agent":{"name":"PC-WZ","ip":"203.0.113.9"},"full_log":"x"}'::jsonb);
  if id1 is null then raise exception 'FAIL: Wazuh 경보 저장 안 됨'; end if;
  if (select severity from alerts where id = id1) <> 'high' then raise exception 'FAIL: level 10 → high 아님'; end if;
  if (select device_id from alerts where id = id1) is null then raise exception 'FAIL: 호스트 매칭 실패'; end if;
  if (select source from alerts where id = id1) <> 'wazuh' then raise exception 'FAIL: source wazuh 아님'; end if;
  if (select details->>'mitre_technique' from alerts where id = id1) is null then raise exception 'FAIL: MITRE 누락'; end if;
  if (select incident_id from alerts where id = id1) is null then raise exception 'FAIL: 인시던트 묶음 안 됨'; end if;
  -- 중복 id → null
  iddup := public.edr_ingest_wazuh_alert('aaaaaaaa-0000-0000-0000-000000000001',
    '{"id":"9001","rule":{"id":"5710","level":10,"description":"dup"}}'::jsonb);
  if iddup is not null then raise exception 'FAIL: 중복 Wazuh 경보가 또 저장됨'; end if;
  -- level 13 → critical, 호스트 못 맞춤 → device_id null 이어도 저장
  id2 := public.edr_ingest_wazuh_alert('aaaaaaaa-0000-0000-0000-000000000001',
    '{"id":"9002","rule":{"id":"100100","level":13,"description":"integrity"},"agent":{"name":"NO-SUCH"}}'::jsonb);
  if (select severity from alerts where id = id2) <> 'critical' then raise exception 'FAIL: level 13 → critical 아님'; end if;
  if (select device_id from alerts where id = id2) is not null then raise exception 'FAIL: 없는 호스트인데 device_id 채워짐'; end if;
end $$;

-- authenticated 는 이 함수를 직접 실행할 수 없다(수집 서버 edr_ingest 전용)
set local role authenticated;
select set_config('request.jwt.claim.sub', '6e000000-0000-0000-0000-000000000001', true) \g /dev/null
do $$ begin
  begin
    perform public.edr_ingest_wazuh_alert('aaaaaaaa-0000-0000-0000-000000000001', '{"id":"x","rule":{"id":"1","level":5,"description":"y"}}'::jsonb);
    raise exception 'FAIL: authenticated 가 Wazuh 저장 함수를 실행함';
  exception when insufficient_privilege then null;
  end;
  -- 구성원은 Wazuh 경보도 같은 경보 화면(RLS)으로 읽을 수 있다
  if (select count(*) from alerts where source = 'wazuh') <> 2 then
    raise exception 'FAIL: 구성원에게 보이는 Wazuh 경보 수 = %', (select count(*) from alerts where source = 'wazuh');
  end if;
  raise notice 'OK: wazuh ingest (level→severity, host match, dedup, source, incident grouping, ingest-only exec, member read via RLS)';
end $$;
rollback;
