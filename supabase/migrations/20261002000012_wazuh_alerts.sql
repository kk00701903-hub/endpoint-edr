-- 0012 Wazuh 경보 수집 (외부 오픈소스 EDR 연동)
--
-- 목적
--   * 사내에 함께 운영하는 Wazuh(오픈소스 EDR)의 경보를 이 콘솔 한 화면에서 같이 보도록 받는다.
--   * Wazuh 가 수집 서버의 웹훅(POST /v1/wazuh)으로 경보를 보내면, 저장 함수가 alerts 에 source='wazuh' 로 넣는다.
--   * 받기만 한다. Wazuh 를 제어하거나 PC 에 개입하지 않는다.
--
-- 설계
--   * 기존 경보 화면·인시던트 묶음·알림 연동(0011)을 그대로 탄다(트리거는 source 와 무관하게 동작).
--   * 장치는 Wazuh 에이전트 이름(hostname)으로 맞춘다. 못 맞추면 device_id 는 비운다(경보는 그대로 보임).
--   * 중복은 Wazuh 경보 id 로 막는다(dedup_key).

-- 경보 출처 구분(기존 탐지 = edr, Wazuh = wazuh)
alter table public.alerts add column if not exists source text not null default 'edr';
alter table public.alerts drop constraint if exists alerts_source_check;
alter table public.alerts add constraint alerts_source_check check (source in ('edr', 'wazuh'));
create index if not exists alerts_source_idx on public.alerts (tenant_id, source, created_at desc);

-- Wazuh 경보 1건 저장. 수집 서버(edr_ingest 역할)가 호출한다.
create or replace function public.edr_ingest_wazuh_alert(p_tenant uuid, p_alert jsonb)
returns bigint
language plpgsql security definer set search_path = public as $$
declare
  v_level   int := coalesce((p_alert#>>'{rule,level}')::int, 0);
  v_sev     text;
  v_rule    text := coalesce(p_alert#>>'{rule,id}', '0');
  v_desc    text := coalesce(nullif(p_alert#>>'{rule,description}', ''), 'Wazuh 경보');
  v_host    text := nullif(p_alert#>>'{agent,name}', '');
  v_ip      text := nullif(p_alert#>>'{agent,ip}', '');
  v_wid     text := nullif(p_alert->>'id', '');
  v_ts      timestamptz := coalesce((p_alert->>'timestamp')::timestamptz, now());
  v_dev     uuid;
  v_dedup   text;
  v_details jsonb;
  v_id      bigint;
begin
  -- Wazuh rule.level(0~15) → 심각도
  v_sev := case when v_level >= 12 then 'critical'
                when v_level >= 9  then 'high'
                when v_level >= 7  then 'medium'
                else 'low' end;

  if v_host is not null then
    select id into v_dev from devices where tenant_id = p_tenant and lower(hostname) = lower(v_host) limit 1;
  end if;

  v_dedup := 'wazuh:' || coalesce(v_wid, md5(v_rule || ':' || coalesce(v_host, '') || ':' || v_ts::text || ':' || left(coalesce(p_alert->>'full_log', ''), 200)));

  -- src_ip 은 인시던트 묶음(edr_attach_alert)이 details->>'src_ip' 로 읽으므로 같은 키로 넣는다
  v_details := jsonb_strip_nulls(jsonb_build_object(
    'wazuh', true,
    'wazuh_id', v_wid,
    'wazuh_rule_id', v_rule,
    'level', v_level,
    'agent', v_host,
    'src_ip', v_ip,
    'location', nullif(p_alert->>'location', ''),
    'groups', p_alert#>'{rule,groups}',
    'mitre_tactic', p_alert#>'{rule,mitre,tactic}',
    'mitre_technique', p_alert#>'{rule,mitre,id}',
    'full_log', left(nullif(p_alert->>'full_log', ''), 2000)));

  insert into alerts (tenant_id, device_id, rule_id, severity, title, details, dedup_key, source, created_at)
  values (p_tenant, v_dev, 'WAZUH-' || v_rule, v_sev,
          '[Wazuh] ' || left(v_desc, 300) || case when v_host is not null then ' — ' || v_host else '' end,
          v_details, v_dedup, 'wazuh', v_ts)
  on conflict (tenant_id, dedup_key) do nothing
  returning id into v_id;

  return v_id;  -- 중복이면 null
end $$;
revoke all on function public.edr_ingest_wazuh_alert(uuid, jsonb) from public, anon, authenticated;
grant execute on function public.edr_ingest_wazuh_alert(uuid, jsonb) to edr_ingest;
