-- 0011 알림 연동 (사내 메신저·이메일·SIEM)
--
-- 목적
--   * 경보(alerts)가 생기면 정해진 채널로 알림을 내보낸다: 슬랙 웹훅, 이메일(SMTP), SIEM(Syslog/JSON).
--   * 보내는 쪽은 enricher 의 알림 루프(outbox 를 임대 방식으로 비운다). 이 마이그레이션은 설정·큐·감사만.
--
-- 설계
--   * 비밀값(슬랙 웹훅 URL, SMTP 비밀번호)은 DB·브라우저에 두지 않는다(CLAUDE.md 보안 기본값).
--     채널에는 비밀값이 든 .env 키 "이름"(secret_ref)만 저장하고, 실제 값은 서버의 .env 에서 읽는다.
--   * 경보 INSERT 트리거가 조건(심각도 하한·규칙 접두사)에 맞는 채널마다 outbox 행 1건을 만든다(발송 대기).
--   * enricher 가 대기 행을 가져가 보내고 sent/failed 로 표시한다. 전송은 이벤트 구동이므로 pg_cron 일정은 두지 않고,
--     오래된 보낸 기록 정리만 enricher 루프에서 edr_prune_notifications() 로 주기 실행한다.

-- ---------- 채널 ----------
create table public.notification_channels (
  id          bigint generated always as identity primary key,
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  name        text not null,
  kind        text not null check (kind in ('slack', 'email', 'syslog', 'webhook')),
  target      text not null default '',          -- 표시·수신 대상: 이메일 주소(쉼표 구분), 슬랙 채널명(표시용), syslog host:port
  secret_ref  text not null default '',          -- 비밀값이 든 .env 키 이름 (예: SLACK_WEBHOOK_SOC). 값 자체가 아님
  min_severity text not null default 'high' check (min_severity in ('low', 'medium', 'high', 'critical')),
  rule_prefixes text[] not null default '{}',    -- 비우면 전체. 예: {'EDR-AUTH','EDR-IOC'} 면 해당 규칙만
  enabled     boolean not null default true,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (tenant_id, name)
);
create index on public.notification_channels (tenant_id, enabled);

-- ---------- 발송 큐(outbox) ----------
create table public.notification_outbox (
  id          bigint generated always as identity primary key,
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  channel_id  bigint not null references public.notification_channels(id) on delete cascade,
  alert_id    bigint references public.alerts(id) on delete set null,
  payload     jsonb not null default '{}'::jsonb,  -- 보낼 때 필요한 정보 스냅샷(경보가 지워져도 유지)
  status      text not null default 'pending' check (status in ('pending', 'sent', 'failed', 'skipped')),
  attempts    int not null default 0,
  last_error  text,
  locked_until timestamptz,                         -- 임대(동시 발송 방지)
  created_at  timestamptz not null default now(),
  sent_at     timestamptz
);
create index on public.notification_outbox (status, created_at) where status = 'pending';
create index on public.notification_outbox (tenant_id, created_at desc);

-- ---------- 경보 → outbox 적재 ----------
-- 새 경보가 생기면(= 탐지 함수가 insert) 조건에 맞는 채널마다 대기 행 1건.
create or replace function public.edr_enqueue_notifications()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into notification_outbox (tenant_id, channel_id, alert_id, payload)
  select c.tenant_id, c.id, new.id,
         jsonb_build_object(
           'rule_id', new.rule_id, 'severity', new.severity, 'title', new.title,
           'device_id', new.device_id, 'created_at', new.created_at,
           'tactic', r.mitre_tactic, 'technique', r.mitre_technique, 'technique_name', r.technique_name)
  from notification_channels c
  left join detection_rules r on r.rule_id = new.rule_id
  where c.tenant_id = new.tenant_id
    and c.enabled
    and edr_sev_rank(new.severity) >= edr_sev_rank(c.min_severity)
    and (cardinality(c.rule_prefixes) = 0
         or exists (select 1 from unnest(c.rule_prefixes) p where new.rule_id like p || '%'));
  return null;
end $$;
revoke all on function public.edr_enqueue_notifications() from public, anon, authenticated;

create trigger trg_enqueue_notifications after insert on public.alerts
  for each row execute function public.edr_enqueue_notifications();

-- ---------- 발송 루프용 함수 (enricher, edr_enricher 역할) ----------
-- 대기 행을 임대해서 가져온다(동시 인스턴스 안전). 최대 n건.
create or replace function public.edr_lease_notifications(n int default 20)
returns setof public.notification_outbox
language plpgsql security definer set search_path = public as $$
begin
  return query
  update notification_outbox o
  set status = 'pending', locked_until = now() + interval '2 minutes', attempts = o.attempts + 1
  where o.id in (
    select id from notification_outbox
    where status = 'pending' and (locked_until is null or locked_until < now())
    order by created_at
    limit n
    for update skip locked)
  returning o.*;
end $$;
revoke all on function public.edr_lease_notifications(int) from public, anon, authenticated;
grant execute on function public.edr_lease_notifications(int) to edr_enricher;

-- 발송 결과 표시.
create or replace function public.edr_mark_notification(p_id bigint, p_ok boolean, p_error text default null)
returns void language plpgsql security definer set search_path = public as $$
begin
  update notification_outbox
  set status = case when p_ok then 'sent' else (case when attempts >= 5 then 'failed' else 'pending' end) end,
      last_error = case when p_ok then null else p_error end,
      locked_until = case when p_ok or attempts >= 5 then null else now() + interval '5 minutes' end,
      sent_at = case when p_ok then now() else sent_at end
  where id = p_id;
end $$;
revoke all on function public.edr_mark_notification(bigint, boolean, text) from public, anon, authenticated;
grant execute on function public.edr_mark_notification(bigint, boolean, text) to edr_enricher;

-- 오래된 보낸/건너뛴 기록 정리(30일). enricher 루프에서 가끔 호출.
create or replace function public.edr_prune_notifications()
returns void language sql security definer set search_path = public as $$
  delete from notification_outbox where status in ('sent', 'skipped') and created_at < now() - interval '30 days';
$$;
revoke all on function public.edr_prune_notifications() from public, anon, authenticated;
grant execute on function public.edr_prune_notifications() to edr_enricher;

-- ---------- 콘솔용: 테스트 발송(관리자) ----------
-- 설정 화면에서 "테스트 알림 보내기" 를 누르면 대기 행 1건을 만든다. 실제 전송은 enricher 가 한다.
create or replace function public.console_notification_test(p_channel bigint)
returns bigint language plpgsql security definer set search_path = public as $$
declare v_tenant uuid; v_id bigint;
begin
  select tenant_id into v_tenant from notification_channels where id = p_channel;
  if v_tenant is null or not public.has_tenant_role(v_tenant, array['owner', 'admin']) then
    raise exception '권한이 없습니다';
  end if;
  insert into notification_outbox (tenant_id, channel_id, alert_id, payload)
  values (v_tenant, p_channel, null,
          jsonb_build_object('rule_id', 'TEST', 'severity', 'low', 'title', '[테스트] 알림 연동 확인', 'test', true))
  returning id into v_id;
  return v_id;
end $$;
revoke all on function public.console_notification_test(bigint) from public, anon;
grant execute on function public.console_notification_test(bigint) to authenticated;

-- ---------- 감사(전용 트리거, 0010 과 같은 방식) ----------
create or replace function public.edr_audit_notification()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  uid   uuid := (select auth.uid());
  email text;
  o     jsonb := case when tg_op in ('UPDATE', 'DELETE') then to_jsonb(old) end;
  nw    jsonb := case when tg_op in ('INSERT', 'UPDATE') then to_jsonb(new) end;
  r     jsonb := coalesce(nw, o);
  act   text;
  diff  jsonb;
begin
  if uid is null then return null; end if;   -- enricher 의 큐 갱신은 기록하지 않음
  select u.email into email from auth.users u where u.id = uid;
  act := case tg_op when 'INSERT' then 'notification.channel.create'
                    when 'DELETE' then 'notification.channel.delete'
                    else 'notification.channel.update' end;
  diff := case tg_op
            when 'UPDATE' then edr_audit_diff(o, nw, array['name', 'kind', 'target', 'secret_ref', 'min_severity', 'rule_prefixes', 'enabled'])
            else jsonb_build_object('name', r->'name', 'kind', r->'kind', 'min_severity', r->'min_severity', 'enabled', r->'enabled') end;
  if tg_op = 'UPDATE' and diff = '{}'::jsonb then return null; end if;
  insert into audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, target_label, changes)
  values ((r->>'tenant_id')::uuid, uid, email, act, 'notification_channel', r->>'id', r->>'name', diff);
  return null;
end $$;
revoke all on function public.edr_audit_notification() from public, anon, authenticated;

create trigger trg_audit_notification after insert or update or delete on public.notification_channels
  for each row execute function public.edr_audit_notification();

-- ---------- RLS ----------
alter table public.notification_channels enable row level security;
alter table public.notification_outbox   enable row level security;

-- 채널: 구성원은 읽기, 관리는 소유자·관리자만. (secret_ref 는 값이 아니라 키 이름이라 노출돼도 비밀 아님)
create policy nch_select on public.notification_channels for select to authenticated
  using (tenant_id in (select public.my_tenant_ids()));
create policy nch_manage on public.notification_channels for all to authenticated
  using ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])))
  with check ((select public.has_tenant_role(tenant_id, array['owner', 'admin'])));
create policy nch_service on public.notification_channels for select to edr_enricher using (true);

-- outbox: 구성원은 읽기(발송 상태 확인), 쓰기는 enricher 와 저장 함수만. authenticated 직접 쓰기 없음.
create policy nob_select on public.notification_outbox for select to authenticated
  using (tenant_id in (select public.my_tenant_ids()));
create policy nob_service on public.notification_outbox for select to edr_enricher using (true);

-- 테이블 권한(실제 허용 범위는 위 RLS 정책이 판단). 새 테이블이라 명시적으로 준다.
grant select, insert, update, delete on public.notification_channels to authenticated;
grant select on public.notification_outbox to authenticated;
grant select on public.notification_channels to edr_enricher;
grant select, update on public.notification_outbox to edr_enricher;
