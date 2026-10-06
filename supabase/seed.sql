-- 로컬 개발·SSO 실험용 기본 데이터 (npx supabase start / db reset 때만 실행, 클라우드에는 적용되지 않음)
insert into public.tenants (id, name)
values ('aaaaaaaa-0000-0000-0000-000000000001', 'BING (SSO 실험)')
on conflict (id) do nothing;

-- AD 그룹 → 콘솔 역할 (deploy/sso-lab 의 테스트용 AD 그룹과 같은 이름)
insert into public.sso_group_roles (tenant_id, provider, idp_group, role) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'keycloak', 'EDR-Admins',   'admin'),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'keycloak', 'EDR-Analysts', 'analyst'),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'keycloak', 'EDR-Viewers',  'viewer')
on conflict do nothing;
