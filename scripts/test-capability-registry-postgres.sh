#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="dondone-auth-pg-test-$$"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required for this independent PostgreSQL integration test." >&2
  exit 2
fi

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --rm -d --name "$container" -e POSTGRES_PASSWORD=test \
  -v "$root_dir:/workspace:ro" postgres:15-alpine >/dev/null

until docker exec "$container" sh -c 'test "$(cat /proc/1/comm)" = postgres' >/dev/null 2>&1 \
  && docker exec "$container" psql -v ON_ERROR_STOP=1 -Atqc 'select 1' -U postgres >/dev/null 2>&1; do
  if test "$(docker inspect -f '{{.State.Running}}' "$container")" != "true"; then
    docker logs "$container" >&2
    exit 1
  fi
  sleep 0.2
done

docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
create extension if not exists pgcrypto;
create schema auth;
create table auth.users(
  id uuid primary key default gen_random_uuid(),
  email text,
  raw_user_meta_data jsonb default '{}'::jsonb
);
create function auth.uid() returns uuid language sql stable as $$ select null::uuid $$;
create role anon;
create role authenticated;
create role service_role;
SQL

docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -f /workspace/docs/sql/authorization.sql >/dev/null
docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -f /workspace/docs/sql/migrations/20260713_add_service_redirect_uris.sql >/dev/null
docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -f /workspace/docs/sql/migrations/20260714_add_service_capability_registry.sql >/dev/null
docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -f /workspace/supabase/migrations/20260715000600_restore_idempotent_capability_sync_state.sql >/dev/null

docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
-- Recreate the historical direct-grant table when the canonical schema no
-- longer defines it. The final migration is tested against this pre-final
-- production shape, independently from the canonical fresh-install shape.
create table if not exists public.user_permissions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  permission_key text not null references public.permissions(key) on delete cascade,
  status text not null default 'active' check (status in ('active', 'revoked')),
  granted_by uuid references public.profiles(id),
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  unique (user_id, permission_key)
);

-- Restore the historical trigger behavior too, so the final new-user check
-- proves the migration replaced it rather than inheriting the canonical form.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name, avatar_url)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name'),
    new.raw_user_meta_data->>'avatar_url'
  )
  on conflict (id) do update set email = excluded.email;

  insert into public.user_permission_groups(user_id, group_id)
  select new.id, id from public.permission_groups
  where service_key='api' and key='basic'
  on conflict (user_id, group_id) do nothing;

  return new;
end;
$$;

insert into auth.users(id,email)
values ('00000000-0000-0000-0000-000000000001','admin@example.com');
update public.services set resource_uri='https://api.dondone.dev' where key='api';
insert into public.user_permissions(user_id, permission_key, status)
values ('00000000-0000-0000-0000-000000000001', 'tier:vip', 'active');

select * from public.import_service_capability_version(
  'api','v1','hash-v1',
  '{"resource":"https://api.dondone.dev","authorization_servers":["https://auth.dondone.dev"],"scopes_supported":["api:echo","api:tier:vip"],"vendor_extension":{"revision":1},"dondone_capabilities":{"schema_version":1,"catalog_version":"v1","permissions":[{"key":"api:echo","description":"Echo"},{"key":"api:tier:vip","description":"VIP"}],"roles":[{"key":"basic","name":"Basic","permission_keys":["api:echo"]},{"key":"vip","name":"VIP","permission_keys":["api:echo","api:tier:vip"]}]}}'::jsonb,
  '00000000-0000-0000-0000-000000000001');

-- The first pending version locks the resource identity immediately, before
-- approval. This closes the fetch/import/approve TOCTOU window.
do $$ begin
  begin
    update public.services set resource_uri='https://new-api.dondone.dev' where key='api';
    raise exception 'pending resource URI change unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'resource_uri_locked' then raise; end if;
  end;
end $$;

-- Import must compare the raw manifest resource again while holding the
-- service-row lock; parser-side validation before the RPC is not sufficient.
update public.services set resource_uri='https://time-api.dondone.dev' where key='time';
do $$ begin
  begin
    perform * from public.import_service_capability_version(
      'time','race-v1','race-hash',
      '{"resource":"https://other-time-api.dondone.dev","authorization_servers":["https://auth.dondone.dev"],"scopes_supported":[],"dondone_capabilities":{"schema_version":1,"catalog_version":"race-v1","permissions":[],"roles":[]}}'::jsonb,
      '00000000-0000-0000-0000-000000000001');
    raise exception 'mismatched import resource unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'capability_resource_mismatch' then raise; end if;
  end;
  if exists (select 1 from public.service_capability_versions where service_key='time') then
    raise exception 'failed mismatched import left a version';
  end if;
end $$;

-- Simulate legacy/corrupt stale state by temporarily bypassing the identity
-- trigger. Approval must independently re-check the target manifest resource.
alter table public.services disable trigger services_lock_active_resource_uri;
update public.services set resource_uri='https://stale-api.dondone.dev' where key='api';
alter table public.services enable trigger services_lock_active_resource_uri;
do $$ begin
  begin
    perform public.approve_service_capability_version(
      'api','v1','00000000-0000-0000-0000-000000000001',null,'{}'::jsonb);
    raise exception 'stale resource approval unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'capability_resource_mismatch' then raise; end if;
  end;
  if (select import_status from public.service_capability_versions where service_key='api' and catalog_version='v1') <> 'pending_review'
    or (select active_capability_version from public.services where key='api') is not null then
    raise exception 'failed stale approval mutated catalog state';
  end if;
end $$;
alter table public.services disable trigger services_lock_active_resource_uri;
update public.services set resource_uri='https://api.dondone.dev' where key='api';
alter table public.services enable trigger services_lock_active_resource_uri;
select public.approve_service_capability_version(
  'api','v1','00000000-0000-0000-0000-000000000001',null,'{}'::jsonb);

-- A resource URI is a stable, unique resource identity. Duplicate registration
-- and changing an identity with an active catalog must both fail atomically.
do $$ begin
  begin
    insert into public.services(key,name,resource_uri) values ('duplicate-api','Duplicate API','https://api.dondone.dev');
    raise exception 'duplicate resource URI unexpectedly succeeded';
  exception when unique_violation then null;
  end;
  begin
    update public.services set resource_uri='https://new-api.dondone.dev' where key='api';
    raise exception 'active resource URI change unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'resource_uri_locked' then raise; end if;
  end;
  if (select resource_uri from public.services where key='api') <> 'https://api.dondone.dev' then
    raise exception 'failed resource URI change mutated the identity';
  end if;

  update public.services set resource_uri='https://time-api.dondone.dev' where key='time';
  if (select resource_uri from public.services where key='time') <> 'https://time-api.dondone.dev' then
    raise exception 'unbound resource URI could not be changed';
  end if;
end $$;

-- Identical synchronization must not downgrade the approved version.
select public.record_service_capability_sync_failure(
  'api','00000000-0000-0000-0000-000000000001','stale fetch failure');
select * from public.import_service_capability_version(
  'api','v1','hash-v1',
  '{"resource":"https://api.dondone.dev","authorization_servers":["https://auth.dondone.dev"],"scopes_supported":["api:echo","api:tier:vip"],"vendor_extension":{"revision":1},"dondone_capabilities":{"schema_version":1,"catalog_version":"v1","permissions":[{"key":"api:echo","description":"Echo"},{"key":"api:tier:vip","description":"VIP"}],"roles":[{"key":"basic","name":"Basic","permission_keys":["api:echo"]},{"key":"vip","name":"VIP","permission_keys":["api:echo","api:tier:vip"]}]}}'::jsonb,
  '00000000-0000-0000-0000-000000000001');
do $$ begin
  if (select import_status from public.service_capability_versions where service_key='api' and catalog_version='v1') <> 'approved' then
    raise exception 'idempotent sync downgraded approved version';
  end if;
  if (select capability_sync_status from public.services where key='api') <> 'active' then
    raise exception 'idempotent successful sync did not restore active service status';
  end if;
  if (select capability_last_error from public.services where key='api') is not null then
    raise exception 'idempotent successful sync did not clear stale service error';
  end if;
  if not exists (select 1 from public.permission_groups where service_key='api' and key='vip' and is_system and status='active') then
    raise exception 'system role projection missing';
  end if;
  if (select manifest->'vendor_extension'->>'revision' from public.service_capability_versions where service_key='api' and catalog_version='v1') <> '1' then
    raise exception 'raw manifest extension was not stored';
  end if;
end $$;

-- Re-synchronizing an unchanged rejected version must not invent a pending
-- review, but it must clear any stale transport error from the last attempt.
select * from public.import_service_capability_version(
  'time','rejected-v1','time-rejected-hash',
  '{"resource":"https://time-api.dondone.dev","authorization_servers":["https://auth.dondone.dev"],"scopes_supported":[],"dondone_capabilities":{"schema_version":1,"catalog_version":"rejected-v1","permissions":[],"roles":[]}}'::jsonb,
  '00000000-0000-0000-0000-000000000001');
select public.reject_service_capability_version(
  'time','rejected-v1','00000000-0000-0000-0000-000000000001','not acceptable');
select public.record_service_capability_sync_failure(
  'time','00000000-0000-0000-0000-000000000001','stale rejected fetch failure');
select * from public.import_service_capability_version(
  'time','rejected-v1','time-rejected-hash',
  '{"resource":"https://time-api.dondone.dev","authorization_servers":["https://auth.dondone.dev"],"scopes_supported":[],"dondone_capabilities":{"schema_version":1,"catalog_version":"rejected-v1","permissions":[],"roles":[]}}'::jsonb,
  '00000000-0000-0000-0000-000000000001');
do $$ begin
  if (select import_status from public.service_capability_versions where service_key='time' and catalog_version='rejected-v1') <> 'rejected' then
    raise exception 'idempotent sync reopened a rejected version';
  end if;
  if (select capability_sync_status from public.services where key='time') <> 'failed' then
    raise exception 'idempotent rejected sync invented a pending review';
  end if;
  if (select capability_last_error from public.services where key='time') is not null then
    raise exception 'idempotent rejected sync did not clear stale transport error';
  end if;
end $$;

-- A change confined to an unknown extension still changes the raw JCS hash
-- and must conflict with the immutable catalog_version.
do $$ begin
  begin
    perform * from public.import_service_capability_version(
      'api','v1','hash-v1-extension-changed',
      '{"resource":"https://api.dondone.dev","authorization_servers":["https://auth.dondone.dev"],"scopes_supported":["api:echo","api:tier:vip"],"vendor_extension":{"revision":2},"dondone_capabilities":{"schema_version":1,"catalog_version":"v1","permissions":[{"key":"api:echo","description":"Echo"},{"key":"api:tier:vip","description":"VIP"}],"roles":[{"key":"basic","name":"Basic","permission_keys":["api:echo"]},{"key":"vip","name":"VIP","permission_keys":["api:echo","api:tier:vip"]}]}}'::jsonb,
      '00000000-0000-0000-0000-000000000001');
    raise exception 'raw extension drift unexpectedly succeeded';
  exception when unique_violation then
    if sqlerrm <> 'catalog_version_conflict' then raise; end if;
  end;
end $$;

-- The anon role can read only the restricted active resource projection.
set role anon;
do $$ begin
  if (select count(*) from public.active_resource_capabilities where resource_uri='https://api.dondone.dev') <> 2 then
    raise exception 'anon cannot read the active resource projection';
  end if;
  if (select count(*) from public.services) <> 0 then
    raise exception 'RLS exposed services rows to anon';
  end if;
end $$;
reset role;
do $$ begin
  if has_function_privilege('anon', 'public.import_service_capability_version(text,text,text,jsonb,uuid)', 'execute')
    or has_function_privilege('authenticated', 'public.import_service_capability_version(text,text,text,jsonb,uuid)', 'execute')
    or has_function_privilege('anon', 'public.approve_service_capability_version(text,text,uuid,text,jsonb)', 'execute')
    or has_function_privilege('authenticated', 'public.approve_service_capability_version(text,text,uuid,text,jsonb)', 'execute')
    or has_function_privilege('anon', 'public.console_create_permission_group(text,text,text,text,text[],uuid)', 'execute')
    or has_function_privilege('authenticated', 'public.console_create_permission_group(text,text,text,text,text[],uuid)', 'execute')
    or has_function_privilege('anon', 'public.console_update_permission_group(text,text,text,text,text,text[],uuid)', 'execute')
    or has_function_privilege('authenticated', 'public.console_update_permission_group(text,text,text,text,text,text[],uuid)', 'execute')
    or has_function_privilege('anon', 'public.console_replace_user_permission_groups(uuid,jsonb,uuid)', 'execute')
    or has_function_privilege('authenticated', 'public.console_replace_user_permission_groups(uuid,jsonb,uuid)', 'execute') then
    raise exception 'browser roles can execute capability admin RPCs';
  end if;
  if has_table_privilege('anon', 'public.service_capability_versions', 'select')
    or has_table_privilege('authenticated', 'public.service_capability_versions', 'select')
    or has_table_privilege('anon', 'public.service_capability_audit', 'select')
    or has_table_privilege('authenticated', 'public.service_capability_audit', 'select') then
    raise exception 'browser roles can read raw capability tables';
  end if;
end $$;

-- Console group changes are catalog-bound and atomic. A permission belonging
-- to another service must reject the whole create, leaving no orphan group.
select public.console_create_permission_group(
  'api','managed','Managed','Console-managed bundle',array['api:echo'],
  '00000000-0000-0000-0000-000000000001');
do $$ begin
  begin
    perform public.console_create_permission_group(
      'api','wrong-service','Wrong service',null,array['console:admin'],
      '00000000-0000-0000-0000-000000000001');
    raise exception 'wrong-service group unexpectedly succeeded';
  exception when check_violation then null;
  end;
  if exists (select 1 from public.permission_groups where service_key='api' and key='wrong-service') then
    raise exception 'failed group create left an orphan row';
  end if;
end $$;

-- Service-owned roles are immutable through Console, including their status
-- and permission mapping.
do $$ begin
  begin
    perform public.console_update_permission_group(
      'api','vip','Modified',null,'disabled',array['api:echo'],
      '00000000-0000-0000-0000-000000000001');
    raise exception 'system role update unexpectedly succeeded';
  exception when check_violation then null;
  end;
  if (select status from public.permission_groups where service_key='api' and key='vip') <> 'active' then
    raise exception 'failed system-role update changed the role';
  end if;
end $$;

-- User-group replacement updates expiry, writes one audit per affected
-- service, and rolls back grants when any audit insert fails.
do $$
declare
  api_group uuid;
  console_group uuid;
  audit_before bigint;
begin
  select id into api_group from public.permission_groups where service_key='api' and key='managed';
  select id into console_group from public.permission_groups where service_key='console' and key='admin';
  perform public.console_replace_user_permission_groups(
    '00000000-0000-0000-0000-000000000001',
    jsonb_build_array(
      jsonb_build_object('group_id',api_group,'expires_at','2027-01-01T00:00:00Z'),
      jsonb_build_object('group_id',console_group,'expires_at',null)),
    '00000000-0000-0000-0000-000000000001');
  if (select expires_at from public.user_permission_groups where user_id='00000000-0000-0000-0000-000000000001' and group_id=api_group)
      <> '2027-01-01T00:00:00Z'::timestamptz then
    raise exception 'initial grant expiry missing';
  end if;
  if (select count(distinct service_key) from public.service_capability_audit
      where action='grant_changed' and detail->>'user_id'='00000000-0000-0000-0000-000000000001') < 2 then
    raise exception 'user replacement did not audit every affected service';
  end if;

  perform public.console_replace_user_permission_groups(
    '00000000-0000-0000-0000-000000000001',
    jsonb_build_array(jsonb_build_object('group_id',api_group,'expires_at','2028-01-01T00:00:00Z')),
    '00000000-0000-0000-0000-000000000001');
  if (select expires_at from public.user_permission_groups where user_id='00000000-0000-0000-0000-000000000001' and group_id=api_group)
      <> '2028-01-01T00:00:00Z'::timestamptz then
    raise exception 'existing grant expiry was not updated';
  end if;
  if not exists (
    select 1 from public.service_capability_audit where service_key='api' and action='grant_changed'
      and detail->'expiry_changed_group_ids' ? api_group::text
  ) then raise exception 'expiry change missing from audit'; end if;

  select count(*) into audit_before from public.service_capability_audit;
  create function pg_temp.reject_grant_audit() returns trigger language plpgsql as $f$
    begin if new.action='grant_changed' then raise exception 'injected audit failure'; end if; return new; end $f$;
  create trigger reject_grant_audit before insert on public.service_capability_audit
    for each row execute function pg_temp.reject_grant_audit();
  begin
    perform public.console_replace_user_permission_groups(
      '00000000-0000-0000-0000-000000000001','[]'::jsonb,
      '00000000-0000-0000-0000-000000000001');
    raise exception 'audit failure injection unexpectedly succeeded';
  exception when others then
    if sqlerrm='audit failure injection unexpectedly succeeded' then raise; end if;
  end;
  drop trigger reject_grant_audit on public.service_capability_audit;
  if not exists (select 1 from public.user_permission_groups where user_id='00000000-0000-0000-0000-000000000001' and group_id=api_group and status='active')
    or (select count(*) from public.service_capability_audit) <> audit_before then
    raise exception 'audit failure did not roll back user grants';
  end if;
end $$;

-- Approve v2, then explicitly roll back to superseded v1.
select * from public.import_service_capability_version(
  'api','v2','hash-v2',
  '{"resource":"https://api.dondone.dev","authorization_servers":["https://auth.dondone.dev"],"scopes_supported":["api:echo"],"dondone_capabilities":{"schema_version":1,"catalog_version":"v2","permissions":[{"key":"api:echo","description":"Echo v2"}],"roles":[{"key":"basic","name":"Basic","permission_keys":["api:echo"]}]}}'::jsonb,
  '00000000-0000-0000-0000-000000000001');
select public.approve_service_capability_version('api','v2','00000000-0000-0000-0000-000000000001','v1','{}'::jsonb);
select public.approve_service_capability_version('api','v1','00000000-0000-0000-0000-000000000001','v2','{"reason":"rollback"}'::jsonb);
do $$ begin
  if (select active_capability_version from public.services where key='api') <> 'v1' then
    raise exception 'rollback did not restore v1';
  end if;
end $$;

-- Inject an approval failure after early mutations would have occurred. The
-- non-system group collision must roll back version status, pointer and audit.
insert into public.permission_groups(service_key,key,name,is_system)
values ('api','custom','Managed Custom',false);
select * from public.import_service_capability_version(
  'api','v3','hash-v3',
  '{"resource":"https://api.dondone.dev","authorization_servers":["https://auth.dondone.dev"],"scopes_supported":["api:echo"],"dondone_capabilities":{"schema_version":1,"catalog_version":"v3","permissions":[{"key":"api:echo","description":"Echo v3"}],"roles":[{"key":"custom","name":"Service Custom","permission_keys":["api:echo"]}]}}'::jsonb,
  '00000000-0000-0000-0000-000000000001');
do $$
declare audit_before bigint;
begin
  select count(*) into audit_before from public.service_capability_audit;
  begin
    perform public.approve_service_capability_version('api','v3','00000000-0000-0000-0000-000000000001','v1','{}'::jsonb);
    raise exception 'fault injection unexpectedly succeeded';
  exception when others then
    if sqlerrm = 'fault injection unexpectedly succeeded' then raise; end if;
  end;
  if (select active_capability_version from public.services where key='api') <> 'v1'
    or (select import_status from public.service_capability_versions where service_key='api' and catalog_version='v1') <> 'approved'
    or (select import_status from public.service_capability_versions where service_key='api' and catalog_version='v3') <> 'pending_review'
    or (select count(*) from public.service_capability_audit) <> audit_before then
    raise exception 'failed approval left partial transactional state';
  end if;
end $$;
SQL

docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres -f /workspace/docs/sql/migrations/20260714_migrate_seed_permissions_to_capabilities.sql >/dev/null

docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
do $$ begin
  if exists (select 1 from public.permissions where key='tier:vip') then
    raise exception 'legacy tier:vip permission remains';
  end if;
  if not exists (
    select 1 from public.user_permissions
    where user_id='00000000-0000-0000-0000-000000000001' and permission_key='api:tier:vip' and status='active'
  ) then
    raise exception 'direct VIP grant was not preserved';
  end if;
end $$;
SQL

# The pure-role migration must reject unexpected live direct permissions before
# it drops the legacy table or migrates any api:echo grant.
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
insert into public.permission_groups(service_key,key,name,is_system,status)
values ('api','caller','Caller',true,'active')
on conflict (service_key,key) do update
set name=excluded.name,is_system=excluded.is_system,status=excluded.status;
insert into public.permission_group_permissions(group_id,permission_key)
select id,'api:echo' from public.permission_groups
where service_key='api' and key='caller'
on conflict do nothing;

insert into auth.users(id,email) values
  ('00000000-0000-0000-0000-000000000002','merge@example.com'),
  ('00000000-0000-0000-0000-000000000003','permanent@example.com'),
  ('00000000-0000-0000-0000-000000000004','expired@example.com'),
  ('00000000-0000-0000-0000-000000000005','revoked@example.com'),
  ('00000000-0000-0000-0000-000000000007','existing-permanent@example.com');

insert into public.user_permission_groups(user_id,group_id,status,granted_by,expires_at)
select '00000000-0000-0000-0000-000000000002',id,'active',
       '00000000-0000-0000-0000-000000000002','2028-01-01T00:00:00Z'
from public.permission_groups where service_key='api' and key='caller';
insert into public.user_permission_groups(user_id,group_id,status,granted_by,expires_at)
select '00000000-0000-0000-0000-000000000003',id,'revoked',
       '00000000-0000-0000-0000-000000000001','2029-01-01T00:00:00Z'
from public.permission_groups where service_key='api' and key='caller';
insert into public.user_permission_groups(user_id,group_id,status,granted_by,expires_at)
select '00000000-0000-0000-0000-000000000007',id,'active',
       '00000000-0000-0000-0000-000000000001',null
from public.permission_groups where service_key='api' and key='caller';

insert into public.user_permissions(user_id,permission_key,status,granted_by,expires_at) values
  ('00000000-0000-0000-0000-000000000002','api:echo','active','00000000-0000-0000-0000-000000000001','2027-01-01T00:00:00Z'),
  ('00000000-0000-0000-0000-000000000003','api:echo','active','00000000-0000-0000-0000-000000000002',null),
  ('00000000-0000-0000-0000-000000000004','api:echo','active','00000000-0000-0000-0000-000000000001',now() - interval '1 day'),
  ('00000000-0000-0000-0000-000000000005','api:echo','revoked','00000000-0000-0000-0000-000000000001',null),
  ('00000000-0000-0000-0000-000000000007','api:echo','active','00000000-0000-0000-0000-000000000002','2099-01-01T00:00:00Z');
SQL

if docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres \
  -f /workspace/docs/sql/migrations/20260715_finalize_pure_role_authorization.sql >/dev/null 2>&1; then
  echo "Pure-role migration unexpectedly accepted an active non-api:echo direct grant." >&2
  exit 1
fi

docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
do $$ begin
  if to_regclass('public.user_permissions') is null then
    raise exception 'failed pure-role migration dropped direct grants';
  end if;
  if exists (
    select 1 from public.user_permission_groups membership
    join public.permission_groups role on role.id=membership.group_id
    where membership.user_id='00000000-0000-0000-0000-000000000002'
      and role.service_key='api' and role.key='caller'
      and membership.granted_by='00000000-0000-0000-0000-000000000001'
  ) then
    raise exception 'failed pure-role migration partially migrated api:echo';
  end if;
end $$;
update public.user_permissions
set status='revoked'
where permission_key <> 'api:echo' and status='active';
SQL

docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres \
  -f /workspace/docs/sql/migrations/20260715_finalize_pure_role_authorization.sql >/dev/null

docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
do $$
declare caller_group uuid;
begin
  select id into caller_group from public.permission_groups
  where service_key='api' and key='caller';

  if to_regclass('public.user_permissions') is not null then
    raise exception 'successful pure-role migration retained direct grants';
  end if;
  if not exists (
    select 1 from public.user_permission_groups
    where user_id='00000000-0000-0000-0000-000000000002'
      and group_id=caller_group and status='active'
      and granted_by='00000000-0000-0000-0000-000000000001'
      and expires_at='2028-01-01T00:00:00Z'
  ) then
    raise exception 'finite direct Caller grant metadata was not preserved and merged';
  end if;
  if not exists (
    select 1 from public.user_permission_groups
    where user_id='00000000-0000-0000-0000-000000000003'
      and group_id=caller_group and status='active'
      and granted_by='00000000-0000-0000-0000-000000000002'
      and expires_at is null
  ) then
    raise exception 'permanent direct Caller grant did not win union expiry';
  end if;
  if not exists (
    select 1 from public.user_permission_groups
    where user_id='00000000-0000-0000-0000-000000000007'
      and group_id=caller_group and status='active'
      and expires_at is null
  ) then
    raise exception 'existing permanent Caller membership did not win union expiry';
  end if;
  if exists (
    select 1 from public.user_permission_groups
    where user_id in (
      '00000000-0000-0000-0000-000000000004',
      '00000000-0000-0000-0000-000000000005'
    ) and group_id=caller_group
  ) then
    raise exception 'expired or revoked direct grant was migrated';
  end if;
end $$;

insert into auth.users(id,email)
values ('00000000-0000-0000-0000-000000000006','new-user@example.com');
do $$ begin
  if not exists (
    select 1 from public.profiles
    where id='00000000-0000-0000-0000-000000000006'
  ) then
    raise exception 'new auth user did not receive a profile';
  end if;
  if exists (
    select 1 from public.user_permission_groups
    where user_id='00000000-0000-0000-0000-000000000006'
  ) then
    raise exception 'new auth user received a default group';
  end if;
end $$;
SQL

# ---- Usage Policy migration ----

# Resolve conflicting memberships from test fixtures before migration.
# Users created with the old trigger have basic(api) active alongside
# caller(api) active. In production these would be resolved via Console.
docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
update public.user_permission_groups upg
set status = 'revoked', updated_at = now()
where upg.status = 'active'
  and exists (
    select 1 from public.permission_groups pg
    where pg.id = upg.group_id and pg.service_key = 'api' and pg.key = 'basic'
  )
  and exists (
    select 1 from public.user_permission_groups other
    join public.permission_groups opg on opg.id = other.group_id
    where other.user_id = upg.user_id
      and other.status = 'active'
      and opg.service_key = 'api'
      and opg.key <> 'basic'
  );
SQL

docker exec "$container" psql -v ON_ERROR_STOP=1 -U postgres \
  -f /workspace/supabase/migrations/20260716000100_add_usage_policies.sql >/dev/null

docker exec -i "$container" psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
-- Verify schema additions exist
do $$ begin
  if not exists (select 1 from information_schema.columns where table_name='services' and column_name='default_group_id') then
    raise exception 'default_group_id column missing';
  end if;
  if not exists (select 1 from information_schema.tables where table_name='usage_policies') then
    raise exception 'usage_policies table missing';
  end if;
  if not exists (select 1 from information_schema.tables where table_name='usage_policy_rules') then
    raise exception 'usage_policy_rules table missing';
  end if;
  if not exists (select 1 from information_schema.tables where table_name='usage_adjustment_audit') then
    raise exception 'usage_adjustment_audit table missing';
  end if;
  if not exists (select 1 from information_schema.columns where table_name='user_permission_groups' and column_name='service_key') then
    raise exception 'user_permission_groups.service_key column missing';
  end if;
  if not exists (select 1 from information_schema.columns where table_name='permission_groups' and column_name='usage_policy_id') then
    raise exception 'permission_groups.usage_policy_id column missing';
  end if;
end $$;

-- Verify service_key was backfilled on user_permission_groups
do $$ begin
  if exists (select 1 from public.user_permission_groups where service_key is null) then
    raise exception 'service_key backfill incomplete';
  end if;
end $$;

-- The usage-policy fixtures exercise the active v2 control contract.
update public.service_capabilities cap
set usage_controls = '[
  {"key":"daily_calls","name":"Daily calls","kind":"quota","unit":"call","window":"calendar_day","minimum":0,"maximum":1000},
  {"key":"request_rate","name":"Request rate","kind":"rate_limit","unit":"request","window_seconds":60,"minimum":0,"maximum":300}
]'::jsonb
from public.services s
where cap.service_key = 'api'
  and cap.key = 'api:echo'
  and cap.catalog_version = s.active_capability_version
  and s.key = 'api';

do $$
declare target jsonb;
begin
  target := public.load_usage_target_context('api', 'api:echo');
  if target->>'resource_uri' <> 'https://api.dondone.dev'
    or target->>'permission_key' <> 'api:echo'
    or (target->>'permission_oauth_scope')::boolean is not true
    or (target->>'permission_control_count')::integer <> 2 then
    raise exception 'load_usage_target_context did not resolve the active resource Permission';
  end if;
  if public.load_usage_target_context('api', 'api:missing')->>'permission_key' is not null then
    raise exception 'load_usage_target_context resolved a missing Permission';
  end if;
end $$;

-- Verify partial unique index prevents two active groups per service
do $$
declare
  caller_group uuid;
  managed_group uuid;
begin
  select id into caller_group from public.permission_groups where service_key='api' and key='caller';
  select id into managed_group from public.permission_groups where service_key='api' and key='managed';

  -- User 2 already has caller active; trying to insert managed should fail
  begin
    insert into public.user_permission_groups(user_id, group_id, service_key, status)
    values ('00000000-0000-0000-0000-000000000002', managed_group, 'api', 'active');
    raise exception 'second active group per service unexpectedly succeeded';
  exception when unique_violation then null;
  end;
end $$;

-- Default group: set and test ensure_default_service_group
do $$
declare
  caller_group uuid;
  result uuid;
begin
  select id into caller_group from public.permission_groups where service_key='api' and key='caller';
  perform public.console_set_service_default_group('api', 'caller', '00000000-0000-0000-0000-000000000001');

  if (select default_group_id from public.services where key='api') <> caller_group then
    raise exception 'default_group_id not set';
  end if;

  -- User without a group gets the default
  select public.ensure_default_service_group('00000000-0000-0000-0000-000000000006', 'api') into result;
  if result <> caller_group then
    raise exception 'ensure_default_service_group did not assign default group';
  end if;

  -- Calling again is idempotent
  select public.ensure_default_service_group('00000000-0000-0000-0000-000000000006', 'api') into result;
  if result <> caller_group then
    raise exception 'ensure_default_service_group not idempotent';
  end if;

  -- User with existing group keeps their group
  select public.ensure_default_service_group('00000000-0000-0000-0000-000000000002', 'api') into result;
  if result <> caller_group then
    raise exception 'ensure_default_service_group replaced existing group';
  end if;

  -- Service without default returns null
  select public.ensure_default_service_group('00000000-0000-0000-0000-000000000006', 'time') into result;
  if result is not null then
    raise exception 'ensure_default_service_group returned non-null for no-default service';
  end if;
end $$;

-- Cannot disable a group that is the default
do $$ begin
  begin
    update public.permission_groups set status='disabled'
    where service_key='api' and key='caller';
    raise exception 'disabling default group unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'cannot_disable_default_group' then raise; end if;
  end;
end $$;

-- Clear default before disabling works
do $$ begin
  perform public.console_set_service_default_group('api', null, '00000000-0000-0000-0000-000000000001');
end $$;

-- Usage policy CRUD
do $$
declare
  v_policy_id uuid;
begin
  select public.console_upsert_usage_policy(
    'api', 'caller-limits', 'Caller Limits', 'Default limits', 'active',
    '[{"permission_key":"api:echo","control_key":"daily_calls","value":10},{"permission_key":"api:echo","control_key":"request_rate","value":30}]'::jsonb,
    '00000000-0000-0000-0000-000000000001'
  ) into v_policy_id;

  if v_policy_id is null then
    raise exception 'console_upsert_usage_policy returned null';
  end if;

  if (select count(*) from public.usage_policy_rules where policy_id = v_policy_id) <> 2 then
    raise exception 'policy rules not created';
  end if;

  -- Upsert replaces the complete rule set
  perform public.console_upsert_usage_policy(
    'api', 'caller-limits', 'Caller Limits Updated', null, 'active',
    '[{"permission_key":"api:echo","control_key":"daily_calls","value":20},{"permission_key":"api:echo","control_key":"request_rate","value":60}]'::jsonb,
    '00000000-0000-0000-0000-000000000001'
  );

  if (select count(*) from public.usage_policy_rules where policy_id = v_policy_id) <> 2 then
    raise exception 'upsert did not replace rules';
  end if;
  if (select name from public.usage_policies where id = v_policy_id) <> 'Caller Limits Updated' then
    raise exception 'upsert did not update name';
  end if;
end $$;

-- Policy rules must match the active catalog and be complete per Permission.
do $$ begin
  begin
    perform public.console_upsert_usage_policy(
      'api', 'incomplete-policy', 'Incomplete', null, 'active',
      '[{"permission_key":"api:echo","control_key":"daily_calls","value":10}]'::jsonb,
      '00000000-0000-0000-0000-000000000001');
    raise exception 'incomplete policy unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'usage_policy_rules_incomplete' then raise; end if;
  end;

  begin
    perform public.console_upsert_usage_policy(
      'api', 'unknown-control-policy', 'Unknown control', null, 'active',
      '[{"permission_key":"api:echo","control_key":"missing","value":10}]'::jsonb,
      '00000000-0000-0000-0000-000000000001');
    raise exception 'unknown policy control unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'usage_policy_control_not_found' then raise; end if;
  end;

  begin
    perform public.console_upsert_usage_policy(
      'api', 'out-of-range-policy', 'Out of range', null, 'active',
      '[{"permission_key":"api:echo","control_key":"daily_calls","value":1001},{"permission_key":"api:echo","control_key":"request_rate","value":30}]'::jsonb,
      '00000000-0000-0000-0000-000000000001');
    raise exception 'out-of-range policy value unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'invalid_usage_policy_rule_value' then raise; end if;
  end;
end $$;

-- Cross-service policy rule rejected
do $$ begin
  begin
    perform public.console_upsert_usage_policy(
      'api', 'bad-policy', 'Bad', null, 'active',
      '[{"permission_key":"console:admin","control_key":"x","value":1}]'::jsonb,
      '00000000-0000-0000-0000-000000000001'
    );
    raise exception 'cross-service policy rule unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'policy_rule_service_mismatch' then raise; end if;
  end;
end $$;

-- Bind policy to group
do $$ begin
  perform public.console_upsert_usage_policy(
    'api', 'empty-policy', 'Empty', null, 'active', '[]'::jsonb,
    '00000000-0000-0000-0000-000000000001');

  begin
    perform public.console_bind_group_usage_policy(
      'api', 'caller', 'empty-policy', '00000000-0000-0000-0000-000000000001');
    raise exception 'incomplete policy binding unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'usage_policy_incomplete_for_group' then raise; end if;
  end;

  perform public.console_bind_group_usage_policy(
    'api', 'caller', 'caller-limits', '00000000-0000-0000-0000-000000000001');
  if (select usage_policy_id from public.permission_groups where service_key='api' and key='caller') is null then
    raise exception 'bind_group_usage_policy did not set policy';
  end if;

  begin
    perform public.console_bind_group_usage_policy(
      'api', 'caller', null, '00000000-0000-0000-0000-000000000001');
    raise exception 'clearing a controlled active group policy unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'usage_policy_required_for_group' then raise; end if;
  end;
end $$;

-- Group creation and policy binding are one transaction.
do $$ begin
  perform public.console_create_permission_group_with_policy(
    'api', 'atomic-controlled', 'Atomic controlled', null,
    array['api:echo'], 'caller-limits',
    '00000000-0000-0000-0000-000000000001');
  if not exists (
    select 1 from public.permission_groups
    where service_key = 'api' and key = 'atomic-controlled' and usage_policy_id is not null
  ) then
    raise exception 'atomic controlled Group was not created with its policy';
  end if;

  begin
    perform public.console_create_permission_group_with_policy(
      'api', 'atomic-missing-policy', 'Atomic missing', null,
      array['api:echo'], null,
      '00000000-0000-0000-0000-000000000001');
    raise exception 'controlled Group without a policy unexpectedly succeeded';
  exception when check_violation then
    if sqlerrm <> 'usage_policy_required_for_group' then raise; end if;
  end;
  if exists (
    select 1 from public.permission_groups
    where service_key = 'api' and key = 'atomic-missing-policy'
  ) then
    raise exception 'failed atomic Group creation left a partial Group';
  end if;
end $$;

-- console_replace_user_permission_groups rejects same-service duplicate
do $$
declare
  caller_group uuid;
  managed_group uuid;
begin
  select id into caller_group from public.permission_groups where service_key='api' and key='caller';
  select id into managed_group from public.permission_groups where service_key='api' and key='managed';
  begin
    perform public.console_replace_user_permission_groups(
      '00000000-0000-0000-0000-000000000003',
      jsonb_build_array(
        jsonb_build_object('group_id', caller_group, 'expires_at', null),
        jsonb_build_object('group_id', managed_group, 'expires_at', null)
      ),
      '00000000-0000-0000-0000-000000000001'
    );
    raise exception 'same-service duplicate unexpectedly succeeded';
  exception when unique_violation then
    if sqlerrm <> 'multiple_groups_for_service' then raise; end if;
  end;
end $$;

-- Cross-service assignment succeeds (api + console)
do $$
declare
  caller_group uuid;
  admin_group uuid;
begin
  select id into caller_group from public.permission_groups where service_key='api' and key='caller';
  select id into admin_group from public.permission_groups where service_key='console' and key='admin';
  perform public.console_replace_user_permission_groups(
    '00000000-0000-0000-0000-000000000003',
    jsonb_build_array(
      jsonb_build_object('group_id', caller_group, 'expires_at', null),
      jsonb_build_object('group_id', admin_group, 'expires_at', null)
    ),
    '00000000-0000-0000-0000-000000000001'
  );
  if (select count(*) from public.user_permission_groups
      where user_id='00000000-0000-0000-0000-000000000003' and status='active') <> 2 then
    raise exception 'cross-service assignment failed';
  end if;
end $$;

-- load_usage_decision_context returns correct structure
do $$
declare
  ctx jsonb;
begin
  -- Re-bind policy for test
  perform public.console_bind_group_usage_policy(
    'api', 'caller', 'caller-limits', '00000000-0000-0000-0000-000000000001');

  select public.load_usage_decision_context(
    '00000000-0000-0000-0000-000000000003', 'api', 'api:echo'
  ) into ctx;

  if ctx->>'service_status' <> 'active' then
    raise exception 'load_usage_decision_context service_status wrong: %', ctx;
  end if;
  if ctx->>'profile_status' <> 'active' then
    raise exception 'load_usage_decision_context profile_status wrong: %', ctx;
  end if;
  if (ctx->>'permission_granted')::boolean is not true then
    raise exception 'load_usage_decision_context permission_granted wrong: %', ctx;
  end if;
  if ctx->>'policy_key' <> 'caller-limits' then
    raise exception 'load_usage_decision_context policy_key wrong: %', ctx;
  end if;
end $$;

-- RLS: new tables not visible to browser roles
do $$ begin
  if has_table_privilege('anon', 'public.usage_policies', 'select')
    or has_table_privilege('authenticated', 'public.usage_policies', 'select')
    or has_table_privilege('anon', 'public.usage_policy_rules', 'select')
    or has_table_privilege('authenticated', 'public.usage_policy_rules', 'select')
    or has_table_privilege('anon', 'public.usage_adjustment_audit', 'select')
    or has_table_privilege('authenticated', 'public.usage_adjustment_audit', 'select') then
    raise exception 'browser roles can read usage policy tables';
  end if;
  if has_function_privilege('anon', 'public.ensure_default_service_group(uuid,text)', 'execute')
    or has_function_privilege('authenticated', 'public.ensure_default_service_group(uuid,text)', 'execute')
    or has_function_privilege('anon', 'public.console_upsert_usage_policy(text,text,text,text,text,jsonb,uuid)', 'execute')
    or has_function_privilege('authenticated', 'public.console_upsert_usage_policy(text,text,text,text,text,jsonb,uuid)', 'execute')
    or has_function_privilege('anon', 'public.load_usage_decision_context(uuid,text,text)', 'execute')
    or has_function_privilege('authenticated', 'public.load_usage_decision_context(uuid,text,text)', 'execute') then
    raise exception 'browser roles can execute usage policy RPCs';
  end if;
end $$;
SQL

echo "PostgreSQL capability registry integration test passed."
