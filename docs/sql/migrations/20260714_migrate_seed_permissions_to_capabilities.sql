-- Migrate seeded permission definitions to the approved service capability catalog.
-- Prerequisites: The relevant service manifests must have been published, synced,
-- and approved before running this migration.
--
-- This migration maps existing permissions (api:echo, api:tier:vip, ai:chat) to their
-- respective approved catalogs while preserving all user_permissions and
-- permission_group_permissions references.

begin;

-- 1. Verify the required approved versions exist
do $$
declare
  api_version text;
  ai_version text;
begin
  select active_capability_version into api_version
    from public.services where key = 'api';
  if api_version is null then
    raise exception 'Service "api" has no approved capability version. Approve the API manifest first.';
  end if;

  select active_capability_version into ai_version
    from public.services where key = 'ai';
  -- ai is optional — it may not have a manifest yet
end;
$$;

-- 2. Fail before touching grants unless the API release already owns both
-- target keys. In particular, ../dondone-api must publish api:tier:vip (not
-- tier:vip), and that catalog must be synced and approved first.
do $$
begin
  if not exists (
    select 1 from public.active_service_capabilities
    where service_key = 'api' and key = 'api:echo'
  ) or not exists (
    select 1 from public.active_service_capabilities
    where service_key = 'api' and key = 'api:tier:vip'
  ) then
    raise exception 'Approved API catalog must contain api:echo and api:tier:vip before seed migration.';
  end if;
end;
$$;

-- 3. Rename the legacy cross-namespace VIP key while preserving every grant.
insert into public.permissions(key, service_key, description)
select 'api:tier:vip', 'api', description from public.permissions where key = 'tier:vip'
on conflict (key) do update set service_key = 'api', description = excluded.description;
insert into public.user_permissions(user_id, permission_key, status, granted_by, expires_at, created_at)
select user_id, 'api:tier:vip', status, granted_by, expires_at, created_at
from public.user_permissions where permission_key = 'tier:vip'
on conflict (user_id, permission_key) do nothing;
delete from public.user_permissions where permission_key = 'tier:vip';
insert into public.permission_group_permissions(group_id, permission_key)
select group_id, 'api:tier:vip' from public.permission_group_permissions where permission_key = 'tier:vip'
on conflict do nothing;
delete from public.permission_group_permissions where permission_key = 'tier:vip';
delete from public.permissions where key = 'tier:vip';

-- 4. Verify that approved catalog contains the migrated keys
do $$
declare
  missing text;
begin
  select string_agg(p.key, ', ') into missing
  from public.permissions p
  left join public.active_service_capabilities asc_cap
    on asc_cap.key = p.key and asc_cap.service_key = p.service_key
  where p.key in ('api:echo', 'api:tier:vip')
    and asc_cap.key is null;

  if missing is not null then
    raise exception 'Permission(s) % not found in approved catalogs. Approve matching manifests first.', missing;
  end if;
end;
$$;

-- 5. Update legacy permission descriptions to match the approved catalog
update public.permissions p
set description = asc_cap.description
from public.active_service_capabilities asc_cap
where asc_cap.key = p.key
  and asc_cap.service_key = p.service_key
  and p.key in ('api:echo', 'api:tier:vip', 'ai:chat')
  and p.description <> asc_cap.description;

-- 6. Log the migration
insert into public.service_capability_audit
  (service_key, action, outcome, detail)
values
  ('api', 'grant_changed', 'migrated', '{"note":"Seed permissions mapped to approved catalog"}');

commit;
