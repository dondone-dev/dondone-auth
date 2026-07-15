-- Service-owned Capability Registry schema.
-- Adds immutable imported capability versions, normalized catalog rows,
-- capability-sync state on services, and an active-capabilities read model.
-- Run once after authorization.sql and 20260713_add_service_redirect_uris.sql.

-- 1. Extend services with capability-sync metadata
alter table public.services
  add column if not exists resource_uri text,
  add column if not exists capability_sync_status text not null default 'not_configured'
    check (capability_sync_status in ('not_configured', 'pending_review', 'active', 'failed')),
  add column if not exists active_capability_version text,
  add column if not exists capability_last_synced_at timestamptz,
  add column if not exists capability_last_error text;

-- A protected-resource URI is its stable OAuth resource identity. It is
-- globally unique when configured and cannot be rebound after a catalog has
-- been activated for that service.
create unique index if not exists services_resource_uri_unique
  on public.services(resource_uri) where resource_uri is not null;

create or replace function public.prevent_active_resource_uri_change()
returns trigger language plpgsql set search_path = public
as $$
begin
  if new.resource_uri is distinct from old.resource_uri
    and exists (
      select 1 from public.service_capability_versions
      where service_key = old.key
    ) then
    raise exception using errcode = '23514', message = 'resource_uri_locked';
  end if;
  return new;
end;
$$;

drop trigger if exists services_lock_active_resource_uri on public.services;
create trigger services_lock_active_resource_uri
before update of resource_uri on public.services
for each row execute function public.prevent_active_resource_uri_change();

-- 2. Immutable imported manifest versions
create table if not exists public.service_capability_versions (
  id uuid primary key default gen_random_uuid(),
  service_key text not null references public.services(key) on delete cascade,
  catalog_version text not null,
  manifest_sha256 text not null,
  manifest jsonb not null,
  import_status text not null
    check (import_status in ('pending_review', 'approved', 'rejected', 'superseded', 'failed')),
  fetched_at timestamptz not null default now(),
  approved_at timestamptz,
  approved_by uuid references public.profiles(id),
  rejection_reason text,
  unique (service_key, catalog_version),
  unique (service_key, manifest_sha256)
);

create index if not exists service_capability_versions_active_idx
  on public.service_capability_versions(service_key, import_status, fetched_at desc);

-- 3. Normalized permission rows per version
create table if not exists public.service_capabilities (
  service_key text not null references public.services(key) on delete cascade,
  catalog_version text not null,
  key text not null,
  description text not null,
  oauth_scope boolean not null default true,
  primary key (service_key, catalog_version, key),
  foreign key (service_key, catalog_version)
    references public.service_capability_versions(service_key, catalog_version)
);

-- 4. Service-defined roles per version
create table if not exists public.service_capability_roles (
  service_key text not null,
  catalog_version text not null,
  key text not null,
  name text not null,
  description text,
  primary key (service_key, catalog_version, key),
  foreign key (service_key, catalog_version)
    references public.service_capability_versions(service_key, catalog_version)
);

-- 5. Role-permission mapping per version
create table if not exists public.service_capability_role_permissions (
  service_key text not null,
  catalog_version text not null,
  role_key text not null,
  permission_key text not null,
  primary key (service_key, catalog_version, role_key, permission_key),
  foreign key (service_key, catalog_version, role_key)
    references public.service_capability_roles(service_key, catalog_version, key),
  foreign key (service_key, catalog_version, permission_key)
    references public.service_capabilities(service_key, catalog_version, key)
);

-- 6. Append-only audit trail for sync, approval, rejection, and grant changes
create table if not exists public.service_capability_audit (
  id uuid primary key default gen_random_uuid(),
  occurred_at timestamptz not null default now(),
  actor uuid references public.profiles(id),
  service_key text not null,
  catalog_version text,
  action text not null
    check (action in (
      'sync_succeeded', 'sync_failed',
      'approved', 'rejected', 'superseded',
      'grant_changed')),
  outcome text not null,
  detail jsonb
);

create index if not exists service_capability_audit_service_idx
  on public.service_capability_audit(service_key, occurred_at desc);

-- 7. Active-capabilities read model (approved + active service only)
create or replace view public.active_service_capabilities as
select c.service_key, c.key, c.description, c.oauth_scope, v.catalog_version
from public.service_capabilities c
join public.service_capability_versions v
  on v.service_key = c.service_key
 and v.catalog_version = c.catalog_version
join public.services s on s.key = c.service_key
where v.import_status = 'approved'
  and s.active_capability_version = c.catalog_version
  and s.status = 'active';

-- Resource-token hot path. This deliberately exposes no redirect URI, service
-- description, sync error, or other mutable service metadata.
create or replace view public.active_resource_capabilities as
select s.resource_uri, c.service_key, c.key, c.description, c.oauth_scope, c.catalog_version
from public.active_service_capabilities c
join public.services s on s.key = c.service_key
where s.resource_uri is not null;

-- Import one immutable version, its normalized catalog, service sync state,
-- and audit entry in one PostgreSQL transaction. An identical version/hash is
-- a true no-op for catalog state and retains its current status.
create or replace function public.import_service_capability_version(
  p_service_key text,
  p_catalog_version text,
  p_manifest_sha256 text,
  p_manifest jsonb,
  p_actor uuid
) returns table(import_status text, created boolean)
language plpgsql security definer set search_path = public
as $$
declare
  existing public.service_capability_versions%rowtype;
  service_row public.services%rowtype;
begin
  select * into service_row from public.services where key = p_service_key for update;
  if not found then raise exception 'service_not_found'; end if;
  if (p_manifest->>'resource') is distinct from service_row.resource_uri then
    raise exception using errcode = '23514', message = 'capability_resource_mismatch';
  end if;

  select * into existing from public.service_capability_versions
  where service_key = p_service_key and catalog_version = p_catalog_version
  for update;

  if found then
    if existing.manifest_sha256 <> p_manifest_sha256 then
      raise exception using errcode = '23505', message = 'catalog_version_conflict';
    end if;
    update public.services set
      capability_sync_status = case
        when active_capability_version is not null then 'active'
        when existing.import_status = 'pending_review' then 'pending_review'
        else 'failed'
      end,
      capability_last_synced_at = now(),
      capability_last_error = null
    where key = p_service_key;
    insert into public.service_capability_audit(actor, service_key, catalog_version, action, outcome, detail)
    values (p_actor, p_service_key, p_catalog_version, 'sync_succeeded', 'unchanged',
      jsonb_build_object('manifest_sha256', p_manifest_sha256, 'status', existing.import_status));
    return query select existing.import_status, false;
    return;
  end if;

  insert into public.service_capability_versions(service_key, catalog_version, manifest_sha256, manifest, import_status)
  values (p_service_key, p_catalog_version, p_manifest_sha256, p_manifest, 'pending_review');

  insert into public.service_capabilities(service_key, catalog_version, key, description, oauth_scope)
  select p_service_key, p_catalog_version, permission->>'key', permission->>'description',
    (p_manifest->'scopes_supported') ? (permission->>'key')
  from jsonb_array_elements(p_manifest->'dondone_capabilities'->'permissions') permission;

  insert into public.service_capability_roles(service_key, catalog_version, key, name, description)
  select p_service_key, p_catalog_version, role->>'key', role->>'name', role->>'description'
  from jsonb_array_elements(p_manifest->'dondone_capabilities'->'roles') role;

  insert into public.service_capability_role_permissions(service_key, catalog_version, role_key, permission_key)
  select p_service_key, p_catalog_version, role->>'key', jsonb_array_elements_text(role->'permission_keys')
  from jsonb_array_elements(p_manifest->'dondone_capabilities'->'roles') role;

  update public.services set
    capability_sync_status = 'pending_review', capability_last_synced_at = now(), capability_last_error = null
  where key = p_service_key;
  if not found then raise exception 'service_not_found'; end if;

  insert into public.service_capability_audit(actor, service_key, catalog_version, action, outcome, detail)
  values (p_actor, p_service_key, p_catalog_version, 'sync_succeeded', 'pending_review',
    jsonb_build_object('manifest_sha256', p_manifest_sha256));
  return query select 'pending_review'::text, true;
end;
$$;

create or replace function public.record_service_capability_sync_failure(
  p_service_key text, p_actor uuid, p_error text
) returns void language plpgsql security definer set search_path = public
as $$
begin
  update public.services set capability_sync_status = 'failed', capability_last_synced_at = now(), capability_last_error = p_error
  where key = p_service_key;
  insert into public.service_capability_audit(actor, service_key, action, outcome, detail)
  values (p_actor, p_service_key, 'sync_failed', 'error', jsonb_build_object('error', p_error));
end;
$$;

-- Approval also projects service-owned roles as read-only system groups. The
-- caller supplies the active version it diffed against; a concurrent approval
-- causes a conflict instead of approving against stale review data.
create or replace function public.approve_service_capability_version(
  p_service_key text,
  p_catalog_version text,
  p_actor uuid,
  p_expected_active_version text,
  p_detail jsonb
) returns void language plpgsql security definer set search_path = public
as $$
declare
  target public.service_capability_versions%rowtype;
  service_row public.services%rowtype;
  previous_version text;
begin
  select * into service_row from public.services where key = p_service_key for update;
  if not found then raise exception 'service_not_found'; end if;
  if service_row.active_capability_version is distinct from p_expected_active_version then
    raise exception using errcode = '40001', message = 'active_version_changed';
  end if;

  select * into target from public.service_capability_versions
  where service_key = p_service_key and catalog_version = p_catalog_version for update;
  if not found then raise exception 'version_not_found'; end if;
  if (target.manifest->>'resource') is distinct from service_row.resource_uri then
    raise exception using errcode = '23514', message = 'capability_resource_mismatch';
  end if;
  if target.import_status not in ('pending_review', 'superseded', 'rejected') then
    raise exception 'invalid_version_status:%', target.import_status;
  end if;
  previous_version := service_row.active_capability_version;

  if previous_version is not null and previous_version <> p_catalog_version then
    update public.service_capability_versions set import_status = 'superseded'
    where service_key = p_service_key and catalog_version = previous_version;
    insert into public.service_capability_audit(actor, service_key, catalog_version, action, outcome, detail)
    values (p_actor, p_service_key, previous_version, 'superseded', 'superseded',
      jsonb_build_object('replaced_by', p_catalog_version));
  end if;

  update public.service_capability_versions set import_status = 'approved', approved_at = now(), approved_by = p_actor,
    rejection_reason = null where id = target.id;
  update public.services set active_capability_version = p_catalog_version, capability_sync_status = 'active',
    capability_last_error = null where key = p_service_key;

  insert into public.permissions(key, service_key, description)
  select key, service_key, description from public.service_capabilities
  where service_key = p_service_key and catalog_version = p_catalog_version
  on conflict (key) do update set service_key = excluded.service_key, description = excluded.description;

  update public.permission_groups set status = 'disabled'
  where service_key = p_service_key and is_system and key not in (
    select key from public.service_capability_roles where service_key = p_service_key and catalog_version = p_catalog_version
  );
  if exists (
    select 1 from public.permission_groups pg
    join public.service_capability_roles role on role.service_key = pg.service_key and role.key = pg.key
    where pg.service_key = p_service_key and role.catalog_version = p_catalog_version and not pg.is_system
  ) then
    raise exception 'system_role_key_conflicts_with_managed_group';
  end if;
  insert into public.permission_groups(service_key, key, name, description, status, is_system)
  select service_key, key, name, description, 'active', true from public.service_capability_roles
  where service_key = p_service_key and catalog_version = p_catalog_version
  on conflict (service_key, key) do update set name = excluded.name, description = excluded.description,
    status = 'active' where permission_groups.is_system;

  delete from public.permission_group_permissions pgp using public.permission_groups pg
  where pgp.group_id = pg.id and pg.service_key = p_service_key and pg.is_system;
  insert into public.permission_group_permissions(group_id, permission_key)
  select pg.id, rp.permission_key
  from public.service_capability_role_permissions rp
  join public.permission_groups pg on pg.service_key = rp.service_key and pg.key = rp.role_key and pg.is_system
  where rp.service_key = p_service_key and rp.catalog_version = p_catalog_version;

  insert into public.service_capability_audit(actor, service_key, catalog_version, action, outcome, detail)
  values (p_actor, p_service_key, p_catalog_version, 'approved', 'approved',
    coalesce(p_detail, '{}'::jsonb) || jsonb_build_object('previous_version', previous_version));
end;
$$;

create or replace function public.reject_service_capability_version(
  p_service_key text, p_catalog_version text, p_actor uuid, p_reason text
) returns void language plpgsql security definer set search_path = public
as $$
begin
  if btrim(coalesce(p_reason, '')) = '' then raise exception 'rejection_reason_required'; end if;
  update public.service_capability_versions set import_status = 'rejected', rejection_reason = btrim(p_reason)
  where service_key = p_service_key and catalog_version = p_catalog_version and import_status = 'pending_review';
  if not found then raise exception 'invalid_version_status'; end if;
  insert into public.service_capability_audit(actor, service_key, catalog_version, action, outcome, detail)
  values (p_actor, p_service_key, p_catalog_version, 'rejected', 'rejected', jsonb_build_object('reason', btrim(p_reason)));
end;
$$;

-- Console-managed groups are grant bundles, but their permissions must come
-- exclusively from the owning service's active approved catalog. Group row,
-- permission mapping, and audit record are committed as one transaction.
create or replace function public.console_create_permission_group(
  p_service_key text,
  p_group_key text,
  p_name text,
  p_description text,
  p_permission_keys text[],
  p_actor uuid
) returns uuid language plpgsql security definer set search_path = public
as $$
declare
  created_id uuid;
  requested text[] := coalesce(p_permission_keys, array[]::text[]);
begin
  if cardinality(requested) <> (select count(distinct key) from unnest(requested) key) then
    raise exception using errcode = '23514', message = 'duplicate_permission_keys';
  end if;
  if (select count(*) from public.active_service_capabilities
      where service_key = p_service_key and key = any(requested)) <> cardinality(requested) then
    raise exception using errcode = '23514', message = 'permission_not_in_active_service_catalog';
  end if;

  insert into public.permission_groups(service_key, key, name, description, is_system)
  values (p_service_key, p_group_key, p_name, p_description, false)
  returning id into created_id;
  insert into public.permission_group_permissions(group_id, permission_key)
  select created_id, key from unnest(requested) key;
  insert into public.service_capability_audit(actor, service_key, action, outcome, detail)
  values (p_actor, p_service_key, 'grant_changed', 'applied',
    jsonb_build_object('target','permission_group','group_id',created_id,
      'group_key',p_group_key,'permission_keys',to_jsonb(requested),'operation','created'));
  return created_id;
end;
$$;

create or replace function public.console_update_permission_group(
  p_service_key text,
  p_group_key text,
  p_name text,
  p_description text,
  p_status text,
  p_permission_keys text[],
  p_actor uuid
) returns uuid language plpgsql security definer set search_path = public
as $$
declare
  target public.permission_groups%rowtype;
  requested text[] := coalesce(p_permission_keys, array[]::text[]);
  previous_permissions text[];
begin
  select * into target from public.permission_groups
  where service_key = p_service_key and key = p_group_key for update;
  if not found then raise exception 'group_not_found'; end if;
  if target.is_system then
    raise exception using errcode = '23514', message = 'system_role_read_only';
  end if;
  if p_status not in ('active','disabled') then
    raise exception using errcode = '23514', message = 'invalid_group_status';
  end if;
  if cardinality(requested) <> (select count(distinct key) from unnest(requested) key) then
    raise exception using errcode = '23514', message = 'duplicate_permission_keys';
  end if;
  if (select count(*) from public.active_service_capabilities
      where service_key = p_service_key and key = any(requested)) <> cardinality(requested) then
    raise exception using errcode = '23514', message = 'permission_not_in_active_service_catalog';
  end if;
  select coalesce(array_agg(permission_key order by permission_key), array[]::text[])
    into previous_permissions from public.permission_group_permissions where group_id = target.id;

  update public.permission_groups set name=p_name, description=p_description, status=p_status
  where id=target.id;
  delete from public.permission_group_permissions where group_id=target.id;
  insert into public.permission_group_permissions(group_id, permission_key)
  select target.id, key from unnest(requested) key;
  insert into public.service_capability_audit(actor, service_key, action, outcome, detail)
  values (p_actor, p_service_key, 'grant_changed', 'applied',
    jsonb_build_object('target','permission_group','group_id',target.id,
      'group_key',p_group_key,'previous_permission_keys',to_jsonb(previous_permissions),
      'permission_keys',to_jsonb(requested),'operation','updated'));
  return target.id;
end;
$$;

-- Replace all active group grants for one user. Validation, expiry updates,
-- revocation/reactivation, and one audit row per affected service are atomic.
create or replace function public.console_replace_user_permission_groups(
  p_user_id uuid,
  p_grants jsonb,
  p_actor uuid
) returns void language plpgsql security definer set search_path = public
as $$
declare
  affected_service text;
  added_ids jsonb;
  revoked_ids jsonb;
  expiry_ids jsonb;
begin
  if jsonb_typeof(p_grants) <> 'array' then
    raise exception using errcode = '22023', message = 'invalid_grants';
  end if;
  if (select count(*) from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz))
      <> (select count(distinct group_id) from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz)) then
    raise exception using errcode = '23514', message = 'duplicate_group_grants';
  end if;
  if exists (
    select 1 from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz)
    left join public.permission_groups pg on pg.id=x.group_id
    where pg.id is null or pg.status <> 'active'
  ) then raise exception using errcode = '23514', message = 'unknown_or_inactive_group'; end if;

  perform 1 from public.user_permission_groups where user_id=p_user_id for update;

  for affected_service in
    with requested as (
      select * from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz)
    ), changes as (
      select pg.service_key
      from requested r join public.permission_groups pg on pg.id=r.group_id
      left join public.user_permission_groups current
        on current.user_id=p_user_id and current.group_id=r.group_id
      where current.id is null or current.status <> 'active' or current.expires_at is distinct from r.expires_at
      union
      select pg.service_key
      from public.user_permission_groups current join public.permission_groups pg on pg.id=current.group_id
      left join requested r on r.group_id=current.group_id
      where current.user_id=p_user_id and current.status='active' and r.group_id is null
    ) select distinct service_key from changes
  loop
    with requested as (
      select * from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz)
    )
    select
      coalesce(jsonb_agg(r.group_id::text) filter (where current.id is null or current.status <> 'active'),'[]'::jsonb),
      coalesce(jsonb_agg(r.group_id::text) filter (where current.status='active' and current.expires_at is distinct from r.expires_at),'[]'::jsonb)
    into added_ids, expiry_ids
    from requested r join public.permission_groups pg on pg.id=r.group_id
    left join public.user_permission_groups current on current.user_id=p_user_id and current.group_id=r.group_id
    where pg.service_key=affected_service;

    with requested as (
      select * from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz)
    )
    select coalesce(jsonb_agg(current.group_id::text),'[]'::jsonb) into revoked_ids
    from public.user_permission_groups current join public.permission_groups pg on pg.id=current.group_id
    left join requested r on r.group_id=current.group_id
    where current.user_id=p_user_id and current.status='active' and r.group_id is null
      and pg.service_key=affected_service;

    insert into public.service_capability_audit(actor, service_key, action, outcome, detail)
    values (p_actor, affected_service, 'grant_changed', 'applied',
      jsonb_build_object('target','user_permission_groups','user_id',p_user_id,
        'added_group_ids',added_ids,'revoked_group_ids',revoked_ids,
        'expiry_changed_group_ids',expiry_ids));
  end loop;

  insert into public.user_permission_groups(user_id,group_id,status,granted_by,expires_at)
  select p_user_id,x.group_id,'active',p_actor,x.expires_at
  from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz)
  on conflict (user_id,group_id) do update set status='active',granted_by=excluded.granted_by,
    expires_at=excluded.expires_at;
  update public.user_permission_groups current set status='revoked',granted_by=p_actor
  where current.user_id=p_user_id and current.status='active'
    and not exists (
      select 1 from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz)
      where x.group_id=current.group_id
    );
end;
$$;

-- 8. RLS: deny-all for anon on raw tables; service-role bypasses RLS.
alter table public.service_capability_versions enable row level security;
alter table public.service_capabilities enable row level security;
alter table public.service_capability_roles enable row level security;
alter table public.service_capability_role_permissions enable row level security;
alter table public.service_capability_audit enable row level security;

-- Only the approved projection is exposed to anon for token-issuance scope checks.
grant select on public.active_service_capabilities to anon;
grant select on public.active_resource_capabilities to anon;

-- service_role needs full access for admin operations.
grant select, insert, update, delete on public.service_capability_versions to service_role;
grant select, insert, update, delete on public.service_capabilities to service_role;
grant select, insert, update, delete on public.service_capability_roles to service_role;
grant select, insert, update, delete on public.service_capability_role_permissions to service_role;
grant select, insert on public.service_capability_audit to service_role;

revoke all on function public.import_service_capability_version(text,text,text,jsonb,uuid) from public;
revoke all on function public.record_service_capability_sync_failure(text,uuid,text) from public;
revoke all on function public.approve_service_capability_version(text,text,uuid,text,jsonb) from public;
revoke all on function public.reject_service_capability_version(text,text,uuid,text) from public;
revoke all on function public.console_create_permission_group(text,text,text,text,text[],uuid) from public;
revoke all on function public.console_update_permission_group(text,text,text,text,text,text[],uuid) from public;
revoke all on function public.console_replace_user_permission_groups(uuid,jsonb,uuid) from public;
grant execute on function public.import_service_capability_version(text,text,text,jsonb,uuid) to service_role;
grant execute on function public.record_service_capability_sync_failure(text,uuid,text) to service_role;
grant execute on function public.approve_service_capability_version(text,text,uuid,text,jsonb) to service_role;
grant execute on function public.reject_service_capability_version(text,text,uuid,text) to service_role;
grant execute on function public.console_create_permission_group(text,text,text,text,text[],uuid) to service_role;
grant execute on function public.console_update_permission_group(text,text,text,text,text,text[],uuid) to service_role;
grant execute on function public.console_replace_user_permission_groups(uuid,jsonb,uuid) to service_role;

-- Verification queries (run manually, do not leave in automated migration):
--
-- 1. Uniqueness: expect zero rows
--   select service_key, catalog_version
--   from public.service_capability_versions
--   group by service_key, catalog_version having count(*) > 1;
--
-- 2. FK violation: expect error
--   insert into public.service_capabilities
--     (service_key, catalog_version, key, description)
--   values ('missing', '1', 'missing:read', 'must fail');
