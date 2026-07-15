-- A successful idempotent capability sync must recover service-level sync
-- metadata from an earlier fetch failure, even when no catalog rows change.
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
