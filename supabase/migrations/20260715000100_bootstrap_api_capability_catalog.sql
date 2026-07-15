-- Bootstrap the first production API catalog through the same transactional
-- import/approval functions used by the Auth admin API. Later catalog releases
-- must use the normal sync and Console review flow.
do $$
declare
  v_actor uuid;
  v_status text;
  v_created boolean;
  v_active_version text;
  v_manifest constant jsonb :=
    '{"resource":"https://api.dondone.dev","resource_name":"Dondone API","authorization_servers":["https://auth.dondone.dev"],"scopes_supported":["api:echo"],"dondone_capabilities":{"schema_version":1,"catalog_version":"2026-07-14.2","permissions":[{"key":"api:echo","description":"Call the echo API."},{"key":"api:tier:vip","description":"Receive the VIP API response tier."}],"roles":[{"key":"caller","name":"Caller","description":"Can call the echo API.","permission_keys":["api:echo"]},{"key":"vip","name":"VIP Caller","description":"Can call the echo API with the VIP response tier.","permission_keys":["api:echo","api:tier:vip"]}]}}'::jsonb;
begin
  select candidate.user_id
    into v_actor
  from (
    select up.user_id
    from public.user_permissions up
    join public.profiles profile on profile.id = up.user_id and profile.status = 'active'
    where up.permission_key = 'console:admin'
      and up.status = 'active'
      and (up.expires_at is null or up.expires_at > now())
    union
    select upg.user_id
    from public.user_permission_groups upg
    join public.profiles profile on profile.id = upg.user_id and profile.status = 'active'
    join public.permission_groups pg on pg.id = upg.group_id and pg.status = 'active'
    join public.permission_group_permissions pgp on pgp.group_id = pg.id
    where pgp.permission_key = 'console:admin'
      and upg.status = 'active'
      and (upg.expires_at is null or upg.expires_at > now())
  ) candidate
  order by candidate.user_id
  limit 1;

  if v_actor is null then
    raise exception 'bootstrap_requires_active_console_admin';
  end if;

  update public.services
  set resource_uri = 'https://api.dondone.dev'
  where key = 'api' and resource_uri is null;

  if (select resource_uri from public.services where key = 'api')
      is distinct from 'https://api.dondone.dev' then
    raise exception 'api_resource_uri_conflict';
  end if;

  select imported.import_status, imported.created
    into v_status, v_created
  from public.import_service_capability_version(
    'api',
    '2026-07-14.2',
    'ee301c4edc06c0500cce8416915fb1ce179a8851f02e00a368e53041aefa4b1e',
    v_manifest,
    v_actor
  ) imported;

  if v_status <> 'approved' then
    select active_capability_version into v_active_version
    from public.services where key = 'api';

    perform public.approve_service_capability_version(
      'api',
      '2026-07-14.2',
      v_actor,
      v_active_version,
      jsonb_build_object(
        'bootstrap', true,
        'manifest_sha256', 'ee301c4edc06c0500cce8416915fb1ce179a8851f02e00a368e53041aefa4b1e'
      )
    );
  end if;
end;
$$;
