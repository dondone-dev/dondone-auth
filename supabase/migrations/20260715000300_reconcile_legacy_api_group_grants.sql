-- Reconcile legacy grants after service-owned API roles are projected.
--
-- 1. The old api/basic role was replaced by api/caller. Preserve its active
--    memberships and expiry without keeping grants attached to a disabled role.
-- 2. Old Console versions allowed groups from another service to carry the
--    API VIP marker. Preserve only that marker as a direct user permission;
--    do not expand it to the api/vip role (which would also grant api:echo).
do $$
declare
  v_basic_group uuid;
  v_caller_group uuid;
begin
  select id into v_basic_group
  from public.permission_groups
  where service_key = 'api' and key = 'basic';

  select id into v_caller_group
  from public.permission_groups
  where service_key = 'api' and key = 'caller' and is_system and status = 'active';

  if v_basic_group is null or v_caller_group is null then
    raise exception 'api_basic_to_caller_migration_requires_both_groups';
  end if;

  insert into public.user_permission_groups(
    user_id, group_id, status, granted_by, expires_at
  )
  select
    legacy.user_id,
    v_caller_group,
    'active',
    legacy.granted_by,
    legacy.expires_at
  from public.user_permission_groups legacy
  where legacy.group_id = v_basic_group and legacy.status = 'active'
  on conflict (user_id, group_id) do update
  set status = 'active',
      granted_by = coalesce(excluded.granted_by, user_permission_groups.granted_by),
      expires_at = case
        when excluded.expires_at is null or user_permission_groups.expires_at is null then null
        else greatest(excluded.expires_at, user_permission_groups.expires_at)
      end;

  update public.user_permission_groups
  set status = 'revoked'
  where group_id = v_basic_group and status = 'active';

  insert into public.user_permissions(
    user_id, permission_key, status, granted_by, expires_at
  )
  select
    membership.user_id,
    'api:tier:vip',
    'active',
    (array_agg(membership.granted_by order by membership.created_at desc)
      filter (where membership.granted_by is not null))[1],
    case
      when bool_or(membership.expires_at is null) then null
      else max(membership.expires_at)
    end
  from public.user_permission_groups membership
  join public.permission_groups legacy_group on legacy_group.id = membership.group_id
  join public.permission_group_permissions mapping on mapping.group_id = legacy_group.id
  where legacy_group.service_key <> 'api'
    and mapping.permission_key = 'api:tier:vip'
    and membership.status = 'active'
  group by membership.user_id
  on conflict (user_id, permission_key) do update
  set status = 'active',
      granted_by = coalesce(excluded.granted_by, user_permissions.granted_by),
      expires_at = case
        when excluded.expires_at is null or user_permissions.expires_at is null then null
        else greatest(excluded.expires_at, user_permissions.expires_at)
      end;

  insert into public.service_capability_audit(
    actor, service_key, action, outcome, detail
  )
  select
    null,
    legacy_group.service_key,
    'grant_changed',
    'migrated',
    jsonb_build_object(
      'migration', '20260715000300_reconcile_legacy_api_group_grants',
      'removed_permission_key', 'api:tier:vip',
      'preserved_as', 'direct_user_permission'
    )
  from public.permission_groups legacy_group
  join public.permission_group_permissions mapping on mapping.group_id = legacy_group.id
  where legacy_group.service_key <> 'api'
    and mapping.permission_key = 'api:tier:vip'
  group by legacy_group.service_key;

  delete from public.permission_group_permissions mapping
  using public.permission_groups legacy_group
  where mapping.group_id = legacy_group.id
    and legacy_group.service_key <> 'api'
    and mapping.permission_key = 'api:tier:vip';
end;
$$;
