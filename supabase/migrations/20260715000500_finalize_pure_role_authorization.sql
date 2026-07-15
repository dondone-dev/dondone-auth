-- Finalize authorization on service-owned roles only. The legacy direct-grant
-- table is removed only after every live grant can be represented by Caller.
begin;

do $$
declare
  v_caller_group uuid;
  v_permission_keys text[];
  v_unexpected_permissions text;
begin
  select id
    into v_caller_group
  from public.permission_groups
  where service_key = 'api'
    and key = 'caller'
    and is_system
    and status = 'active';

  if v_caller_group is null then
    raise exception 'api_caller_role_must_be_active_system_role';
  end if;

  select coalesce(array_agg(permission_key order by permission_key), '{}'::text[])
    into v_permission_keys
  from public.permission_group_permissions
  where group_id = v_caller_group;

  if v_permission_keys <> array['api:echo']::text[] then
    raise exception 'api_caller_role_requires_exact_api_echo_permission';
  end if;

  select string_agg(distinct permission_key, ', ' order by permission_key)
    into v_unexpected_permissions
  from public.user_permissions
  where status = 'active'
    and (expires_at is null or expires_at > now())
    and permission_key <> 'api:echo';

  if v_unexpected_permissions is not null then
    raise exception 'unexpected_active_direct_permission: %', v_unexpected_permissions;
  end if;

  insert into public.user_permission_groups(
    user_id, group_id, status, granted_by, expires_at
  )
  select
    direct_grant.user_id,
    v_caller_group,
    'active',
    direct_grant.granted_by,
    direct_grant.expires_at
  from public.user_permissions direct_grant
  where direct_grant.permission_key = 'api:echo'
    and direct_grant.status = 'active'
    and (direct_grant.expires_at is null or direct_grant.expires_at > now())
  on conflict (user_id, group_id) do update
  set status = 'active',
      granted_by = coalesce(excluded.granted_by, user_permission_groups.granted_by),
      expires_at = case
        when excluded.expires_at is null or user_permission_groups.expires_at is null then null
        else greatest(excluded.expires_at, user_permission_groups.expires_at)
      end;
end;
$$;

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
  on conflict (id) do update set
    email = excluded.email,
    display_name = coalesce(public.profiles.display_name, excluded.display_name),
    avatar_url = coalesce(public.profiles.avatar_url, excluded.avatar_url);

  return new;
end;
$$;

drop table public.user_permissions;

commit;
