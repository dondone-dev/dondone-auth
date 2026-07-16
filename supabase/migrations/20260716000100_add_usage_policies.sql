-- Usage Policy system: policies, rules, adjustment audit, membership constraints,
-- enforcement triggers, console RPCs, and capability catalog extensions.

-- =============================================================================
-- 1. Schema changes
-- =============================================================================

alter table public.services
  add column default_group_id uuid;

alter table public.service_capabilities
  add column name text,
  add column usage_controls jsonb not null default '[]'::jsonb;

create table public.usage_policies (
  id uuid primary key default gen_random_uuid(),
  service_key text not null references public.services(key) on delete cascade,
  key text not null,
  name text not null,
  description text,
  status text not null default 'active' check (status in ('active', 'disabled')),
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (service_key, key)
);

create table public.usage_policy_rules (
  policy_id uuid not null references public.usage_policies(id) on delete cascade,
  permission_key text not null references public.permissions(key) on delete cascade,
  control_key text not null,
  value jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (policy_id, permission_key, control_key)
);

create table public.usage_adjustment_audit (
  operation_id uuid primary key,
  actor uuid not null references public.profiles(id),
  user_id uuid not null references public.profiles(id),
  service_key text not null references public.services(key),
  permission_key text not null references public.permissions(key),
  control_key text not null,
  delta integer not null check (delta <> 0),
  reason text not null,
  status text not null check (status in ('pending', 'applied', 'failed')),
  result jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.permission_groups
  add column usage_policy_id uuid references public.usage_policies(id) on delete restrict;

alter table public.user_permission_groups
  add column service_key text;

-- =============================================================================
-- 2. Backfill and constraints
-- =============================================================================

update public.user_permission_groups upg
set service_key = pg.service_key
from public.permission_groups pg
where pg.id = upg.group_id;

alter table public.user_permission_groups
  alter column service_key set not null;

-- =============================================================================
-- 3. Expired membership reconciliation
-- =============================================================================

update public.user_permission_groups
set status = 'revoked', updated_at = now()
where status = 'active'
  and expires_at is not null
  and expires_at <= now();

-- =============================================================================
-- 4. Conflict preflight check
-- =============================================================================

do $$ begin
  if exists (
    select 1 from public.user_permission_groups upg
    join public.permission_groups pg on pg.id = upg.group_id
    where upg.status = 'active'
      and (upg.expires_at is null or upg.expires_at > now())
    group by upg.user_id, pg.service_key
    having count(*) > 1
  ) then
    raise exception 'multiple_active_groups_per_service'
      using errcode = '23505';
  end if;
end $$;

-- =============================================================================
-- 5. Partial unique index
-- =============================================================================

create unique index user_permission_groups_one_active_group_per_service
  on public.user_permission_groups (user_id, service_key)
  where status = 'active';

-- =============================================================================
-- 6. Enforcement triggers
-- =============================================================================

create or replace function public.enforce_membership_service_key()
returns trigger language plpgsql as $$
declare
  group_service_key text;
begin
  select service_key into group_service_key
  from public.permission_groups where id = new.group_id;
  if group_service_key is null then
    raise exception 'group_not_found' using errcode = '23514';
  end if;
  if new.service_key <> group_service_key then
    raise exception 'membership_service_key_mismatch' using errcode = '23514';
  end if;
  return new;
end $$;

create trigger user_permission_groups_enforce_service_key
before insert or update on public.user_permission_groups
for each row execute function public.enforce_membership_service_key();

create or replace function public.enforce_default_group_service()
returns trigger language plpgsql as $$
begin
  if new.default_group_id is not null then
    if not exists (
      select 1 from public.permission_groups
      where id = new.default_group_id
        and service_key = new.key
        and status = 'active'
    ) then
      raise exception 'invalid_default_group' using errcode = '23514';
    end if;
  end if;
  return new;
end $$;

create trigger services_enforce_default_group
before insert or update of default_group_id on public.services
for each row execute function public.enforce_default_group_service();

create or replace function public.enforce_group_policy_service()
returns trigger language plpgsql as $$
begin
  if new.usage_policy_id is not null then
    if not exists (
      select 1 from public.usage_policies
      where id = new.usage_policy_id
        and service_key = (select service_key from public.permission_groups where id = new.id)
    ) then
      raise exception 'cross_service_policy_binding' using errcode = '23514';
    end if;
  end if;
  return new;
end $$;

create trigger permission_groups_enforce_policy_service
before insert or update of usage_policy_id on public.permission_groups
for each row execute function public.enforce_group_policy_service();

create or replace function public.prevent_disable_default_group()
returns trigger language plpgsql as $$
begin
  if new.status = 'disabled' and old.status = 'active' then
    if exists (
      select 1 from public.services
      where default_group_id = new.id
    ) then
      raise exception 'cannot_disable_default_group'
        using errcode = '23514',
        hint = 'Clear or change the service default_group_id before disabling this group.';
    end if;
  end if;
  return new;
end $$;

create trigger permission_groups_prevent_disable_default
before update of status on public.permission_groups
for each row execute function public.prevent_disable_default_group();

create or replace function public.enforce_policy_rule_service()
returns trigger language plpgsql as $$
declare
  policy_service text;
  perm_service text;
begin
  select service_key into policy_service from public.usage_policies where id = new.policy_id;
  select service_key into perm_service from public.permissions where key = new.permission_key;
  if policy_service is null or perm_service is null or policy_service <> perm_service then
    raise exception 'policy_rule_service_mismatch' using errcode = '23514';
  end if;
  return new;
end $$;

create trigger usage_policy_rules_enforce_service
before insert or update on public.usage_policy_rules
for each row execute function public.enforce_policy_rule_service();

-- =============================================================================
-- 7. set_updated_at triggers for new tables
-- =============================================================================

create trigger usage_policies_set_updated_at
before update on public.usage_policies
for each row execute function public.set_updated_at();

create trigger usage_policy_rules_set_updated_at
before update on public.usage_policy_rules
for each row execute function public.set_updated_at();

create trigger usage_adjustment_audit_set_updated_at
before update on public.usage_adjustment_audit
for each row execute function public.set_updated_at();

-- =============================================================================
-- 8. RLS on new tables
-- =============================================================================

alter table public.usage_policies enable row level security;
alter table public.usage_policy_rules enable row level security;
alter table public.usage_adjustment_audit enable row level security;

grant select, insert, update, delete on public.usage_policies to service_role;
grant select, insert, update, delete on public.usage_policy_rules to service_role;
grant select, insert, update, delete on public.usage_adjustment_audit to service_role;

-- =============================================================================
-- 9. RPC functions
-- =============================================================================

create or replace function public.ensure_default_service_group(
  p_user_id uuid,
  p_service_key text
) returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_existing_group_id uuid;
  v_default_group_id uuid;
  v_membership_id uuid;
begin
  -- Always attempt to revoke expired memberships
  update public.user_permission_groups
  set status = 'revoked', updated_at = now()
  where user_id = p_user_id
    and service_key = p_service_key
    and status = 'active'
    and expires_at is not null
    and expires_at <= now();

  select upg.group_id into v_existing_group_id
  from public.user_permission_groups upg
  where upg.user_id = p_user_id
    and upg.service_key = p_service_key
    and upg.status = 'active'
    and (upg.expires_at is null or upg.expires_at > now())
  for update;

  if v_existing_group_id is not null then
    return v_existing_group_id;
  end if;

  select default_group_id into v_default_group_id
  from public.services
  where key = p_service_key;

  if v_default_group_id is null then
    return null;
  end if;

  if not exists (
    select 1 from public.permission_groups
    where id = v_default_group_id and status = 'active'
  ) then
    return null;
  end if;

  insert into public.user_permission_groups (user_id, group_id, service_key, status, granted_by, expires_at)
  values (p_user_id, v_default_group_id, p_service_key, 'active', null, null)
  on conflict (user_id, group_id) do update
    set status = 'active', granted_by = null, expires_at = null, updated_at = now()
  returning id into v_membership_id;

  return v_default_group_id;
end;
$$;

revoke execute on function public.ensure_default_service_group(uuid, text) from public;
grant execute on function public.ensure_default_service_group(uuid, text) to service_role;

create or replace function public.is_usage_policy_rule_value_valid(
  p_control jsonb,
  p_value jsonb
) returns boolean
language plpgsql
immutable
as $$
declare
  v_kind text := p_control->>'kind';
  v_number numeric;
begin
  if p_value is null or p_value = 'null'::jsonb then
    return false;
  end if;

  if v_kind in ('quota', 'rate_limit', 'numeric_ceiling') then
    if jsonb_typeof(p_value) <> 'number' then return false; end if;
    v_number := (p_value #>> '{}')::numeric;
    if v_number <> trunc(v_number) then return false; end if;
    return v_number >= (p_control->>'minimum')::numeric
      and v_number <= (p_control->>'maximum')::numeric;
  end if;

  if v_kind = 'boolean' then
    return jsonb_typeof(p_value) = 'boolean';
  end if;

  if v_kind = 'enum_one' then
    return jsonb_typeof(p_value) = 'string'
      and exists (
        select 1 from jsonb_array_elements(coalesce(p_control->'options', '[]'::jsonb)) option
        where option->>'value' = p_value #>> '{}'
      );
  end if;

  if v_kind = 'enum_many' then
    return jsonb_typeof(p_value) = 'array'
      and not exists (
        select 1
        from jsonb_array_elements(p_value) selected
        where jsonb_typeof(selected) <> 'string'
           or not exists (
             select 1 from jsonb_array_elements(coalesce(p_control->'options', '[]'::jsonb)) option
             where option->>'value' = selected #>> '{}'
           )
      )
      and (select count(*) from jsonb_array_elements(p_value)) =
          (select count(distinct selected #>> '{}') from jsonb_array_elements(p_value) selected);
  end if;

  return false;
exception when others then
  return false;
end;
$$;

revoke execute on function public.is_usage_policy_rule_value_valid(jsonb, jsonb) from public;
grant execute on function public.is_usage_policy_rule_value_valid(jsonb, jsonb) to service_role;

create or replace function public.console_upsert_usage_policy(
  p_service_key text,
  p_policy_key text,
  p_name text,
  p_description text,
  p_status text,
  p_rules jsonb,
  p_actor uuid
) returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_policy_id uuid;
  v_rule jsonb;
  v_perm_service text;
  v_control jsonb;
begin
  if p_status not in ('active', 'disabled') then
    raise exception 'invalid_policy_status' using errcode = '22023';
  end if;
  if jsonb_typeof(coalesce(p_rules, '[]'::jsonb)) <> 'array' then
    raise exception 'invalid_usage_policy_rules' using errcode = '22023';
  end if;
  if (
    select count(*) <> count(distinct jsonb_build_array(rule->>'permission_key', rule->>'control_key'))
    from jsonb_array_elements(coalesce(p_rules, '[]'::jsonb)) rule
  ) then
    raise exception 'duplicate_usage_policy_rule' using errcode = '23514';
  end if;

  insert into public.usage_policies (service_key, key, name, description, status, created_by)
  values (p_service_key, p_policy_key, p_name, p_description, p_status, p_actor)
  on conflict (service_key, key) do update
    set name = excluded.name,
        description = excluded.description,
        status = excluded.status,
        updated_at = now()
  returning id into v_policy_id;

  delete from public.usage_policy_rules where policy_id = v_policy_id;

  for v_rule in select * from jsonb_array_elements(coalesce(p_rules, '[]'::jsonb))
  loop
    select service_key into v_perm_service
    from public.permissions
    where key = v_rule->>'permission_key';

    if v_perm_service is null or v_perm_service <> p_service_key then
      raise exception 'policy_rule_service_mismatch' using errcode = '23514';
    end if;

    select elem into v_control
    from public.services s
    join public.service_capabilities cap
      on cap.service_key = s.key and cap.catalog_version = s.active_capability_version
    cross join lateral jsonb_array_elements(cap.usage_controls) elem
    where s.key = p_service_key
      and cap.key = v_rule->>'permission_key'
      and elem->>'key' = v_rule->>'control_key';

    if v_control is null then
      raise exception 'usage_policy_control_not_found' using errcode = '23514';
    end if;
    if not public.is_usage_policy_rule_value_valid(v_control, v_rule->'value') then
      raise exception 'invalid_usage_policy_rule_value' using errcode = '23514';
    end if;

    insert into public.usage_policy_rules (policy_id, permission_key, control_key, value)
    values (
      v_policy_id,
      v_rule->>'permission_key',
      v_rule->>'control_key',
      v_rule->'value'
    );
  end loop;

  if exists (
    with requested_permissions as (
      select distinct rule->>'permission_key' as permission_key
      from jsonb_array_elements(coalesce(p_rules, '[]'::jsonb)) rule
    ), expected_controls as (
      select cap.key as permission_key, elem->>'key' as control_key
      from requested_permissions requested
      join public.services s on s.key = p_service_key
      join public.service_capabilities cap
        on cap.service_key = s.key
       and cap.catalog_version = s.active_capability_version
       and cap.key = requested.permission_key
      cross join lateral jsonb_array_elements(cap.usage_controls) elem
    )
    select 1
    from expected_controls expected
    where not exists (
      select 1
      from jsonb_array_elements(coalesce(p_rules, '[]'::jsonb)) rule
      where rule->>'permission_key' = expected.permission_key
        and rule->>'control_key' = expected.control_key
    )
  ) then
    raise exception 'usage_policy_rules_incomplete' using errcode = '23514';
  end if;

  return v_policy_id;
end;
$$;

revoke execute on function public.console_upsert_usage_policy(text, text, text, text, text, jsonb, uuid) from public;
grant execute on function public.console_upsert_usage_policy(text, text, text, text, text, jsonb, uuid) to service_role;

create or replace function public.console_bind_group_usage_policy(
  p_service_key text,
  p_group_key text,
  p_policy_key text,
  p_actor uuid
) returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_policy_id uuid;
  v_group_id uuid;
  v_group_status text;
begin
  select id, status into v_group_id, v_group_status
  from public.permission_groups
  where service_key = p_service_key and key = p_group_key
  for update;

  if v_group_id is null then
    raise exception 'group_not_found' using errcode = '22023';
  end if;

  if p_policy_key is null then
    if v_group_status = 'active' and exists (
      select 1
      from public.permission_group_permissions pgp
      join public.services s on s.key = p_service_key
      join public.service_capabilities cap
        on cap.service_key = s.key
       and cap.catalog_version = s.active_capability_version
       and cap.key = pgp.permission_key
      cross join lateral jsonb_array_elements(cap.usage_controls) control
      where pgp.group_id = v_group_id
    ) then
      raise exception 'usage_policy_required_for_group' using errcode = '23514';
    end if;
    update public.permission_groups
    set usage_policy_id = null, updated_at = now()
    where id = v_group_id;
    return;
  end if;

  select id into v_policy_id
  from public.usage_policies
  where service_key = p_service_key and key = p_policy_key and status = 'active';

  if v_policy_id is null then
    raise exception 'policy_not_found' using errcode = '22023';
  end if;

  if v_group_status = 'active' and exists (
    select 1
    from public.permission_group_permissions pgp
    join public.services s on s.key = p_service_key
    join public.service_capabilities cap
      on cap.service_key = s.key
     and cap.catalog_version = s.active_capability_version
     and cap.key = pgp.permission_key
    cross join lateral jsonb_array_elements(cap.usage_controls) control
    where pgp.group_id = v_group_id
      and not exists (
        select 1 from public.usage_policy_rules rule
        where rule.policy_id = v_policy_id
          and rule.permission_key = pgp.permission_key
          and rule.control_key = control->>'key'
      )
  ) then
    raise exception 'usage_policy_incomplete_for_group' using errcode = '23514';
  end if;

  update public.permission_groups
  set usage_policy_id = v_policy_id, updated_at = now()
  where id = v_group_id;
end;
$$;

revoke execute on function public.console_bind_group_usage_policy(text, text, text, uuid) from public;
grant execute on function public.console_bind_group_usage_policy(text, text, text, uuid) to service_role;

create or replace function public.console_create_permission_group_with_policy(
  p_service_key text,
  p_group_key text,
  p_name text,
  p_description text,
  p_permission_keys text[],
  p_usage_policy_key text,
  p_actor uuid
) returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_group_id uuid;
begin
  v_group_id := public.console_create_permission_group(
    p_service_key,
    p_group_key,
    p_name,
    p_description,
    p_permission_keys,
    p_actor
  );
  perform public.console_bind_group_usage_policy(
    p_service_key,
    p_group_key,
    p_usage_policy_key,
    p_actor
  );
  return v_group_id;
end;
$$;

create or replace function public.console_update_permission_group_with_policy(
  p_service_key text,
  p_group_key text,
  p_name text,
  p_description text,
  p_status text,
  p_permission_keys text[],
  p_usage_policy_key text,
  p_actor uuid
) returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_group_id uuid;
begin
  v_group_id := public.console_update_permission_group(
    p_service_key,
    p_group_key,
    p_name,
    p_description,
    p_status,
    p_permission_keys,
    p_actor
  );
  perform public.console_bind_group_usage_policy(
    p_service_key,
    p_group_key,
    p_usage_policy_key,
    p_actor
  );
  return v_group_id;
end;
$$;

revoke execute on function public.console_create_permission_group_with_policy(text, text, text, text, text[], text, uuid) from public;
revoke execute on function public.console_update_permission_group_with_policy(text, text, text, text, text, text[], text, uuid) from public;
grant execute on function public.console_create_permission_group_with_policy(text, text, text, text, text[], text, uuid) to service_role;
grant execute on function public.console_update_permission_group_with_policy(text, text, text, text, text, text[], text, uuid) to service_role;
revoke execute on function public.console_create_permission_group(text, text, text, text, text[], uuid) from service_role;
revoke execute on function public.console_update_permission_group(text, text, text, text, text, text[], uuid) from service_role;

create or replace function public.console_set_service_default_group(
  p_service_key text,
  p_group_key text,
  p_actor uuid
) returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_group_id uuid;
begin
  if p_group_key is null then
    update public.services set default_group_id = null where key = p_service_key;
    return;
  end if;

  select id into v_group_id
  from public.permission_groups
  where service_key = p_service_key and key = p_group_key and status = 'active';

  if v_group_id is null then
    raise exception 'group_not_found' using errcode = '22023';
  end if;

  update public.services
  set default_group_id = v_group_id
  where key = p_service_key;
end;
$$;

revoke execute on function public.console_set_service_default_group(text, text, uuid) from public;
grant execute on function public.console_set_service_default_group(text, text, uuid) to service_role;

create or replace function public.load_usage_target_context(
  p_service_key text,
  p_permission_key text
) returns jsonb
language sql
stable
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'service_key', s.key,
    'service_status', s.status,
    'resource_uri', s.resource_uri,
    'permission_key', sc.key,
    'permission_oauth_scope', sc.oauth_scope,
    'permission_control_count', case
      when sc.key is null then null
      else jsonb_array_length(sc.usage_controls)
    end
  )
  from public.services s
  left join public.service_capabilities sc
    on sc.service_key = s.key
   and sc.catalog_version = s.active_capability_version
   and sc.key = p_permission_key
  where s.key = p_service_key
$$;

revoke execute on function public.load_usage_target_context(text, text) from public;
grant execute on function public.load_usage_target_context(text, text) to service_role;

create or replace function public.load_usage_decision_context(
  p_user_id uuid,
  p_service_key text,
  p_permission_key text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_service_status text;
  v_profile_status text;
  v_group_id uuid;
  v_group_key text;
  v_group_status text;
  v_membership_expires_at timestamptz;
  v_permission_granted boolean := false;
  v_policy_id uuid;
  v_policy_key text;
  v_policy_status text;
  v_controls jsonb := '[]'::jsonb;
begin
  select status into v_service_status
  from public.services where key = p_service_key;

  select status into v_profile_status
  from public.profiles where id = p_user_id;

  select pg.id, pg.key, pg.status, upg.expires_at, pg.usage_policy_id
  into v_group_id, v_group_key, v_group_status, v_membership_expires_at, v_policy_id
  from public.user_permission_groups upg
  join public.permission_groups pg on pg.id = upg.group_id
  where upg.user_id = p_user_id
    and upg.service_key = p_service_key
    and upg.status = 'active';

  if v_group_id is not null then
    select true into v_permission_granted
    from public.permission_group_permissions
    where group_id = v_group_id and permission_key = p_permission_key;
  end if;

  if v_policy_id is not null then
    select key, status into v_policy_key, v_policy_status
    from public.usage_policies where id = v_policy_id;

    select coalesce(jsonb_agg(
      jsonb_build_object(
        'key', ctrl.key,
        'kind', ctrl.kind,
        'unit', ctrl.unit,
        'window', ctrl.window,
        'window_seconds', ctrl.window_seconds,
        'value', upr.value,
        'has_rule', upr.policy_id is not null
      )
    ), '[]'::jsonb)
    into v_controls
    from (
      select
        elem->>'key' as key,
        elem->>'kind' as kind,
        elem->>'unit' as unit,
        elem->>'window' as window,
        (elem->>'window_seconds')::int as window_seconds
      from public.service_capabilities cap,
           jsonb_array_elements(cap.usage_controls) as elem
      where cap.service_key = p_service_key
        and cap.key = p_permission_key
        and cap.catalog_version = (select active_capability_version from public.services where key = p_service_key)
    ) ctrl
    left join public.usage_policy_rules upr
      on upr.policy_id = v_policy_id
      and upr.permission_key = p_permission_key
      and upr.control_key = ctrl.key;
  end if;

  return jsonb_build_object(
    'service_status', v_service_status,
    'profile_status', v_profile_status,
    'group_id', v_group_id,
    'group_key', v_group_key,
    'group_status', v_group_status,
    'membership_expires_at', v_membership_expires_at,
    'permission_granted', coalesce(v_permission_granted, false),
    'policy_id', v_policy_id,
    'policy_key', v_policy_key,
    'policy_status', v_policy_status,
    'controls', v_controls
  );
end;
$$;

revoke execute on function public.load_usage_decision_context(uuid, text, text) from public;
grant execute on function public.load_usage_decision_context(uuid, text, text) to service_role;

-- =============================================================================
-- 10. Modify console_replace_user_permission_groups
-- =============================================================================

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

  if exists (
    select pg.service_key
    from jsonb_array_elements(p_grants) as elem
    join public.permission_groups pg on pg.id = (elem->>'group_id')::uuid
    group by pg.service_key
    having count(*) > 1
  ) then
    raise exception 'multiple_groups_for_service' using errcode = '23505';
  end if;

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

  update public.user_permission_groups current
  set status='revoked', granted_by=p_actor, updated_at=now()
  where current.user_id=p_user_id and current.status='active'
    and not exists (
      select 1 from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz)
      where x.group_id=current.group_id
    );

  insert into public.user_permission_groups(user_id, group_id, service_key, status, granted_by, expires_at)
  select p_user_id, x.group_id, pg.service_key, 'active', p_actor, x.expires_at
  from jsonb_to_recordset(p_grants) as x(group_id uuid, expires_at timestamptz)
  join public.permission_groups pg on pg.id = x.group_id
  on conflict (user_id, group_id) do update
    set status='active', granted_by=excluded.granted_by,
        expires_at=excluded.expires_at, service_key=excluded.service_key, updated_at=now();
end;
$$;

revoke execute on function public.console_replace_user_permission_groups(uuid, jsonb, uuid) from public;
grant execute on function public.console_replace_user_permission_groups(uuid, jsonb, uuid) to service_role;

-- =============================================================================
-- 11. Extend active_resource_capabilities view
-- =============================================================================

drop view if exists public.active_resource_capabilities;

create view public.active_resource_capabilities as
select
  s.resource_uri,
  sc.service_key,
  sc.key,
  sc.name,
  sc.description,
  sc.oauth_scope,
  sc.usage_controls,
  (jsonb_array_length(sc.usage_controls) > 0) as usage_policy_supported,
  sc.catalog_version
from public.service_capabilities sc
join public.services s on s.key = sc.service_key
where s.resource_uri is not null
  and s.status = 'active';

grant select on public.active_resource_capabilities to anon, authenticated, service_role;

-- =============================================================================
-- 12. Extend catalog import and approval
-- =============================================================================

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

  insert into public.service_capabilities(service_key, catalog_version, key, name, description, oauth_scope, usage_controls)
  select
    p_service_key,
    p_catalog_version,
    permission->>'key',
    permission->>'name',
    permission->>'description',
    (p_manifest->'scopes_supported') ? (permission->>'key'),
    coalesce(permission->'usage_controls', '[]'::jsonb)
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

revoke execute on function public.import_service_capability_version(text, text, text, jsonb, uuid) from public;
grant execute on function public.import_service_capability_version(text, text, text, jsonb, uuid) to service_role;

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

  insert into public.service_capabilities (service_key, catalog_version, key, name, description, oauth_scope, usage_controls)
  select
    p_service_key,
    p_catalog_version,
    perm->>'key',
    perm->>'name',
    perm->>'description',
    exists (select 1 from jsonb_array_elements_text(target.manifest->'scopes_supported') s where s.value = perm->>'key'),
    coalesce(perm->'usage_controls', '[]'::jsonb)
  from jsonb_array_elements(target.manifest->'dondone_capabilities'->'permissions') as perm
  on conflict (service_key, catalog_version, key) do update
    set name = excluded.name,
        description = excluded.description,
        oauth_scope = excluded.oauth_scope,
        usage_controls = excluded.usage_controls;

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

revoke execute on function public.approve_service_capability_version(text, text, uuid, text, jsonb) from public;
grant execute on function public.approve_service_capability_version(text, text, uuid, text, jsonb) to service_role;
