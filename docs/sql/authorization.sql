-- Dondone authorization schema for Supabase.
-- Execute this manually before deploying API authorization features.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  avatar_url text,
  status text not null default 'active'
    check (status in ('active', 'disabled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.services (
  key text primary key,
  name text not null,
  description text,
  status text not null default 'active'
    check (status in ('active', 'disabled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.permissions (
  key text primary key,
  service_key text references public.services(key) on delete cascade,
  description text not null,
  created_at timestamptz not null default now()
);

alter table public.permissions
  add column if not exists service_key text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'permissions_service_key_fkey'
  ) then
    alter table public.permissions
      add constraint permissions_service_key_fkey
      foreign key (service_key) references public.services(key) on delete cascade;
  end if;
end;
$$;

create table if not exists public.permission_groups (
  id uuid primary key default gen_random_uuid(),
  service_key text not null references public.services(key) on delete cascade,
  key text not null,
  name text not null,
  description text,
  status text not null default 'active'
    check (status in ('active', 'disabled')),
  is_system boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (service_key, key)
);

create table if not exists public.permission_group_permissions (
  group_id uuid not null references public.permission_groups(id) on delete cascade,
  permission_key text not null references public.permissions(key) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (group_id, permission_key)
);

create table if not exists public.user_permission_groups (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  group_id uuid not null references public.permission_groups(id) on delete cascade,
  status text not null default 'active'
    check (status in ('active', 'revoked')),
  granted_by uuid references public.profiles(id),
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, group_id)
);

create index if not exists permission_groups_service_key_idx
  on public.permission_groups(service_key);

create index if not exists user_permission_groups_user_id_idx
  on public.user_permission_groups(user_id);

create index if not exists user_permission_groups_lookup_idx
  on public.user_permission_groups(user_id, group_id, status, expires_at);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
before update on public.profiles
for each row execute function public.set_updated_at();

drop trigger if exists services_set_updated_at on public.services;
create trigger services_set_updated_at
before update on public.services
for each row execute function public.set_updated_at();

drop trigger if exists permission_groups_set_updated_at on public.permission_groups;
create trigger permission_groups_set_updated_at
before update on public.permission_groups
for each row execute function public.set_updated_at();

drop trigger if exists user_permission_groups_set_updated_at on public.user_permission_groups;
create trigger user_permission_groups_set_updated_at
before update on public.user_permission_groups
for each row execute function public.set_updated_at();

insert into public.services (key, name, description)
values
  ('console', 'Console', 'Dondone permission management console.'),
  ('api', 'Dondone API', 'Shared Dondone API service.'),
  ('time', 'Local Time', 'Example app using Dondone Auth.'),
  ('ai', 'AI Proxy', 'AI proxy and model access.')
on conflict (key) do update set
  name = excluded.name,
  description = excluded.description;

insert into public.permissions (key, service_key, description)
values
  ('console:admin', 'console', 'Allows managing Dondone services, users, and permissions.'),
  ('api:echo', 'api', 'Allows calling the Dondone API echo endpoint.'),
  ('tier:vip', 'api', 'Marks a user as VIP for API feature gating.'),
  ('ai:chat', 'ai', 'Allows calling AI chat APIs through Dondone API.')
on conflict (key) do update set
  service_key = excluded.service_key,
  description = excluded.description;

insert into public.permission_groups (service_key, key, name, description, is_system)
values
  ('console', 'admin', 'Console Admin', 'Full access to the Dondone Console.', true),
  ('api', 'basic', 'API Basic', 'Basic Dondone API access.', true),
  ('api', 'vip', 'API VIP', 'VIP API tier access.', true),
  ('ai', 'basic', 'AI Basic', 'Basic AI chat access.', true)
on conflict (service_key, key) do update set
  name = excluded.name,
  description = excluded.description,
  is_system = excluded.is_system;

insert into public.permission_group_permissions (group_id, permission_key)
select pg.id, p.key
from public.permission_groups pg
join public.permissions p on p.key in ('console:admin')
where pg.service_key = 'console' and pg.key = 'admin'
on conflict (group_id, permission_key) do nothing;

insert into public.permission_group_permissions (group_id, permission_key)
select pg.id, p.key
from public.permission_groups pg
join public.permissions p on p.key in ('api:echo')
where pg.service_key = 'api' and pg.key = 'basic'
on conflict (group_id, permission_key) do nothing;

insert into public.permission_group_permissions (group_id, permission_key)
select pg.id, p.key
from public.permission_groups pg
join public.permissions p on p.key in ('api:echo', 'tier:vip')
where pg.service_key = 'api' and pg.key = 'vip'
on conflict (group_id, permission_key) do nothing;

insert into public.permission_group_permissions (group_id, permission_key)
select pg.id, p.key
from public.permission_groups pg
join public.permissions p on p.key in ('ai:chat')
where pg.service_key = 'ai' and pg.key = 'basic'
on conflict (group_id, permission_key) do nothing;

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

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.services enable row level security;
alter table public.permissions enable row level security;
alter table public.permission_groups enable row level security;
alter table public.permission_group_permissions enable row level security;
alter table public.user_permission_groups enable row level security;

grant select on public.services to anon, authenticated;
grant select on public.permissions to anon, authenticated;
grant select on public.permission_groups to anon, authenticated;
grant select on public.permission_group_permissions to anon, authenticated;
grant select on public.profiles to authenticated;
grant select on public.user_permission_groups to authenticated;
grant select, insert, update, delete on public.profiles to service_role;
grant select, insert, update, delete on public.services to service_role;
grant select, insert, update, delete on public.permissions to service_role;
grant select, insert, update, delete on public.permission_groups to service_role;
grant select, insert, update, delete on public.permission_group_permissions to service_role;
grant select, insert, update, delete on public.user_permission_groups to service_role;

drop policy if exists "Users can read their own profile" on public.profiles;
create policy "Users can read their own profile"
on public.profiles for select
to authenticated
using ((select auth.uid()) = id);

drop policy if exists "Permissions are readable by signed-in users" on public.permissions;
create policy "Permissions are readable by signed-in users"
on public.permissions for select
to authenticated
using (true);

drop policy if exists "Services are readable by signed-in users" on public.services;
create policy "Services are readable by signed-in users"
on public.services for select
to authenticated
using (true);

drop policy if exists "Permission groups are readable by signed-in users" on public.permission_groups;
create policy "Permission groups are readable by signed-in users"
on public.permission_groups for select
to authenticated
using (true);

drop policy if exists "Permission group permissions are readable by signed-in users" on public.permission_group_permissions;
create policy "Permission group permissions are readable by signed-in users"
on public.permission_group_permissions for select
to authenticated
using (true);

drop policy if exists "Users can read their own permission groups" on public.user_permission_groups;
create policy "Users can read their own permission groups"
on public.user_permission_groups for select
to authenticated
using ((select auth.uid()) = user_id);
