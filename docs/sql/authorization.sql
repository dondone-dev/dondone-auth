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

create table if not exists public.permissions (
  key text primary key,
  description text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.user_permissions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  permission_key text not null references public.permissions(key) on delete cascade,
  status text not null default 'active'
    check (status in ('active', 'revoked')),
  granted_by uuid references public.profiles(id),
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  unique (user_id, permission_key)
);

create index if not exists user_permissions_user_id_idx
  on public.user_permissions(user_id);

create index if not exists user_permissions_lookup_idx
  on public.user_permissions(user_id, permission_key, status, expires_at);

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

  insert into public.user_permissions (user_id, permission_key)
  values (new.id, 'api:echo')
  on conflict (user_id, permission_key) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

insert into public.permissions (key, description)
values
  ('api:echo', 'Allows calling the Dondone API echo endpoint.'),
  ('tier:vip', 'Marks a user as VIP for feature gating.'),
  ('ai:chat', 'Allows calling AI chat APIs through Dondone API.')
on conflict (key) do update set description = excluded.description;

insert into public.user_permissions (user_id, permission_key)
select id, 'api:echo'
from public.profiles
on conflict (user_id, permission_key) do nothing;

alter table public.profiles enable row level security;
alter table public.permissions enable row level security;
alter table public.user_permissions enable row level security;

grant select on public.permissions to anon, authenticated;
grant select on public.profiles to authenticated;
grant select on public.user_permissions to authenticated;
grant select, insert, update, delete on public.profiles to service_role;
grant select, insert, update, delete on public.permissions to service_role;
grant select, insert, update, delete on public.user_permissions to service_role;

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

drop policy if exists "Users can read their own permissions" on public.user_permissions;
create policy "Users can read their own permissions"
on public.user_permissions for select
to authenticated
using ((select auth.uid()) = user_id);
