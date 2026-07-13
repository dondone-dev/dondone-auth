-- One-time migration. Do NOT fold this into docs/sql/authorization.sql —
-- that script re-asserts seed data via `on conflict ... do update` on every
-- run, which would silently overwrite any service name/description an
-- admin has since edited through the Console.
--
-- Run this file exactly once against Supabase, after authorization.sql has
-- already been applied. On a brand-new environment, run authorization.sql
-- first, then every file under docs/sql/migrations/ in filename order.

alter table public.services
  add column if not exists redirect_uris text[] not null default '{}';

-- Backfill the two OAuth clients currently registered via AUTH_APPS_JSON.
-- The `and redirect_uris = '{}'` guard makes this safe to re-run without
-- clobbering a URL someone has already edited through the Console UI.
update public.services
  set redirect_uris = array['https://console.dondone.dev/auth/callback']
  where key = 'console' and redirect_uris = '{}';

update public.services
  set redirect_uris = array['https://time.dondone.dev/auth/callback']
  where key = 'time' and redirect_uris = '{}';

-- Narrow, anon-readable view for dondone-auth's OAuth registry lookup.
-- Exposes only the three columns needed to validate a client_id/redirect_uri
-- pair, only for active services, only when at least one redirect URI is
-- registered (excludes non-OAuth-client services like "api"/"ai"). This
-- view is defined by the migration-running role, so it is not itself
-- subject to the `services` table's row-level security policies (the
-- standard Supabase pattern for exposing a restricted public slice of an
-- RLS-protected table) — the `where` clause below is what limits exposure,
-- not RLS.
create or replace view public.oauth_client_registry as
  select key, name, redirect_uris
  from public.services
  where status = 'active' and array_length(redirect_uris, 1) > 0;

grant select on public.oauth_client_registry to anon, authenticated;
