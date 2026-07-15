# Dondone Auth

[中文文档](./README.zh.md)

A unified Supabase-based authentication service deployed at `auth.dondone.dev`. It supports email/password, OAuth (GitHub / Google), and Passkey sign-in. Downstream apps use an OAuth 2.0 PKCE-style authorization code flow, and Dondone Auth also signs short-lived Dondone API JWTs for `api.dondone.dev`.

## Tech Stack

React 19 + TypeScript · Vite · Tailwind CSS v4 + shadcn/ui · Supabase Auth · Cloudflare Pages + KV

## Authorization Flow

```
Client app → redirects to auth.dondone.dev with PKCE params
           → user signs in
           → /api/authorize issues a 120s one-time code
           → redirects back to the client callback
           → /api/token exchanges the code for Supabase session + Dondone API token
           → client app calls api.dondone.dev with the Dondone API token
```

## API

| Endpoint | Description |
|---|---|
| `POST /api/authorize` | Validates the Supabase session and returns a one-time authorization code redirect. A registered `resource` and non-empty approved `scope` are required and bound to the code. |
| `POST /api/token` | Validates PKCE and exchanges the resource-bound code for an `at+jwt`. If supplied, `resource` must match the code and `scope` may only reduce its non-empty bound scope set; omitting `scope` preserves that set. |
| `POST /api/api-token` | Exchanges a Supabase Bearer token for a short-lived `at+jwt`. Explicit non-empty `resource` and `scope` are required; it never defaults to every approved scope. |
| `GET /api/jwks` | Publishes the public key used to verify Dondone API JWTs. |
| `GET /api/me` | Validates a Bearer token and returns the Supabase user. |
| `POST /api/admin/services/:key/capability-sync` | Admin: fetch and store the capability manifest from the service's well-known endpoint. |
| `GET /api/admin/services/:key/capability-versions/:version/diff` | Admin: preview the diff between a pending version and the current active version. |
| `POST /api/admin/services/:key/capability-versions/:version/approve` | Admin: approve a pending capability version. For breaking changes, pass `{ allow_breaking_change: true, change_reason: "..." }`. |
| `POST /api/admin/services/:key/capability-versions/:version/reject` | Admin: reject a pending capability version with `{ reason: "..." }`. |

Admin endpoints require a Supabase access token with the `console:admin` permission in the `Authorization` header.

## Environment

**Frontend (Vite)**

```sh
VITE_SUPABASE_URL
VITE_SUPABASE_PUBLISHABLE_KEY
VITE_API_BASE
```

**Pages Functions**

```sh
SUPABASE_URL
SUPABASE_PUBLISHABLE_KEY
SUPABASE_SERVICE_ROLE_KEY          # secret — required for admin API and scope validation
DONDONE_JWT_PRIVATE_JWK
DONDONE_JWT_KID
DONDONE_JWT_ISSUER
ADMIN_ALLOWED_ORIGINS              # comma-separated admin API CORS allow-list
```

`SUPABASE_SERVICE_ROLE_KEY` powers the capability registry admin endpoints and transactional RPCs. Token issuance reads only the restricted `active_resource_capabilities` view with the publishable key. Set the service-role key as a Cloudflare Pages secret:

```sh
pnpm wrangler pages secret put SUPABASE_SERVICE_ROLE_KEY --project-name dondone-auth
```

`/api/authorize`, `/api/token`, and `/api/api-token` always require an approved resource and non-empty scope. Issued access tokens are audience-bound `at+jwt` tokens (RFC 9068); legacy unscoped authorization codes and fixed-audience JWTs are rejected.

`ADMIN_ALLOWED_ORIGINS` must list every browser origin allowed to call `/api/admin/*`, for example `https://console.dondone.dev`. Unlisted origins never receive CORS permission.

Registered OAuth clients and redirect URIs are always read from the Supabase `public.oauth_client_registry` view managed by the Dondone Console. Registry failures fail closed; there is no static registry fallback.

**KV Binding**: `AUTH_CODES`

**SQL**: before deploying authorization checks, manually run these migrations in the Supabase SQL editor in order:

1. `docs/sql/authorization.sql` — base RBAC schema
2. `docs/sql/migrations/20260713_add_service_redirect_uris.sql` — redirect URI registry view
3. `docs/sql/migrations/20260714_add_service_capability_registry.sql` — registry tables, restricted resource projection, and transactional RPCs
4. Publish, sync, review, and approve the API capability manifest.
5. `docs/sql/migrations/20260714_migrate_seed_permissions_to_capabilities.sql` — rename `tier:vip` to `api:tier:vip` while preserving grants and map seeds to approved catalogs

Generate an ES256 private JWK and write it to a Cloudflare Pages secret:

```bash
node -e "crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']).then(k=>crypto.subtle.exportKey('jwk',k.privateKey)).then(jwk=>console.log(JSON.stringify(jwk)))" | pnpm wrangler pages secret put DONDONE_JWT_PRIVATE_JWK --project-name dondone-auth
```

If you already have a private JWK value (e.g. restoring an existing key), pipe it directly instead:

```bash
echo '{"kty":"EC","crv":"P-256","x":"...","y":"...","d":"..."}' | pnpm wrangler pages secret put DONDONE_JWT_PRIVATE_JWK --project-name dondone-auth
```

The `d` field is the private key itself — only ever pipe it into `wrangler pages secret put`. Never commit it or print it in CI logs.

For local development, put Functions variables in `.dev.vars` and frontend variables in `.env.local`.

## Development

```bash
pnpm install
pnpm dev          # frontend only
pnpm pages:dev    # frontend + Functions
pnpm test
pnpm test:postgres # independent Docker/PostgreSQL 15 migration + RPC integration test
pnpm build
```

## Deployment

Connect the repository to Cloudflare Pages, set build command to `pnpm build`, output directory to `dist`, configure the custom domain `auth.dondone.dev`, and set the Functions variables plus KV binding in the Cloudflare dashboard.
