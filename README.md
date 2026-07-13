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
| `POST /api/authorize` | Validates the Supabase session and returns a one-time authorization code redirect. |
| `POST /api/token` | Validates the PKCE verifier and exchanges the code for a Supabase session plus Dondone API token. |
| `POST /api/api-token` | Exchanges a Supabase Bearer token for a short-lived Dondone API token. |
| `GET /api/jwks` | Publishes the public key used to verify Dondone API JWTs. |
| `GET /api/me` | Validates a Bearer token and returns the Supabase user. |

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
AUTH_APPS_JSON
SERVICE_REGISTRY_SOURCE
DONDONE_JWT_PRIVATE_JWK
DONDONE_JWT_KID
DONDONE_JWT_ISSUER
DONDONE_API_AUDIENCE
```

`AUTH_APPS_JSON` stores registered client apps, including `client_id` and allowed `redirect_uri` values. `SERVICE_REGISTRY_SOURCE` selects where the registry is read from: unset or `static` reads `AUTH_APPS_JSON`; `db` reads the Supabase `public.oauth_client_registry` view instead, which is managed from the Dondone Console's Services page. Any other value is a configuration error (`invalid_registry_source`). This is a human-controlled switch, not an automatic fallback — a database read failure while set to `db` fails the request rather than silently reverting to `static`.

**KV Binding**: `AUTH_CODES`

**SQL**: before deploying authorization checks, manually run `docs/sql/authorization.sql` in the Supabase SQL editor.

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
pnpm build
```

## Deployment

Connect the repository to Cloudflare Pages, set build command to `pnpm build`, output directory to `dist`, configure the custom domain `auth.dondone.dev`, and set the Functions variables plus KV binding in the Cloudflare dashboard.
