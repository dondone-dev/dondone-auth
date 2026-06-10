# SimpleAuth Pages Functions Authorization Code Exchange Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace URL-fragment token handoff with a unified SimpleAuth login entry and one-time authorization code exchange.

**Architecture:** Keep one GitHub repository and one Cloudflare Pages project. Serve the React app at `auth.dondone.dev/*`, and serve Cloudflare Pages Functions from `functions/api/*.ts` at `auth.dondone.dev/api/*`. Supabase remains the identity provider; the Pages Functions layer validates registered clients and exchanges short-lived one-time codes for Supabase sessions.

**Tech Stack:** React 19, TypeScript, Vite, Supabase Auth, Cloudflare Pages Functions, Cloudflare KV, Vitest, Wrangler.

---

## Summary

Current unstaged work used `redirect_to` plus URL fragment tokens. The new design removes that public token handoff. Business apps now redirect users to SimpleAuth with `client_id`, `redirect_uri`, and `state`; after Supabase login, SimpleAuth calls `/api/authorize`, receives a redirect containing only `code` and `state`, and the business app exchanges that code through `/api/token`.

The v1 target is SPA business apps. A later BFF/Worker variant can redeem the code server-side and set an app-local HttpOnly cookie.

## Public Interfaces

### Login Entry

```txt
https://auth.dondone.dev/?client_id=time&redirect_uri=https%3A%2F%2Ftime.dondone.dev%2Fauth%2Fcallback&state=<random>&code_challenge=<challenge>&code_challenge_method=S256
```

Required query params:

- `client_id`: registered app id from `AUTH_APPS_JSON`.
- `redirect_uri`: exact callback URL registered for the client.
- `state`: random value generated and verified by the business app.
- `code_challenge`: PKCE challenge, `base64url(sha256(code_verifier))`.
- `code_challenge_method`: optional, must be `S256` when present (default `S256`).

### `POST /api/authorize`

Called by the SimpleAuth frontend after a successful Supabase login.

Request:

```json
{
  "client_id": "time",
  "redirect_uri": "https://time.dondone.dev/auth/callback",
  "state": "random-state",
  "code_challenge": "base64url-sha256-of-verifier",
  "code_challenge_method": "S256",
  "access_token": "supabase-access-token",
  "refresh_token": "supabase-refresh-token",
  "expires_at": 1234567890,
  "token_type": "bearer"
}
```

Behavior:

- Validate `client_id` and exact `redirect_uri` against `AUTH_APPS_JSON`.
- Require a `code_challenge`; reject any `code_challenge_method` other than `S256`.
- Verify `access_token` with Supabase `/auth/v1/user`.
- Generate a high-entropy code with 120-second TTL.
- Store session payload and `code_challenge` in `AUTH_CODES` KV.
- Return a redirect URL containing only `code` and `state`.

Response:

```json
{
  "redirect_to": "https://time.dondone.dev/auth/callback?code=<code>&state=<random>"
}
```

### `POST /api/token`

Called by the business app callback.

Request:

```json
{
  "client_id": "time",
  "redirect_uri": "https://time.dondone.dev/auth/callback",
  "code": "<one-time-code>",
  "code_verifier": "<the-original-code-verifier>"
}
```

Behavior:

- Validate `client_id` and exact `redirect_uri`.
- Consume code from KV (deleted before any further check, so a failed exchange still burns the code).
- Reject expired, missing, previously used, client-mismatched, or redirect-mismatched codes.
- Verify `code_verifier` against the stored `code_challenge` (`S256`); reject on mismatch.
- Return the Supabase session payload.

Response:

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "expires_at": 1234567890,
  "token_type": "bearer"
}
```

### `GET /api/me`

Called with `Authorization: Bearer <access_token>`.

Behavior:

- Verify the token with Supabase.
- Return minimal user identity.

## Implementation Steps

### Task 1: Add Test Harness

**Files:**

- Modify: `package.json`
- Create: `functions/**/*.test.ts`

Steps:

1. Add Vitest and a `pnpm test` script.
2. Write failing tests for app registry exact redirect matching.
3. Write failing tests for one-time code creation, TTL, and single consumption.
4. Write failing tests for `/api/authorize` returning only `code` and `state`.
5. Write failing tests for `/api/token` one-time exchange and mismatch rejection.
6. Run `pnpm test` and confirm tests fail because implementation modules do not exist yet.

### Task 2: Implement Functions Core

**Files:**

- Create: `functions/lib/apps.ts`
- Create: `functions/lib/codes.ts`
- Create: `functions/lib/errors.ts`
- Create: `functions/lib/http.ts`
- Create: `functions/lib/supabase.ts`
- Create: `functions/lib/types.ts`

Steps:

1. Implement `AUTH_APPS_JSON` parsing and exact redirect matching.
2. Implement `AUTH_CODES` KV write/read/delete helpers with 120-second TTL.
3. Implement shared API errors and JSON response helpers with `Cache-Control: no-store`.
4. Implement CORS that allows origins derived from registered redirect URIs.
5. Implement Supabase user verification via `/auth/v1/user`.
6. Run `pnpm test` and confirm core tests pass.

### Task 3: Implement Pages Function Routes

**Files:**

- Create: `functions/api/authorize.ts`
- Create: `functions/api/token.ts`
- Create: `functions/api/me.ts`

Steps:

1. Add `POST /api/authorize` handler.
2. Add `POST /api/token` handler.
3. Add `GET /api/me` handler.
4. Add `OPTIONS` handling for API routes.
5. Return unified error bodies: `{ "error": "...", "message": "..." }`.
6. Run `pnpm test` and confirm route tests pass.

### Task 4: Update Frontend Flow

**Files:**

- Modify: `src/App.tsx`
- Rewrite: `src/lib/redirect.ts`

Steps:

1. Replace `redirect_to` parsing with `client_id`, `redirect_uri`, and `state`.
2. Keep normal SimpleAuth login behavior when no auth params are present.
3. Show target app origin when a valid auth request is present.
4. After login, call `/api/authorize` with the current Supabase session.
5. Redirect to the returned `redirect_to`.
6. Remove URL-fragment token handoff entirely.

### Task 5: Add Cloudflare Config And Docs

**Files:**

- Create: `wrangler.toml`
- Create: `tsconfig.functions.json`
- Modify: `tsconfig.json`
- Modify: `.env.example`
- Modify: `README.md`
- Modify: `.gitignore`

Steps:

1. Configure TypeScript project references for Functions code.
2. Add Wrangler Pages config with `pages_build_output_dir = "dist"`.
3. Document required Cloudflare KV binding: `AUTH_CODES`.
4. Document required Functions env vars: `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `AUTH_APPS_JSON`.
5. Add local Pages command: `pnpm pages:dev`.
6. Ignore local `.wrangler` cache.

## Test Plan

Run after implementation:

```bash
pnpm test
pnpm build
pnpm lint
pnpm exec wrangler pages dev dist --compatibility-date=2026-06-10 --port=8788
```

Expected results:

- Vitest covers registered app matching, invalid token rejection, one-time code TTL/consumption, token exchange success, second exchange failure, wrong client rejection, and wrong redirect rejection.
- Build runs `tsc -b && vite build` successfully for React and Functions TypeScript.
- ESLint reports no errors.
- Wrangler compiles the Pages Worker and serves the app locally.

Manual scenarios:

- Visit `auth.dondone.dev` and confirm normal login/logout still works.
- Visit the login entry URL with `client_id=time`, login, and confirm the browser returns to `time.dondone.dev/auth/callback?code=...&state=...`.
- Confirm the callback URL never contains `access_token` or `refresh_token`.
- Exchange `code` through `/api/token`, then call `supabase.auth.setSession()` in the business app.
- Try reusing the same code and confirm it fails.

## Deployment Notes

Cloudflare Pages:

- Build command: `pnpm build`
- Build output directory: `dist`
- Custom domain: `auth.dondone.dev`
- KV binding: `AUTH_CODES`

Environment variables:

```bash
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=your-publishable-key
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_PUBLISHABLE_KEY=your-publishable-key
AUTH_APPS_JSON={"time":{"name":"Time","redirectUris":["https://time.dondone.dev/auth/callback"]}}
```

For local Pages Functions, put Functions variables in `.dev.vars`; Vite variables stay in `.env.local`.

## Assumptions

- v1 uses Cloudflare Pages Functions, not a separately routed Worker.
- v1 uses Cloudflare KV for short-lived codes, not D1 or Durable Objects.
- v1 business apps are SPAs that exchange code from the browser and call `supabase.auth.setSession()`.
- PKCE (S256) is mandatory for all clients; there is no client secret.
- Single-use of a code is best-effort: KV `get`+`delete` is not atomic, so concurrent `/api/token` calls with the same code could both succeed within KV's consistency window. Strong single-use guarantees require D1 or Durable Objects.
- The stronger BFF mode, where business Workers redeem codes and set HttpOnly cookies, is a future enhancement.
- Existing fragment-token handoff is removed as a formal auth flow.
