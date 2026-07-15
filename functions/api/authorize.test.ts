import { afterEach, describe, expect, it, vi } from 'vitest'
import { handleAuthorize } from './authorize'
import { ApiError } from '../lib/errors'
import type { AuthEnv, SupabaseUser } from '../lib/types'

class MemoryKV {
  readonly values = new Map<string, string>()

  async get(key: string) {
    return this.values.get(key) ?? null
  }

  async put(key: string, value: string) {
    this.values.set(key, value)
  }

  async delete(key: string) {
    this.values.delete(key)
  }
}

async function testPrivateJwk(): Promise<string> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )
  return JSON.stringify(await crypto.subtle.exportKey('jwk', keyPair.privateKey))
}

async function env(): Promise<AuthEnv> {
  return {
    AUTH_CODES: new MemoryKV() as unknown as KVNamespace,
    AUTH_APPS_JSON: JSON.stringify({
      time: {
        name: 'Time',
        redirectUris: ['https://time.dondone.dev/auth/callback'],
      },
    }),
    SUPABASE_URL: 'https://project.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'publishable-key',
    DONDONE_JWT_PRIVATE_JWK: await testPrivateJwk(),
    DONDONE_JWT_KID: 'test-key',
    DONDONE_JWT_ISSUER: 'https://auth.dondone.dev',
    DONDONE_API_AUDIENCE: 'https://api.dondone.dev',
  }
}

class FakeCache {
  private store = new Map<string, Response>()
  async match(request: Request) {
    const stored = this.store.get(request.url)
    return stored ? stored.clone() : undefined
  }
  async put(request: Request, response: Response) {
    this.store.set(request.url, response.clone())
  }
}

describe('POST /api/authorize', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns a redirect URL with only code and state for a valid session', async () => {
    const verify = async (): Promise<SupabaseUser> => ({
      id: 'user-123',
      email: 'user@example.com',
    })
    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          state: 'state-123',
          code_challenge: 'challenge-123',
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_at: 123,
          token_type: 'bearer',
        }),
      }),
      await env(),
      verify
    )

    const body = (await response.json()) as { redirect_to: string }
    const redirectTo = new URL(body.redirect_to)

    expect(response.status).toBe(200)
    expect(redirectTo.origin).toBe('https://time.dondone.dev')
    expect(redirectTo.searchParams.get('code')).toHaveLength(43)
    expect(redirectTo.searchParams.get('state')).toBe('state-123')
    expect(body.redirect_to).not.toContain('access-token')
    expect(body.redirect_to).not.toContain('refresh-token')
  })

  it('binds normalized resource and scope to the authorization code', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' },
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:read' },
    ]))))
    const testEnv = await env()
    const kv = testEnv.AUTH_CODES as unknown as MemoryKV
    const response = await handleAuthorize(new Request('https://auth.dondone.dev/api/authorize', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
        code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
        token_type: 'bearer', resource: 'https://api.dondone.dev', scope: 'api:read  api:echo api:read',
      }),
    }), testEnv, async () => ({ id: 'user-123' }))
    const code = new URL(((await response.json()) as { redirect_to: string }).redirect_to).searchParams.get('code')!
    const stored = JSON.parse(kv.values.get(code)!)

    expect(stored.resource).toBe('https://api.dondone.dev')
    expect(stored.scopes).toEqual(['api:echo', 'api:read'])
  })

  it('requires resource and non-empty scope in resource-token mode without writing a code', async () => {
    const testEnv = { ...(await env()), RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const kv = testEnv.AUTH_CODES as unknown as MemoryKV
    const response = await handleAuthorize(new Request('https://auth.dondone.dev/api/authorize', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
        code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
        token_type: 'bearer', scope: 'api:echo',
      }),
    }), testEnv, async () => ({ id: 'user' }))
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_target' })
    expect(kv.values.size).toBe(0)
  })

  it('rejects malformed scope arrays without writing a code', async () => {
    const testEnv = { ...(await env()), RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const kv = testEnv.AUTH_CODES as unknown as MemoryKV
    const response = await handleAuthorize(new Request('https://auth.dondone.dev/api/authorize', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
        code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
        token_type: 'bearer', resource: 'https://api.dondone.dev', scope: ['api:echo', 42],
      }),
    }), testEnv, async () => ({ id: 'user' }))
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_scope' })
    expect(kv.values.size).toBe(0)
  })

  it('rejects unknown resources and unapproved scopes without writing a code', async () => {
    for (const [rows, resource, scope, error] of [
      [[], 'https://unknown.dondone.dev', 'unknown:read', 'invalid_target'],
      [[{ service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' }], 'https://api.dondone.dev', 'api:read', 'invalid_scope'],
    ] as const) {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(rows))))
      const testEnv = { ...(await env()), RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
      const kv = testEnv.AUTH_CODES as unknown as MemoryKV
      const response = await handleAuthorize(new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST', body: JSON.stringify({
          client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
          code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
          token_type: 'bearer', resource, scope,
        }),
      }), testEnv, async () => ({ id: 'user' }))
      expect(response.status).toBe(400)
      expect(await response.json()).toMatchObject({ error })
      expect(kv.values.size).toBe(0)
    }
  })

  it('validates explicit resource/scope types even when resource-token mode is disabled', async () => {
    const testEnv = await env()
    const kv = testEnv.AUTH_CODES as unknown as MemoryKV
    const response = await handleAuthorize(new Request('https://auth.dondone.dev/api/authorize', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
        code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
        token_type: 'bearer', resource: 42, scope: 'api:echo',
      }),
    }), testEnv, async () => ({ id: 'user' }))
    expect(response.status).toBe(400)
    expect(kv.values.size).toBe(0)
  })

  it('accepts and normalizes a valid string-array scope after catalog validation', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' },
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:read' },
    ]))))
    const testEnv = { ...(await env()), RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    const kv = testEnv.AUTH_CODES as unknown as MemoryKV
    const response = await handleAuthorize(new Request('https://auth.dondone.dev/api/authorize', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
        code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
        token_type: 'bearer', resource: 'https://api.dondone.dev', scope: ['api:read', 'api:echo', 'api:read'],
      }),
    }), testEnv, async () => ({ id: 'user' }))
    const code = new URL(((await response.json()) as { redirect_to: string }).redirect_to).searchParams.get('code')!
    expect(JSON.parse(kv.values.get(code)!).scopes).toEqual(['api:echo', 'api:read'])
  })

  it('rejects unknown clients before creating a code', async () => {
    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'unknown',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          state: 'state-123',
          code_challenge: 'challenge-123',
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_at: 123,
          token_type: 'bearer',
        }),
      }),
      await env(),
      async () => ({ id: 'user-123' })
    )

    expect(response.status).toBe(403)
  })

  it('rejects an invalid Supabase access token', async () => {
    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          state: 'state-123',
          code_challenge: 'challenge-123',
          access_token: 'bad-token',
          refresh_token: 'refresh-token',
          expires_at: 123,
          token_type: 'bearer',
        }),
      }),
      await env(),
      async () => {
        throw new ApiError(401, 'invalid_token', 'Supabase access token is invalid.')
      }
    )

    expect(response.status).toBe(401)
  })

  it('validates client_id/redirect_uri against the db-mode registry when SERVICE_REGISTRY_SOURCE is "db"', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify([
            { key: 'time', name: 'Local Time', redirect_uris: ['https://time.dondone.dev/auth/callback'] },
          ]),
          { status: 200 }
        )
      )
    )
    vi.stubGlobal('caches', { default: new FakeCache() })

    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          state: 'state-123',
          code_challenge: 'challenge-123',
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_at: 123,
          token_type: 'bearer',
        }),
      }),
      { ...(await env()), SERVICE_REGISTRY_SOURCE: 'db' },
      async () => ({ id: 'user-123', email: 'user@example.com' })
    )

    expect(response.status).toBe(200)
  })

  it('rejects a client not present in the db-mode registry', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([]), { status: 200 })))
    vi.stubGlobal('caches', { default: new FakeCache() })

    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          state: 'state-123',
          code_challenge: 'challenge-123',
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_at: 123,
          token_type: 'bearer',
        }),
      }),
      { ...(await env()), SERVICE_REGISTRY_SOURCE: 'db' },
      async () => ({ id: 'user-123' })
    )

    expect(response.status).toBe(403)
  })
})
