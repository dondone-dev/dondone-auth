import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
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
    SUPABASE_URL: 'https://project.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'publishable-key',
    DONDONE_JWT_PRIVATE_JWK: await testPrivateJwk(),
    DONDONE_JWT_KID: 'test-key',
    DONDONE_JWT_ISSUER: 'https://auth.dondone.dev',
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

const clientRows = [
  { key: 'time', name: 'Local Time', redirect_uris: ['https://time.dondone.dev/auth/callback'] },
]
const capabilityRows = [
  { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' },
]

function stubRegistryFetch(options: {
  clients?: unknown[]
  capabilities?: unknown[]
} = {}) {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
    const url = String(input)
    const rows = url.includes('oauth_client_registry')
      ? (options.clients ?? clientRows)
      : (options.capabilities ?? capabilityRows)
    return new Response(JSON.stringify(rows), { status: 200 })
  }))
  vi.stubGlobal('caches', { default: new FakeCache() })
}

describe('POST /api/authorize', () => {
  beforeEach(() => stubRegistryFetch())

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('rejects a catalog-valid scope the user is not granted before writing a code', async () => {
    const testEnv = await env()
    const kv = testEnv.AUTH_CODES as unknown as MemoryKV
    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
          code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
          token_type: 'bearer', resource: 'https://api.dondone.dev', scope: 'api:echo',
        }),
      }),
      testEnv,
      async () => ({ id: 'user-123' }),
      async () => []
    )

    expect(response.status).toBe(403)
    expect(await response.json()).toEqual({
      error: 'permission_denied',
      message: 'Requested scope is not granted to this user.',
    })
    expect(kv.values.size).toBe(0)
  })

  it('reports catalog-invalid scope before checking user permissions', async () => {
    const loadPermissions = vi.fn(async () => [])
    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
          code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
          token_type: 'bearer', resource: 'https://api.dondone.dev', scope: 'api:not-in-catalog',
        }),
      }),
      await env(),
      async () => ({ id: 'user-123' }),
      loadPermissions
    )

    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_scope' })
    expect(loadPermissions).not.toHaveBeenCalled()
  })

  it('requires resource and scope without a rollout flag', async () => {
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
      async () => ({ id: 'user-123' })
    )

    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_target' })
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
          resource: 'https://api.dondone.dev',
          scope: 'api:echo',
        }),
      }),
      await env(),
      verify,
      async () => ['api:echo']
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
    stubRegistryFetch({ capabilities: [
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' },
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:read' },
    ] })
    const testEnv = await env()
    const kv = testEnv.AUTH_CODES as unknown as MemoryKV
    const response = await handleAuthorize(new Request('https://auth.dondone.dev/api/authorize', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
        code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
        token_type: 'bearer', resource: 'https://api.dondone.dev', scope: 'api:read  api:echo api:read',
      }),
    }), testEnv, async () => ({ id: 'user-123' }), async () => ['api:echo', 'api:read'])
    const code = new URL(((await response.json()) as { redirect_to: string }).redirect_to).searchParams.get('code')!
    const stored = JSON.parse(kv.values.get(code)!)

    expect(stored.resource).toBe('https://api.dondone.dev')
    expect(stored.scopes).toEqual(['api:echo', 'api:read'])
  })

  it('requires resource and non-empty scope in resource-token mode without writing a code', async () => {
    const testEnv = await env()
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
    const testEnv = await env()
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
      stubRegistryFetch({ capabilities: [...rows] })
      const testEnv = await env()
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
    stubRegistryFetch({ capabilities: [
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' },
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:read' },
    ] })
    const testEnv = await env()
    const kv = testEnv.AUTH_CODES as unknown as MemoryKV
    const response = await handleAuthorize(new Request('https://auth.dondone.dev/api/authorize', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', state: 'state',
        code_challenge: 'challenge', access_token: 'access', refresh_token: 'refresh', expires_at: 123,
        token_type: 'bearer', resource: 'https://api.dondone.dev', scope: ['api:read', 'api:echo', 'api:read'],
      }),
    }), testEnv, async () => ({ id: 'user' }), async () => ['api:echo', 'api:read'])
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
          resource: 'https://api.dondone.dev',
          scope: 'api:echo',
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
          resource: 'https://api.dondone.dev',
          scope: 'api:echo',
        }),
      }),
      await env(),
      async () => {
        throw new ApiError(401, 'invalid_token', 'Supabase access token is invalid.')
      }
    )

    expect(response.status).toBe(401)
  })

  it('validates client_id/redirect_uri against the database registry', async () => {
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
          resource: 'https://api.dondone.dev',
          scope: 'api:echo',
        }),
      }),
      await env(),
      async () => ({ id: 'user-123', email: 'user@example.com' }),
      async () => ['api:echo']
    )

    expect(response.status).toBe(200)
  })

  it('rejects a client not present in the db-mode registry', async () => {
    stubRegistryFetch({ clients: [] })

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
          resource: 'https://api.dondone.dev',
          scope: 'api:echo',
        }),
      }),
      await env(),
      async () => ({ id: 'user-123' })
    )

    expect(response.status).toBe(403)
  })
})
