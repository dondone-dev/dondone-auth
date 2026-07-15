import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { importJWK, jwtVerify } from 'jose'
import { createAuthorizationCode } from '../lib/codes'
import { computeS256Challenge } from '../lib/pkce'
import type { AuthEnv, AuthorizationCodeRecord } from '../lib/types'
import { handleToken } from './token'
import { handleJwks } from './jwks'

const CODE_VERIFIER = 'verifier-abc-123'

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

async function env(kv: KVNamespace): Promise<AuthEnv> {
  return {
    AUTH_CODES: kv,
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

describe('POST /api/token', () => {
  beforeEach(() => stubRegistryFetch())

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('exchanges a code once for a Supabase session and Dondone API token', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const testEnv = await env(kv)
    const session = {
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      expires_at: 123,
      token_type: 'bearer',
    }
    const record: AuthorizationCodeRecord = {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER),
      userId: 'user-123',
      userEmail: 'user@example.com',
      resource: 'https://api.dondone.dev',
      scopes: ['api:echo'],
      session,
    }
    const code = await createAuthorizationCode(kv, record)

    const request = () =>
      new Request('https://auth.dondone.dev/api/token', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          code,
          code_verifier: CODE_VERIFIER,
        }),
      })

    const response = await handleToken(request(), testEnv)
    const secondResponse = await handleToken(request(), testEnv)
    const body = (await response.json()) as typeof session & {
      api_access_token: string
      api_token_type: string
      api_expires_in: number
    }
    const jwksResponse = await handleJwks(
      new Request('https://auth.dondone.dev/api/jwks'),
      testEnv
    )
    const jwks = (await jwksResponse.json()) as { keys: JsonWebKey[] }
    const key = await importJWK(jwks.keys[0], 'ES256')
    const verified = await jwtVerify(body.api_access_token, key, {
      issuer: testEnv.DONDONE_JWT_ISSUER,
      audience: 'https://api.dondone.dev',
    })

    expect(response.status).toBe(200)
    expect(body.access_token).toBe(session.access_token)
    expect(body.refresh_token).toBe(session.refresh_token)
    expect(body.expires_at).toBe(session.expires_at)
    expect(body.token_type).toBe(session.token_type)
    expect(body.api_token_type).toBe('Bearer')
    expect(body.api_expires_in).toBe(900)
    expect(verified.payload.sub).toBe('user-123')
    expect(verified.payload.email).toBe('user@example.com')
    expect(verified.payload.client_id).toBe('time')
    expect(verified.payload.scope).toBe('api:echo')
    expect(secondResponse.status).toBe(410)
  })

  it('rejects an authorization code without a resource in the final strict mode', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time', redirectUri: 'https://time.dondone.dev/auth/callback', state: 'state',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER), userId: 'user-123',
      session: { access_token: 'a', refresh_token: 'r', expires_at: 123, token_type: 'bearer' },
    })
    const response = await handleToken(new Request('https://auth.dondone.dev/api/token', {
      method: 'POST', body: JSON.stringify({ client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', code, code_verifier: CODE_VERIFIER }),
    }), await env(kv))

    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_target' })
  })

  it('rejects an authorization code without a non-empty bound scope', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time', redirectUri: 'https://time.dondone.dev/auth/callback', state: 'state',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER), userId: 'user-123',
      resource: 'https://api.dondone.dev',
      session: { access_token: 'a', refresh_token: 'r', expires_at: 123, token_type: 'bearer' },
    })
    const response = await handleToken(new Request('https://auth.dondone.dev/api/token', {
      method: 'POST', body: JSON.stringify({ client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', code, code_verifier: CODE_VERIFIER }),
    }), await env(kv))

    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_scope' })
  })

  it('rejects an explicitly empty token-exchange scope', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time', redirectUri: 'https://time.dondone.dev/auth/callback', state: 'state',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER), userId: 'user-123',
      resource: 'https://api.dondone.dev', scopes: ['api:echo'],
      session: { access_token: 'a', refresh_token: 'r', expires_at: 123, token_type: 'bearer' },
    })
    const response = await handleToken(new Request('https://auth.dondone.dev/api/token', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', code,
        code_verifier: CODE_VERIFIER, scope: '   ',
      }),
    }), await env(kv))

    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_scope' })
  })

  it('rejects switching the resource bound to an authorization code', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time', redirectUri: 'https://time.dondone.dev/auth/callback', state: 'state',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER), userId: 'user-123',
      resource: 'https://api.dondone.dev', scopes: ['api:echo'],
      session: { access_token: 'a', refresh_token: 'r', expires_at: 123, token_type: 'bearer' },
    })
    const response = await handleToken(new Request('https://auth.dondone.dev/api/token', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', code,
        code_verifier: CODE_VERIFIER, resource: 'https://ai.dondone.dev',
      }),
    }), await env(kv))
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_target' })
  })

  it('rejects token-exchange scopes that were not bound to the code', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time', redirectUri: 'https://time.dondone.dev/auth/callback', state: 'state',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER), userId: 'user-123',
      resource: 'https://api.dondone.dev', scopes: ['api:echo'],
      session: { access_token: 'a', refresh_token: 'r', expires_at: 123, token_type: 'bearer' },
    })
    const response = await handleToken(new Request('https://auth.dondone.dev/api/token', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', code,
        code_verifier: CODE_VERIFIER, resource: 'https://api.dondone.dev', scope: 'api:read',
      }),
    }), await env(kv))
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_scope' })
  })

  it('keeps code-bound scopes when token exchange omits scope instead of widening to the catalog', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const testEnv = await env(kv)
    stubRegistryFetch({ capabilities: [
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' },
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:read' },
    ] })
    const code = await createAuthorizationCode(kv, {
      clientId: 'time', redirectUri: 'https://time.dondone.dev/auth/callback', state: 'state',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER), userId: 'user-123',
      resource: 'https://api.dondone.dev', scopes: ['api:echo'],
      session: { access_token: 'a', refresh_token: 'r', expires_at: 123, token_type: 'bearer' },
    })
    const response = await handleToken(new Request('https://auth.dondone.dev/api/token', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', code,
        code_verifier: CODE_VERIFIER, resource: 'https://api.dondone.dev',
      }),
    }), testEnv)
    const body = await response.json() as { api_access_token: string }
    const jwks = await (await handleJwks(new Request('https://auth.dondone.dev/api/jwks'), testEnv)).json() as { keys: JsonWebKey[] }
    const verified = await jwtVerify(body.api_access_token, await importJWK(jwks.keys[0], 'ES256'))
    expect(verified.payload.scope).toBe('api:echo')
  })

  it('successfully reduces two code-bound scopes to one with exact resource aud and typ', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const testEnv = await env(kv)
    stubRegistryFetch({ capabilities: [
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' },
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:read' },
    ] })
    const code = await createAuthorizationCode(kv, {
      clientId: 'time', redirectUri: 'https://time.dondone.dev/auth/callback', state: 'state',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER), userId: 'user-123',
      resource: 'https://api.dondone.dev', scopes: ['api:echo', 'api:read'],
      session: { access_token: 'a', refresh_token: 'r', expires_at: 123, token_type: 'bearer' },
    })
    const response = await handleToken(new Request('https://auth.dondone.dev/api/token', {
      method: 'POST', body: JSON.stringify({
        client_id: 'time', redirect_uri: 'https://time.dondone.dev/auth/callback', code,
        code_verifier: CODE_VERIFIER, resource: 'https://api.dondone.dev', scope: 'api:read',
      }),
    }), testEnv)
    const body = await response.json() as { api_access_token: string }
    const jwks = await (await handleJwks(new Request('https://auth.dondone.dev/api/jwks'), testEnv)).json() as { keys: JsonWebKey[] }
    const verified = await jwtVerify(body.api_access_token, await importJWK(jwks.keys[0], 'ES256'), {
      issuer: testEnv.DONDONE_JWT_ISSUER, audience: 'https://api.dondone.dev',
    })
    expect(response.status).toBe(200)
    expect(verified.protectedHeader.typ).toBe('at+jwt')
    expect(verified.payload.aud).toBe('https://api.dondone.dev')
    expect(verified.payload.scope).toBe('api:read')
  })

  it('rejects a code redeemed with the wrong redirect URI', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER),
      userId: 'user-123',
      resource: 'https://api.dondone.dev',
      scopes: ['api:echo'],
      session: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 123,
        token_type: 'bearer',
      },
    })

    const response = await handleToken(
      new Request('https://auth.dondone.dev/api/token', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/wrong',
          code,
          code_verifier: CODE_VERIFIER,
        }),
      }),
      await env(kv)
    )

    expect(response.status).toBe(403)
  })

  it('rejects a code redeemed with the wrong client', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER),
      userId: 'user-123',
      resource: 'https://api.dondone.dev',
      scopes: ['api:echo'],
      session: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 123,
        token_type: 'bearer',
      },
    })

    const response = await handleToken(
      new Request('https://auth.dondone.dev/api/token', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'notes',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          code,
          code_verifier: CODE_VERIFIER,
        }),
      }),
      await env(kv)
    )

    expect(response.status).toBe(403)
  })

  it('rejects a code redeemed with the wrong PKCE verifier', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER),
      userId: 'user-123',
      session: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 123,
        token_type: 'bearer',
      },
    })

    const response = await handleToken(
      new Request('https://auth.dondone.dev/api/token', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          code,
          code_verifier: 'wrong-verifier',
        }),
      }),
      await env(kv)
    )

    expect(response.status).toBe(403)
  })

  it('exchanges a code using the database registry', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER),
      userId: 'user-123',
      resource: 'https://api.dondone.dev',
      scopes: ['api:echo'],
      session: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 123,
        token_type: 'bearer',
      },
    })

    const response = await handleToken(
      new Request('https://auth.dondone.dev/api/token', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          code,
          code_verifier: CODE_VERIFIER,
        }),
      }),
      await env(kv)
    )

    expect(response.status).toBe(200)
  })
})
