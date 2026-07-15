import { afterEach, describe, expect, it, vi } from 'vitest'
import { importJWK, jwtVerify } from 'jose'
import type { AuthEnv, SupabaseUser } from '../lib/types'
import { handleApiToken } from './api-token'
import { handleJwks } from './jwks'

class MemoryKV {
  async get() {
    return null
  }

  async put() {}

  async delete() {}
}

async function env(): Promise<AuthEnv> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )
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
    DONDONE_JWT_PRIVATE_JWK: JSON.stringify(
      await crypto.subtle.exportKey('jwk', keyPair.privateKey)
    ),
    DONDONE_JWT_KID: 'test-key',
    DONDONE_JWT_ISSUER: 'https://auth.dondone.dev',
    DONDONE_API_AUDIENCE: 'https://api.dondone.dev',
  }
}

describe('POST /api/api-token', () => {
  afterEach(() => vi.unstubAllGlobals())
  it('rejects requests without a Supabase bearer token', async () => {
    const response = await handleApiToken(
      new Request('https://auth.dondone.dev/api/api-token', { method: 'POST' }),
      await env(),
      async () => ({ id: 'user-123' })
    )

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({
      error: 'missing_token',
      message: 'Authorization bearer token is required.',
    })
  })

  it('signs a Dondone API JWT for a verified Supabase user', async () => {
    const testEnv = await env()
    const user: SupabaseUser = {
      id: 'user-123',
      email: 'user@example.com',
    }
    const response = await handleApiToken(
      new Request('https://auth.dondone.dev/api/api-token', {
        method: 'POST',
        headers: { Authorization: 'Bearer supabase-token' },
      }),
      testEnv,
      async () => user
    )
    const body = (await response.json()) as {
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
      audience: testEnv.DONDONE_API_AUDIENCE,
    })

    expect(response.status).toBe(200)
    expect(body.api_token_type).toBe('Bearer')
    expect(body.api_expires_in).toBe(900)
    expect(verified.payload.sub).toBe(user.id)
    expect(verified.payload.email).toBe(user.email)
    expect(verified.payload.client_id).toBe('auth')
    expect(verified.payload.scope).toBe('api:echo')
  })

  it('rejects malformed JSON when resource tokens are enabled', async () => {
    const response = await handleApiToken(new Request('https://auth.dondone.dev/api/api-token', {
      method: 'POST', headers: { Authorization: 'Bearer token' }, body: '{',
    }), { ...(await env()), RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }, async () => ({ id: 'user' }))
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_json' })
  })

  it('rejects non-string members in a scope array instead of silently dropping them', async () => {
    const response = await handleApiToken(new Request('https://auth.dondone.dev/api/api-token', {
      method: 'POST', headers: { Authorization: 'Bearer token' },
      body: JSON.stringify({ resource: 'https://api.dondone.dev', scope: ['api:echo', 42] }),
    }), { ...(await env()), RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }, async () => ({ id: 'user' }))
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_scope' })
  })

  it('requires an explicit non-empty scope for session-based resource token minting', async () => {
    const response = await handleApiToken(new Request('https://auth.dondone.dev/api/api-token', {
      method: 'POST', headers: { Authorization: 'Bearer token' },
      body: JSON.stringify({ resource: 'https://api.dondone.dev' }),
    }), { ...(await env()), RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }, async () => ({ id: 'user' }))
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_scope' })
  })

  it('mints a resource JWT with exact aud, typ and requested scope', async () => {
    const testEnv = { ...(await env()), RESOURCE_ACCESS_TOKENS_ENABLED: 'true' }
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' },
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:read' },
    ]))))
    const response = await handleApiToken(new Request('https://auth.dondone.dev/api/api-token', {
      method: 'POST', headers: { Authorization: 'Bearer token' },
      body: JSON.stringify({ resource: 'https://api.dondone.dev', scope: 'api:echo' }),
    }), testEnv, async () => ({ id: 'user', email: 'user@example.com' }))
    const body = await response.json() as { api_access_token: string }
    const jwks = await (await handleJwks(new Request('https://auth.dondone.dev/api/jwks'), testEnv)).json() as { keys: JsonWebKey[] }
    const verified = await jwtVerify(body.api_access_token, await importJWK(jwks.keys[0], 'ES256'), {
      issuer: testEnv.DONDONE_JWT_ISSUER, audience: 'https://api.dondone.dev',
    })
    expect(response.status).toBe(200)
    expect(verified.protectedHeader.typ).toBe('at+jwt')
    expect(verified.payload.aud).toBe('https://api.dondone.dev')
    expect(verified.payload.scope).toBe('api:echo')
  })
})
