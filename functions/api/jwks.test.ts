import { describe, expect, it } from 'vitest'
import type { AuthEnv } from '../lib/types'
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
    AUTH_APPS_JSON: '{}',
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

describe('GET /api/jwks', () => {
  it('publishes the public ES256 key without private key material', async () => {
    const response = await handleJwks(
      new Request('https://auth.dondone.dev/api/jwks'),
      await env()
    )
    const body = (await response.json()) as { keys: JsonWebKey[] }

    expect(response.status).toBe(200)
    expect(body.keys).toHaveLength(1)
    expect(body.keys[0]).toMatchObject({
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      use: 'sig',
      kid: 'test-key',
    })
    expect(body.keys[0].d).toBeUndefined()
  })
})
