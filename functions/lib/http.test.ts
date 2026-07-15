import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { handleOptions, jsonResponse } from './http'
import type { AuthEnv } from './types'

function baseEnv(overrides: Partial<AuthEnv> = {}): AuthEnv {
  return {
    AUTH_CODES: {} as KVNamespace,
    SUPABASE_URL: 'https://project.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'publishable-key',
    DONDONE_JWT_PRIVATE_JWK: '{}',
    DONDONE_JWT_KID: 'test-key',
    DONDONE_JWT_ISSUER: 'https://auth.dondone.dev',
    ...overrides,
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

function requestFrom(origin: string) {
  return new Request('https://auth.dondone.dev/api/authorize', {
    headers: { Origin: origin },
  })
}

describe('CORS origin handling', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([
      { key: 'time', name: 'Local Time', redirect_uris: ['https://time.dondone.dev/auth/callback'] },
    ]), { status: 200 })))
    vi.stubGlobal('caches', { default: new FakeCache() })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('allows a registered origin', async () => {
    const response = await handleOptions(requestFrom('https://time.dondone.dev'), baseEnv())
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://time.dondone.dev')
  })

  it('rejects an unregistered origin', async () => {
    const response = await handleOptions(requestFrom('https://evil.dondone.dev'), baseEnv())
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull()
  })

  it('rejects an origin omitted by the database view', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([]), { status: 200 })))
    vi.stubGlobal('caches', { default: new FakeCache() })

    const response = await handleOptions(
      requestFrom('https://time.dondone.dev'),
      baseEnv()
    )
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull()
  })

  it('jsonResponse also sets the CORS header for a registered origin', async () => {
    const response = await jsonResponse(requestFrom('https://time.dondone.dev'), baseEnv(), { ok: true })
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://time.dondone.dev')
  })
})
