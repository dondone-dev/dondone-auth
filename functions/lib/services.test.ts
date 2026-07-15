import { afterEach, describe, expect, it, vi } from 'vitest'
import { assertRegisteredService, findRegisteredService, loadApprovedScopes, loadServiceRegistry, validateRequestedScopes } from './services'
import { ApiError } from './errors'
import type { AuthEnv, ServiceRegistry } from './types'

const registry: ServiceRegistry = {
  time: {
    name: 'Local Time',
    redirectUris: ['https://time.dondone.dev/auth/callback'],
  },
}

function baseEnv(overrides: Partial<AuthEnv> = {}): AuthEnv {
  return {
    AUTH_CODES: {} as KVNamespace,
    AUTH_APPS_JSON: JSON.stringify({
      time: { name: 'Local Time', redirectUris: ['https://time.dondone.dev/auth/callback'] },
    }),
    SUPABASE_URL: 'https://project.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'publishable-key',
    DONDONE_JWT_PRIVATE_JWK: '{}',
    DONDONE_JWT_KID: 'test-key',
    DONDONE_JWT_ISSUER: 'https://auth.dondone.dev',
    DONDONE_API_AUDIENCE: 'https://api.dondone.dev',
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

function dbRow(overrides: Partial<{ key: string; name: string; redirect_uris: string[] }> = {}) {
  return {
    key: 'time',
    name: 'Local Time',
    redirect_uris: ['https://time.dondone.dev/auth/callback'],
    ...overrides,
  }
}

describe('service registry matching', () => {
  it('accepts an exact registered redirect URI', () => {
    const app = findRegisteredService(
      registry,
      'time',
      'https://time.dondone.dev/auth/callback'
    )

    expect(app?.name).toBe('Local Time')
  })

  it('rejects an unregistered redirect URI for a known client', () => {
    expect(
      findRegisteredService(registry, 'time', 'https://evil.dondone.dev/auth/callback')
    ).toBeNull()
  })

  it('rejects an unknown client', () => {
    expect(
      findRegisteredService(registry, 'unknown', 'https://time.dondone.dev/auth/callback')
    ).toBeNull()
  })

  it('assertRegisteredService throws redirect_not_allowed for no match', () => {
    expect(() =>
      assertRegisteredService(registry, 'time', 'https://evil.dondone.dev/auth/callback')
    ).toThrow(ApiError)
  })

  it('assertRegisteredService returns the app for a match', () => {
    const app = assertRegisteredService(
      registry,
      'time',
      'https://time.dondone.dev/auth/callback'
    )
    expect(app.name).toBe('Local Time')
  })
})

describe('loadServiceRegistry source switch', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('reads AUTH_APPS_JSON when SERVICE_REGISTRY_SOURCE is unset', async () => {
    const result = await loadServiceRegistry(baseEnv())
    expect(result.time?.name).toBe('Local Time')
  })

  it('reads AUTH_APPS_JSON when SERVICE_REGISTRY_SOURCE is explicitly "static"', async () => {
    const result = await loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'static' }))
    expect(result.time?.name).toBe('Local Time')
  })

  it('fetches from oauth_client_registry when SERVICE_REGISTRY_SOURCE is "db", sending only apikey', async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify([dbRow()]), { status: 200 })
    )
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('caches', { default: new FakeCache() })

    const result = await loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' }))

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(String(fetchMock.mock.calls[0][0])).toContain('/rest/v1/oauth_client_registry')
    const [, init] = fetchMock.mock.calls[0]
    const headers = init.headers as Record<string, string>
    expect(headers.apikey).toBe('publishable-key')
    expect(headers.Authorization).toBeUndefined()
    expect(result.time?.name).toBe('Local Time')
  })

  it('rejects an unrecognized SERVICE_REGISTRY_SOURCE value instead of silently using AUTH_APPS_JSON', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      loadServiceRegistry({
        ...baseEnv(),
        // @ts-expect-error deliberately simulating a runtime env-var typo
        SERVICE_REGISTRY_SOURCE: 'DB',
      })
    ).rejects.toMatchObject({ status: 500, error: 'invalid_registry_source' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('throws registry_unavailable when fetch itself rejects (DNS/connection failure), without falling back', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('network error')
      })
    )
    vi.stubGlobal('caches', { default: new FakeCache() })

    await expect(
      loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' }))
    ).rejects.toMatchObject({ status: 500, error: 'registry_unavailable' })
  })

  it('excludes a DB row whose redirect URI fails the strict checks (fragment, userinfo, non-loopback http)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify([
            dbRow({
              key: 'bad-fragment',
              redirect_uris: ['https://example.dondone.dev/callback#token'],
            }),
            dbRow({
              key: 'bad-userinfo',
              redirect_uris: ['https://user:pass@example.dondone.dev/callback'],
            }),
            dbRow({
              key: 'bad-http',
              redirect_uris: ['http://example.dondone.dev/callback'],
            }),
            dbRow(),
          ]),
          { status: 200 }
        )
      )
    )
    vi.stubGlobal('caches', { default: new FakeCache() })

    const result = await loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' }))

    expect(result['bad-fragment']).toBeUndefined()
    expect(result['bad-userinfo']).toBeUndefined()
    expect(result['bad-http']).toBeUndefined()
    expect(result.time?.name).toBe('Local Time')
  })

  it('does not include a service the view omitted (e.g. disabled)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([]), { status: 200 })))
    vi.stubGlobal('caches', { default: new FakeCache() })

    const result = await loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' }))

    expect(result.time).toBeUndefined()
  })

  it('throws registry_unavailable on a DB fetch failure, without falling back to AUTH_APPS_JSON', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('error', { status: 500 })))
    vi.stubGlobal('caches', { default: new FakeCache() })

    await expect(
      loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' }))
    ).rejects.toBeInstanceOf(ApiError)
  })

  it('serves a cache hit without calling fetch again', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify([dbRow()]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('caches', { default: new FakeCache() })

    const env = baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' })
    await loadServiceRegistry(env)
    await loadServiceRegistry(env)

    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('falls through to the DB fetch when the cache read throws', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify([dbRow()]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('caches', {
      default: {
        match: async () => {
          throw new Error('cache unavailable')
        },
        put: async () => {},
      },
    })

    const result = await loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' }))

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(result.time?.name).toBe('Local Time')
  })

  it('ignores a structurally invalid cache entry and refetches from the DB', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify([dbRow()]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('caches', {
      default: {
        match: async () => new Response(JSON.stringify({ time: 'not-an-app-object' })),
        put: async () => {},
      },
    })

    const result = await loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' }))

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(result.time?.name).toBe('Local Time')
  })

  it('ignores a structurally valid cache entry containing an unsafe redirect URI', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify([dbRow()]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('caches', {
      default: {
        match: async () =>
          new Response(
            JSON.stringify({
              time: {
                name: 'Local Time',
                redirectUris: ['http://time.dondone.dev/auth/callback'],
              },
            })
          ),
        put: async () => {},
      },
    })

    const result = await loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' }))

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(result.time?.redirectUris).toEqual(['https://time.dondone.dev/auth/callback'])
  })

  it('does not fail the request when the cache write throws', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify([dbRow()]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('caches', {
      default: {
        match: async () => undefined,
        put: async () => {
          throw new Error('cache write failed')
        },
      },
    })

    const result = await loadServiceRegistry(baseEnv({ SERVICE_REGISTRY_SOURCE: 'db' }))

    expect(result.time?.name).toBe('Local Time')
  })
})

describe('loadApprovedScopes', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('loads the anon-safe active resource projection without querying services', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify([
      { service_key: 'api', resource_uri: 'https://api.dondone.dev', key: 'api:echo' },
    ]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    const result = await loadApprovedScopes(baseEnv(), 'https://api.dondone.dev')

    expect(result.serviceKey).toBe('api')
    expect([...result.scopes]).toEqual(['api:echo'])
    expect(String(fetchMock.mock.calls[0][0])).toContain('/rest/v1/active_resource_capabilities')
    expect(String(fetchMock.mock.calls[0][0])).not.toContain('/rest/v1/services?')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('validateRequestedScopes', () => {
  it('returns a deterministic de-duplicated scope list', () => {
    expect(validateRequestedScopes(['api:read', 'api:echo', 'api:read'], new Set(['api:echo', 'api:read'])))
      .toEqual(['api:echo', 'api:read'])
  })
})
