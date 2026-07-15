import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { handleCapabilitySync, recordSyncFailure, type SyncDeps } from './capability-sync'
import type { AdminContext } from './admin-auth'
import type { AuthEnv } from './types'
import { manifestSha256, parseCapabilityManifest } from './capability-manifest'

function mockEnv(): AuthEnv {
  return {
    AUTH_CODES: {} as KVNamespace,
    SUPABASE_URL: 'https://test.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'anon-key',
    SUPABASE_SERVICE_ROLE_KEY: 'service-role-key',
    DONDONE_JWT_PRIVATE_JWK: '{}',
    DONDONE_JWT_KID: 'kid',
    DONDONE_JWT_ISSUER: 'https://auth.dondone.dev',
  }
}

function mockAdmin(): AdminContext {
  return {
    user: { id: 'admin-user-id', email: 'admin@test.com' },
    permissions: ['console:admin'],
  }
}

function validManifest() {
  return {
    resource: 'https://api.dondone.dev',
    resource_name: 'Dondone API',
    authorization_servers: ['https://auth.dondone.dev'],
    scopes_supported: ['api:echo'],
    dondone_capabilities: {
      schema_version: 1,
      catalog_version: '2026-07-14.1',
      permissions: [{ key: 'api:echo', description: 'Call the echo API.' }],
      roles: [{ key: 'basic', name: 'Basic', permission_keys: ['api:echo'] }],
    },
  }
}

const mockStore: Record<string, unknown[]> = {}
const rpcMock = vi.fn()

vi.mock('@supabase/supabase-js', () => ({
  createClient: () => createMockSupabase(),
}))

function createMockSupabase() {
  const chainable = (result: { data?: unknown; error?: unknown } = {}) => ({
    select: vi.fn().mockReturnThis(),
    insert: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    upsert: vi.fn().mockReturnThis(),
    delete: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    maybeSingle: vi.fn().mockResolvedValue(result),
    single: vi.fn().mockResolvedValue(result),
    then: (resolve: (v: unknown) => unknown) => resolve(result),
  })

  return {
    rpc: rpcMock,
    from: vi.fn((table: string) => {
      if (table === 'services') {
        return chainable({
          data: mockStore.service?.[0] ?? {
            key: 'api',
            status: 'active',
            resource_uri: 'https://api.dondone.dev',
          },
        })
      }
      if (table === 'service_capability_versions') {
        return chainable({
          data: mockStore.existingVersion?.[0] ?? null,
        })
      }
      return chainable({})
    }),
  }
}

beforeEach(() => {
  mockStore.service = undefined as unknown as unknown[]
  mockStore.existingVersion = undefined as unknown as unknown[]
  rpcMock.mockReset()
  rpcMock.mockResolvedValue({ data: [{ import_status: 'pending_review', created: true }], error: null })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('handleCapabilitySync', () => {
  it('fetches the derived well-known URL', async () => {
    const fetchManifest = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(validManifest()), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    )
    const deps: SyncDeps = { fetchManifest }

    const result = await handleCapabilitySync(mockEnv(), 'api', mockAdmin(), deps)

    expect(fetchManifest).toHaveBeenCalledWith(
      'https://api.dondone.dev/.well-known/oauth-protected-resource'
    )
    expect(result.service_key).toBe('api')
    expect(result.catalog_version).toBe('2026-07-14.1')
    expect(result.status).toBe('pending_review')
  })

  it('returns pending_review on successful import', async () => {
    const deps: SyncDeps = {
      fetchManifest: vi.fn().mockResolvedValue(
        new Response(JSON.stringify(validManifest()))
      ),
    }

    const result = await handleCapabilitySync(mockEnv(), 'api', mockAdmin(), deps)
    expect(result.status).toBe('pending_review')
  })

  it('stores the whole import through the transactional RPC', async () => {
    const deps: SyncDeps = { fetchManifest: vi.fn().mockResolvedValue(new Response(JSON.stringify(validManifest()))) }
    await handleCapabilitySync(mockEnv(), 'api', mockAdmin(), deps)
    expect(rpcMock).toHaveBeenCalledWith('import_service_capability_version', expect.objectContaining({
      p_service_key: 'api', p_catalog_version: '2026-07-14.1', p_actor: 'admin-user-id',
    }))
  })

  it('hashes and stores the fetched raw JSON including unknown standard or extension fields', async () => {
    const raw = { ...validManifest(), signed_metadata: 'future-jws', vendor_extension: { revision: 1 } }
    await handleCapabilitySync(mockEnv(), 'api', mockAdmin(), {
      fetchManifest: vi.fn().mockResolvedValue(new Response(JSON.stringify(raw))),
    })
    const rpcPayload = rpcMock.mock.calls[0][1]
    const projected = parseCapabilityManifest(raw, 'api', 'https://api.dondone.dev')
    expect(rpcPayload.p_manifest).toEqual(raw)
    expect(rpcPayload.p_manifest_sha256).toBe(await manifestSha256(raw))
    expect(rpcPayload.p_manifest_sha256).not.toBe(await manifestSha256(projected))
  })

  it('preserves approved status when an identical version is synchronized again', async () => {
    rpcMock.mockResolvedValue({ data: [{ import_status: 'approved', created: false }], error: null })
    const result = await handleCapabilitySync(mockEnv(), 'api', mockAdmin(), {
      fetchManifest: vi.fn().mockResolvedValue(new Response(JSON.stringify(validManifest()))),
    })
    expect(result.status).toBe('approved')
  })

  it('returns a conflict when the database detects a resource change during fetch', async () => {
    rpcMock.mockResolvedValue({
      data: null,
      error: { code: '23514', message: 'capability_resource_mismatch' },
    })
    await expect(handleCapabilitySync(mockEnv(), 'api', mockAdmin(), {
      fetchManifest: vi.fn().mockResolvedValue(new Response(JSON.stringify(validManifest()))),
    })).rejects.toMatchObject({ status: 409, error: 'resource_uri_changed' })
  })

  it('rejects non-2xx manifest response', async () => {
    const deps: SyncDeps = {
      fetchManifest: vi.fn().mockResolvedValue(new Response('', { status: 500 })),
    }

    await expect(
      handleCapabilitySync(mockEnv(), 'api', mockAdmin(), deps)
    ).rejects.toThrow('HTTP 500')
  })

  it('rejects network failure', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const deps: SyncDeps = {
      fetchManifest: vi.fn().mockRejectedValue(new TypeError('network error')),
    }

    await expect(
      handleCapabilitySync(mockEnv(), 'api', mockAdmin(), deps)
    ).rejects.toThrow('Could not reach')
    expect(consoleError).toHaveBeenCalledWith('Capability manifest fetch failed.', {
      url: 'https://api.dondone.dev/.well-known/oauth-protected-resource',
      reason: 'TypeError: network error',
    })
  })

  it('rejects non-JSON response', async () => {
    const deps: SyncDeps = {
      fetchManifest: vi.fn().mockResolvedValue(new Response('not json')),
    }

    await expect(
      handleCapabilitySync(mockEnv(), 'api', mockAdmin(), deps)
    ).rejects.toThrow('not valid JSON')
  })

  it('rejects invalid manifest content', async () => {
    const bad = validManifest()
    bad.resource = 'https://wrong.dev'
    const deps: SyncDeps = {
      fetchManifest: vi.fn().mockResolvedValue(
        new Response(JSON.stringify(bad))
      ),
    }

    await expect(
      handleCapabilitySync(mockEnv(), 'api', mockAdmin(), deps)
    ).rejects.toThrow('exactly equal')
  })

  it('rejects an unsafe catalog version before invoking the import RPC', async () => {
    const bad = validManifest()
    bad.dondone_capabilities.catalog_version = 'release/1'
    await expect(handleCapabilitySync(mockEnv(), 'api', mockAdmin(), {
      fetchManifest: vi.fn().mockResolvedValue(new Response(JSON.stringify(bad))),
    })).rejects.toThrow('catalog_version')
    expect(rpcMock).not.toHaveBeenCalled()
  })

  it('rejects inactive service', async () => {
    mockStore.service = [{ key: 'api', status: 'disabled', resource_uri: 'https://api.dondone.dev' }]
    const deps: SyncDeps = {
      fetchManifest: vi.fn().mockResolvedValue(
        new Response(JSON.stringify(validManifest()))
      ),
    }

    await expect(
      handleCapabilitySync(mockEnv(), 'api', mockAdmin(), deps)
    ).rejects.toThrow('not active')
  })

  it('rejects service without resource_uri', async () => {
    mockStore.service = [{ key: 'api', status: 'active', resource_uri: null }]
    const deps: SyncDeps = {
      fetchManifest: vi.fn().mockResolvedValue(
        new Response(JSON.stringify(validManifest()))
      ),
    }

    await expect(
      handleCapabilitySync(mockEnv(), 'api', mockAdmin(), deps)
    ).rejects.toThrow('resource_uri')
  })
})

describe('recordSyncFailure', () => {
  it('records service state and audit through one transactional RPC', async () => {
    await expect(
      recordSyncFailure(mockEnv(), 'api', 'user-id', 'some error')
    ).resolves.not.toThrow()
    expect(rpcMock).toHaveBeenCalledWith('record_service_capability_sync_failure', {
      p_service_key: 'api', p_actor: 'user-id', p_error: 'some error',
    })
  })
})
