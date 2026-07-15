import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AuthEnv } from './types'
import type { AdminContext } from './admin-auth'

const mocks = vi.hoisted(() => ({ rpc: vi.fn(), versions: [] as Array<Record<string, unknown>> }))

vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({
    rpc: mocks.rpc,
    from: vi.fn(() => {
      const row = mocks.versions.shift() ?? null
      const chain = {
        select: vi.fn().mockReturnThis(), eq: vi.fn().mockReturnThis(),
        maybeSingle: vi.fn().mockResolvedValue({ data: row, error: null }),
      }
      return chain
    }),
  }),
}))

import { handleApprove, handleReject } from './capability-approval'

const env = { SUPABASE_URL: 'https://test.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'secret' } as AuthEnv
const admin = { user: { id: 'admin' }, permissions: ['console:admin'] } as AdminContext
const manifest = {
  scopes_supported: ['api:echo'],
  dondone_capabilities: {
    permissions: [{ key: 'api:echo', description: 'Echo' }],
    roles: [{ key: 'basic', name: 'Basic', permission_keys: ['api:echo'] }],
  },
}

beforeEach(() => {
  mocks.rpc.mockReset().mockResolvedValue({ data: null, error: null })
  mocks.versions = []
})

describe('capability approval transaction boundary', () => {
  it('approves using one RPC with the reviewed active version', async () => {
    mocks.versions = [
      { id: 'new', service_key: 'api', catalog_version: 'v2', manifest, import_status: 'pending_review' },
      { id: 'old', service_key: 'api', catalog_version: 'v1', manifest, import_status: 'approved' },
    ]
    await handleApprove(env, 'api', 'v2', admin, {})
    expect(mocks.rpc).toHaveBeenCalledWith('approve_service_capability_version', expect.objectContaining({
      p_service_key: 'api', p_catalog_version: 'v2', p_actor: 'admin', p_expected_active_version: 'v1',
    }))
    expect(mocks.rpc).toHaveBeenCalledTimes(1)
  })

  it('allows a superseded historical version to be explicitly re-approved for rollback', async () => {
    mocks.versions = [
      { id: 'old', service_key: 'api', catalog_version: 'v1', manifest, import_status: 'superseded' },
      { id: 'new', service_key: 'api', catalog_version: 'v2', manifest, import_status: 'approved' },
    ]
    await expect(handleApprove(env, 'api', 'v1', admin, {})).resolves.toMatchObject({ status: 'approved' })
  })

  it('returns a conflict when the target manifest is stale for the current resource identity', async () => {
    mocks.versions = [
      { id: 'new', service_key: 'api', catalog_version: 'v2', manifest, import_status: 'pending_review' },
    ]
    mocks.rpc.mockResolvedValue({
      data: null,
      error: { code: '23514', message: 'capability_resource_mismatch' },
    })
    await expect(handleApprove(env, 'api', 'v2', admin, {})).rejects.toMatchObject({
      status: 409,
      error: 'resource_uri_changed',
    })
  })

  it('rejects using one RPC so status and audit cannot diverge', async () => {
    mocks.versions = [{ id: 'new', service_key: 'api', catalog_version: 'v2', manifest, import_status: 'pending_review' }]
    await handleReject(env, 'api', 'v2', admin, { reason: 'unsafe' })
    expect(mocks.rpc).toHaveBeenCalledWith('reject_service_capability_version', {
      p_service_key: 'api', p_catalog_version: 'v2', p_actor: 'admin', p_reason: 'unsafe',
    })
    expect(mocks.rpc).toHaveBeenCalledTimes(1)
  })
})
