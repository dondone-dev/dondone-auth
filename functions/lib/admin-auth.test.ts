import { describe, expect, it } from 'vitest'
import { collectEffectivePermissions } from './admin-auth'

describe('admin effective permissions', () => {
  it('collects only active unexpired group permissions uniquely and sorted', () => {
    const now = Date.parse('2026-07-15T00:00:00Z')
    const permissions = collectEffectivePermissions([
      {
        status: 'active', expires_at: null,
        permission_groups: {
          status: 'active',
          permission_group_permissions: [
            { permissions: { key: 'api:read' } },
            { permissions: { key: 'api:echo' } },
            { permissions: { key: 'api:read' } },
          ],
        },
      },
      {
        status: 'disabled', expires_at: null,
        permission_groups: {
          status: 'active',
          permission_group_permissions: [{ permissions: { key: 'ignored:disabled' } }],
        },
      },
      {
        status: 'active', expires_at: '2026-07-14T23:59:59Z',
        permission_groups: {
          status: 'active',
          permission_group_permissions: [{ permissions: { key: 'ignored:expired' } }],
        },
      },
    ], now)

    expect(permissions).toEqual(['api:echo', 'api:read'])
  })

  it('does not grant permissions through a disabled group', () => {
    const permissions = collectEffectivePermissions([{
      status: 'active', expires_at: null,
      permission_groups: {
        status: 'disabled',
        permission_group_permissions: [{ permissions: { key: 'console:admin' } }],
      },
    }], Date.now())
    expect(permissions).not.toContain('console:admin')
  })
})
