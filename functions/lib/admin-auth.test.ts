import { describe, expect, it } from 'vitest'
import { collectEffectivePermissions } from './admin-auth'

describe('admin effective permissions', () => {
  it('does not grant permissions through a disabled group', () => {
    const permissions = collectEffectivePermissions([], [{
      status: 'active', expires_at: null,
      permission_groups: {
        status: 'disabled',
        permission_group_permissions: [{ permissions: { key: 'console:admin' } }],
      },
    }], Date.now())
    expect(permissions).not.toContain('console:admin')
  })
})
