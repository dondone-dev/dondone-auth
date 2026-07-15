import { describe, it, expect } from 'vitest'
import { classifyDiff } from './capability-approval'

function makeManifest(overrides: {
  permissions?: Array<{ key: string; description: string }>
  roles?: Array<{ key: string; name: string; description?: string; permission_keys: string[] }>
  scopes_supported?: string[]
} = {}) {
  return {
    scopes_supported: overrides.scopes_supported ?? ['api:echo'],
    dondone_capabilities: {
      permissions: overrides.permissions ?? [
        { key: 'api:echo', description: 'Echo.' },
      ],
      roles: overrides.roles ?? [
        { key: 'basic', name: 'Basic', permission_keys: ['api:echo'] },
      ],
    },
  }
}

describe('classifyDiff', () => {
  it('classifies first import as additive', () => {
    const diff = classifyDiff(null, makeManifest())
    expect(diff.change_type).toBe('additive')
    expect(diff.added_permissions).toEqual(['api:echo'])
    expect(diff.added_roles).toEqual(['basic'])
    expect(diff.removed_permissions).toHaveLength(0)
    expect(diff.removed_roles).toHaveLength(0)
  })

  it('classifies new permission as additive', () => {
    const oldM = makeManifest()
    const newM = makeManifest({
      permissions: [
        { key: 'api:echo', description: 'Echo.' },
        { key: 'api:read', description: 'Read.' },
      ],
      scopes_supported: ['api:echo', 'api:read'],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.change_type).toBe('additive')
    expect(diff.added_permissions).toContain('api:read')
  })

  it('classifies new role as additive', () => {
    const oldM = makeManifest()
    const newM = makeManifest({
      roles: [
        { key: 'basic', name: 'Basic', permission_keys: ['api:echo'] },
        { key: 'admin', name: 'Admin', permission_keys: ['api:echo'] },
      ],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.change_type).toBe('additive')
    expect(diff.added_roles).toContain('admin')
  })

  it('classifies description change as benign', () => {
    const oldM = makeManifest()
    const newM = makeManifest({
      permissions: [{ key: 'api:echo', description: 'Updated description.' }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.change_type).toBe('benign')
    expect(diff.description_changes).toContain('api:echo')
  })

  it('classifies role name change as benign', () => {
    const oldM = makeManifest()
    const newM = makeManifest({
      roles: [{ key: 'basic', name: 'Basic Access', permission_keys: ['api:echo'] }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.change_type).toBe('benign')
  })

  it('classifies permission removal as breaking', () => {
    const oldM = makeManifest({
      permissions: [
        { key: 'api:echo', description: 'Echo.' },
        { key: 'api:read', description: 'Read.' },
      ],
      scopes_supported: ['api:echo', 'api:read'],
    })
    const newM = makeManifest()
    const diff = classifyDiff(oldM, newM)
    expect(diff.change_type).toBe('breaking')
    expect(diff.removed_permissions).toEqual(['api:read'])
  })

  it('classifies role removal as breaking', () => {
    const oldM = makeManifest({
      roles: [
        { key: 'basic', name: 'Basic', permission_keys: ['api:echo'] },
        { key: 'admin', name: 'Admin', permission_keys: ['api:echo'] },
      ],
    })
    const newM = makeManifest()
    const diff = classifyDiff(oldM, newM)
    expect(diff.change_type).toBe('breaking')
    expect(diff.removed_roles).toContain('admin')
  })

  it('classifies role membership change as breaking', () => {
    const oldM = makeManifest({
      permissions: [
        { key: 'api:echo', description: 'Echo.' },
        { key: 'api:read', description: 'Read.' },
      ],
      scopes_supported: ['api:echo', 'api:read'],
      roles: [
        { key: 'basic', name: 'Basic', permission_keys: ['api:echo', 'api:read'] },
      ],
    })
    const newM = makeManifest({
      permissions: [
        { key: 'api:echo', description: 'Echo.' },
        { key: 'api:read', description: 'Read.' },
      ],
      scopes_supported: ['api:echo', 'api:read'],
      roles: [{ key: 'basic', name: 'Basic', permission_keys: ['api:echo'] }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.change_type).toBe('breaking')
    expect(diff.changed_role_memberships).toContain('basic')
  })

  it('classifies identical manifests as additive (no changes)', () => {
    const m = makeManifest()
    const diff = classifyDiff(m, m)
    expect(diff.change_type).toBe('additive')
    expect(diff.added_permissions).toHaveLength(0)
    expect(diff.removed_permissions).toHaveLength(0)
  })

  it('reports an existing permission newly exposed as an OAuth scope as additive', () => {
    const oldM = makeManifest({ scopes_supported: [] })
    const newM = makeManifest({ scopes_supported: ['api:echo'] })
    const diff = classifyDiff(oldM, newM)
    expect(diff.change_type).toBe('additive')
    expect(diff.added_scopes).toEqual(['api:echo'])
    expect(diff.removed_scopes).toEqual([])
  })

  it('reports removing an OAuth scope separately and classifies it as breaking', () => {
    const oldM = makeManifest({ scopes_supported: ['api:echo'] })
    const newM = makeManifest({ scopes_supported: [] })
    const diff = classifyDiff(oldM, newM)
    expect(diff.change_type).toBe('breaking')
    expect(diff.removed_scopes).toEqual(['api:echo'])
    expect(diff.removed_permissions).toEqual([])
  })
})
