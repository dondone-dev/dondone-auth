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

  it('initializes control diff fields to empty arrays', () => {
    const diff = classifyDiff(null, makeManifest())
    expect(diff.added_controls).toEqual([])
    expect(diff.removed_controls).toEqual([])
    expect(diff.changed_controls).toEqual([])
    expect(diff.removed_control_options).toEqual([])
  })
})

// ---------- usage control diffs ----------

function makeV2Manifest(overrides: {
  permissions?: Array<{
    key: string
    name?: string
    description?: string
    usage_controls?: Array<{
      key: string
      kind: string
      name?: string
      description?: string
      unit?: string
      window?: string
      window_seconds?: number
      minimum?: number
      maximum?: number
      options?: Array<{ value: string; label: string }>
    }>
  }>
  scopes_supported?: string[]
} = {}) {
  return {
    scopes_supported: overrides.scopes_supported ?? ['api:echo'],
    dondone_capabilities: {
      schema_version: 2,
      permissions: overrides.permissions ?? [
        {
          key: 'api:echo',
          name: 'Echo',
          description: 'Call echo.',
          usage_controls: [
            { key: 'daily_calls', kind: 'quota', name: 'Daily', unit: 'req', window: 'calendar_day', minimum: 0, maximum: 1000 },
          ],
        },
      ],
      roles: [],
    },
  }
}

describe('classifyDiff — usage controls', () => {
  it('reports added controls on first import', () => {
    const diff = classifyDiff(null, makeV2Manifest())
    expect(diff.added_controls).toEqual(['api:echo#daily_calls'])
    expect(diff.change_type).toBe('additive')
  })

  it('classifies adding a control to existing permission as breaking', () => {
    const oldM = makeV2Manifest({
      permissions: [{ key: 'api:echo', name: 'Echo', description: 'Call.' }],
    })
    const newM = makeV2Manifest()
    const diff = classifyDiff(oldM, newM)
    expect(diff.added_controls).toEqual(['api:echo#daily_calls'])
    expect(diff.change_type).toBe('breaking')
  })

  it('classifies removing a control as breaking', () => {
    const oldM = makeV2Manifest()
    const newM = makeV2Manifest({
      permissions: [{ key: 'api:echo', name: 'Echo', description: 'Call.' }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.removed_controls).toEqual(['api:echo#daily_calls'])
    expect(diff.change_type).toBe('breaking')
  })

  it('classifies changing control kind as breaking', () => {
    const oldM = makeV2Manifest()
    const newM = makeV2Manifest({
      permissions: [{
        key: 'api:echo', name: 'Echo', description: 'Call.',
        usage_controls: [
          { key: 'daily_calls', kind: 'rate_limit', name: 'Rate', unit: 'req', window_seconds: 60, minimum: 0, maximum: 1000 },
        ],
      }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.changed_controls).toEqual(['api:echo#daily_calls'])
    expect(diff.change_type).toBe('breaking')
  })

  it('classifies changing control bounds as breaking', () => {
    const oldM = makeV2Manifest()
    const newM = makeV2Manifest({
      permissions: [{
        key: 'api:echo', name: 'Echo', description: 'Call.',
        usage_controls: [
          { key: 'daily_calls', kind: 'quota', name: 'Daily', unit: 'req', window: 'calendar_day', minimum: 0, maximum: 2000 },
        ],
      }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.changed_controls).toEqual(['api:echo#daily_calls'])
    expect(diff.change_type).toBe('breaking')
  })

  it('classifies control name/description change as benign', () => {
    const oldM = makeV2Manifest()
    const newM = makeV2Manifest({
      permissions: [{
        key: 'api:echo', name: 'Echo', description: 'Call.',
        usage_controls: [
          { key: 'daily_calls', kind: 'quota', name: 'Daily Requests', description: 'Updated', unit: 'req', window: 'calendar_day', minimum: 0, maximum: 1000 },
        ],
      }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.description_changes).toContain('api:echo#daily_calls')
    expect(diff.changed_controls).toHaveLength(0)
  })

  it('classifies adding enum option as additive via structural change', () => {
    const oldM = makeV2Manifest({
      permissions: [{
        key: 'api:echo', name: 'Echo', description: 'Call.',
        usage_controls: [
          { key: 'model', kind: 'enum_one', name: 'Model', options: [{ value: 'gpt4', label: 'GPT-4' }] },
        ],
      }],
    })
    const newM = makeV2Manifest({
      permissions: [{
        key: 'api:echo', name: 'Echo', description: 'Call.',
        usage_controls: [
          { key: 'model', kind: 'enum_one', name: 'Model', options: [{ value: 'gpt4', label: 'GPT-4' }, { value: 'gpt5', label: 'GPT-5' }] },
        ],
      }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.changed_controls).toContain('api:echo#model')
    expect(diff.change_type).toBe('breaking')
  })

  it('reports removed enum option values', () => {
    const oldM = makeV2Manifest({
      permissions: [{
        key: 'api:echo', name: 'Echo', description: 'Call.',
        usage_controls: [
          { key: 'model', kind: 'enum_one', name: 'Model', options: [{ value: 'gpt4', label: 'GPT-4' }, { value: 'gpt3', label: 'GPT-3' }] },
        ],
      }],
    })
    const newM = makeV2Manifest({
      permissions: [{
        key: 'api:echo', name: 'Echo', description: 'Call.',
        usage_controls: [
          { key: 'model', kind: 'enum_one', name: 'Model', options: [{ value: 'gpt4', label: 'GPT-4' }] },
        ],
      }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.removed_control_options).toEqual(['api:echo#model:gpt3'])
    expect(diff.change_type).toBe('breaking')
  })

  it('classifies enum label change as benign description change', () => {
    const oldM = makeV2Manifest({
      permissions: [{
        key: 'api:echo', name: 'Echo', description: 'Call.',
        usage_controls: [
          { key: 'model', kind: 'enum_one', name: 'Model', options: [{ value: 'gpt4', label: 'GPT-4' }] },
        ],
      }],
    })
    const newM = makeV2Manifest({
      permissions: [{
        key: 'api:echo', name: 'Echo', description: 'Call.',
        usage_controls: [
          { key: 'model', kind: 'enum_one', name: 'Model', options: [{ value: 'gpt4', label: 'GPT-4 Turbo' }] },
        ],
      }],
    })
    const diff = classifyDiff(oldM, newM)
    expect(diff.changed_controls).toHaveLength(0)
    expect(diff.description_changes).toContain('api:echo#model')
  })

  it('classifies identical v2 manifests with no changes', () => {
    const m = makeV2Manifest()
    const diff = classifyDiff(m, m)
    expect(diff.change_type).toBe('additive')
    expect(diff.added_controls).toHaveLength(0)
    expect(diff.removed_controls).toHaveLength(0)
    expect(diff.changed_controls).toHaveLength(0)
  })

  it('removes controls when permission is removed', () => {
    const oldM = makeV2Manifest()
    const newM = makeV2Manifest({ permissions: [] })
    const diff = classifyDiff(oldM, newM)
    expect(diff.removed_permissions).toEqual(['api:echo'])
    expect(diff.removed_controls).toEqual(['api:echo#daily_calls'])
  })
})
