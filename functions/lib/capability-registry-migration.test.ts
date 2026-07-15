import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'

const sql = readFileSync(new URL('../../docs/sql/migrations/20260714_add_service_capability_registry.sql', import.meta.url), 'utf8')
const seedMigration = readFileSync(new URL('../../docs/sql/migrations/20260714_migrate_seed_permissions_to_capabilities.sql', import.meta.url), 'utf8')

describe('capability registry migration contract', () => {
  it('exposes only the active resource capability projection to anon', () => {
    expect(sql).toMatch(/create or replace view public\.active_resource_capabilities/i)
    expect(sql).toMatch(/grant select on public\.active_resource_capabilities to anon/i)
    expect(sql).not.toMatch(/grant select on public\.services to anon/i)
  })

  it('defines transactional RPC boundaries for sync, failure, approval and rejection', () => {
    for (const fn of ['import_service_capability_version', 'record_service_capability_sync_failure', 'approve_service_capability_version', 'reject_service_capability_version']) {
      expect(sql).toMatch(new RegExp(`function public\\.${fn}\\b`, 'i'))
    }
  })

  it('projects manifest roles into immutable system groups and replaces their mappings', () => {
    expect(sql).toMatch(/insert into public\.permission_groups[\s\S]*is_system/i)
    expect(sql).toMatch(/delete from public\.permission_group_permissions[\s\S]*is_system/i)
    expect(sql).toMatch(/service_capability_role_permissions/i)
  })

  it('permits explicitly re-approving a historical superseded version for rollback', () => {
    expect(sql).toMatch(/import_status\s+not in\s*\('pending_review',\s*'superseded',\s*'rejected'\)/i)
  })

  it('migrates tier:vip to the API-owned namespace', () => {
    expect(seedMigration).toContain('api:tier:vip')
    expect(seedMigration).not.toContain("p.key in ('api:echo', 'tier:vip')")
  })
})
