import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'

const productionMigration = readFileSync(
  new URL('../../supabase/migrations/20260715000500_finalize_pure_role_authorization.sql', import.meta.url),
  'utf8'
)
const migrationMirror = readFileSync(
  new URL('../../docs/sql/migrations/20260715_finalize_pure_role_authorization.sql', import.meta.url),
  'utf8'
)
const authorizationSql = readFileSync(
  new URL('../../docs/sql/authorization.sql', import.meta.url),
  'utf8'
)

describe('pure-role authorization SQL contract', () => {
  it('keeps the production migration and integration mirror identical', () => {
    expect(migrationMirror).toBe(productionMigration)
  })

  it('guards the Caller role and direct-grant migration before dropping the legacy table', () => {
    expect(productionMigration).toMatch(/service_key\s*=\s*'api'[\s\S]*key\s*=\s*'caller'[\s\S]*is_system[\s\S]*status\s*=\s*'active'/i)
    expect(productionMigration).toMatch(/api_caller_role_requires_exact_api_echo_permission/i)
    expect(productionMigration).toMatch(/unexpected_active_direct_permission/i)
    expect(productionMigration).toMatch(/greatest\(excluded\.expires_at,\s*user_permission_groups\.expires_at\)/i)
    expect(productionMigration).toMatch(/drop table public\.user_permissions\s*;/i)
    expect(productionMigration).not.toMatch(/drop table public\.user_permissions\s+cascade/i)
  })

  it('defines a group-only canonical schema with no default role assignment', () => {
    expect(authorizationSql).not.toMatch(/create table if not exists public\.user_permissions/i)
    expect(authorizationSql).not.toMatch(/user_permissions_(?:user_id|lookup)_idx/i)
    expect(authorizationSql).not.toMatch(/on public\.user_permissions/i)
    expect(authorizationSql).not.toMatch(/grant[^;]+public\.user_permissions/i)
    expect(authorizationSql).not.toMatch(/from public\.user_permissions/i)

    const handleNewUser = authorizationSql.match(
      /create or replace function public\.handle_new_user\(\)[\s\S]*?\n\$\$;/i
    )?.[0]
    expect(handleNewUser).toBeDefined()
    expect(handleNewUser).toContain('insert into public.profiles')
    expect(handleNewUser).not.toContain('user_permission_groups')
  })
})
