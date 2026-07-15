import { createClient } from '@supabase/supabase-js'
import { ApiError } from './errors'
import type { AuthEnv, SupabaseUser } from './types'

export interface AdminContext {
  user: SupabaseUser
  permissions: string[]
}

export async function requireAdmin(
  request: Request,
  env: AuthEnv
): Promise<AdminContext> {
  const authorization = request.headers.get('Authorization')
  const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1]
  if (!token) {
    throw new ApiError(401, 'missing_token', 'Authorization bearer token is required.')
  }

  const userResponse = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
    headers: {
      apikey: env.SUPABASE_PUBLISHABLE_KEY,
      Authorization: `Bearer ${token}`,
    },
  })
  if (!userResponse.ok) {
    throw new ApiError(401, 'invalid_token', 'Supabase access token is invalid.')
  }

  const data = (await userResponse.json()) as { id?: unknown; email?: unknown }
  if (typeof data.id !== 'string') {
    throw new ApiError(401, 'invalid_token', 'Supabase access token is invalid.')
  }

  const user: SupabaseUser = {
    id: data.id,
    email: typeof data.email === 'string' ? data.email : undefined,
  }

  const permissions = await loadEffectivePermissions(env, user.id)
  if (!permissions.includes('console:admin')) {
    throw new ApiError(403, 'admin_required', 'This action requires console:admin permission.')
  }

  return { user, permissions }
}

export interface PermissionGroupRow {
  status: string
  expires_at: string | null
  permission_groups: {
    status: string
    permission_group_permissions: Array<{
      permissions: { key: string } | null
    }>
  } | null
}

async function loadEffectivePermissions(
  env: AuthEnv,
  userId: string
): Promise<string[]> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })

  const [directResult, groupResult] = await Promise.all([
    supabase
      .from('user_permissions')
      .select('permission_key,status,expires_at')
      .eq('user_id', userId),
    supabase
      .from('user_permission_groups')
      .select('status,expires_at,permission_groups(status,permission_group_permissions(permissions(key)))')
      .eq('user_id', userId),
  ])

  if (directResult.error) throw directResult.error
  if (groupResult.error) throw groupResult.error
  return collectEffectivePermissions(
    directResult.data ?? [],
    (groupResult.data ?? []) as unknown as PermissionGroupRow[],
    Date.now()
  )
}

export function collectEffectivePermissions(
  directRows: Array<{ permission_key: string; status: string; expires_at: string | null }>,
  groupRows: PermissionGroupRow[],
  now: number
): string[] {
  const direct = directRows
    .filter((r: { status: string; expires_at: string | null }) =>
      r.status === 'active' && (!r.expires_at || Date.parse(r.expires_at) > now))
    .map((r: { permission_key: string }) => r.permission_key)

  const grouped = groupRows
    .filter((r) => r.status === 'active' && (!r.expires_at || Date.parse(r.expires_at) > now))
    .flatMap((r) =>
      r.permission_groups?.status === 'active'
        ? r.permission_groups.permission_group_permissions
        .map((e) => e.permissions?.key)
        .filter((key): key is string => typeof key === 'string') ?? []
        : []
    )

  return [...new Set([...direct, ...grouped])].sort()
}
