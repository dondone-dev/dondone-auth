import { createClient, type SupabaseClient } from '@supabase/supabase-js'
import { ApiError } from './errors'
import type { AdminContext } from './admin-auth'
import type { AuthEnv } from './types'

export interface ApprovalResult {
  service_key: string
  catalog_version: string
  status: 'approved'
  diff: DiffClassification
}

export interface RejectionResult {
  service_key: string
  catalog_version: string
  status: 'rejected'
}

export type ChangeType = 'additive' | 'benign' | 'breaking'

export interface DiffClassification {
  change_type: ChangeType
  added_permissions: string[]
  removed_permissions: string[]
  added_scopes: string[]
  removed_scopes: string[]
  added_roles: string[]
  removed_roles: string[]
  changed_role_memberships: string[]
  description_changes: string[]
}

interface VersionRow {
  id: string
  service_key: string
  catalog_version: string
  manifest: ManifestJson
  import_status: string
}

interface ManifestJson {
  scopes_supported?: string[]
  dondone_capabilities?: {
    permissions?: Array<{ key: string; description: string }>
    roles?: Array<{ key: string; name: string; description?: string; permission_keys: string[] }>
  }
}

export async function handleDiffPreview(
  env: AuthEnv,
  serviceKey: string,
  catalogVersion: string
): Promise<{ catalog_version: string; diff: DiffClassification }> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })

  const version = await loadReviewableVersion(supabase, serviceKey, catalogVersion, true)
  const activeVersion = await loadActiveVersion(supabase, serviceKey)
  const diff = classifyDiff(activeVersion?.manifest, version.manifest)

  return { catalog_version: catalogVersion, diff }
}

export async function handleApprove(
  env: AuthEnv,
  serviceKey: string,
  catalogVersion: string,
  admin: AdminContext,
  body: Record<string, unknown>
): Promise<ApprovalResult> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })

  const version = await loadReviewableVersion(supabase, serviceKey, catalogVersion, true)
  const activeVersion = await loadActiveVersion(supabase, serviceKey)
  const diff = classifyDiff(activeVersion?.manifest, version.manifest)

  if (diff.change_type === 'breaking') {
    if (body.allow_breaking_change !== true) {
      throw new ApiError(
        409,
        'breaking_change',
        'This version contains breaking changes. Set allow_breaking_change=true and provide change_reason.'
      )
    }
    if (typeof body.change_reason !== 'string' || body.change_reason.trim() === '') {
      throw new ApiError(400, 'missing_field', 'change_reason is required for breaking changes.')
    }
  }

  const { error } = await supabase.rpc('approve_service_capability_version', {
    p_service_key: serviceKey,
    p_catalog_version: catalogVersion,
    p_actor: admin.user.id,
    p_expected_active_version: activeVersion?.catalog_version ?? null,
    p_detail: {
      diff,
      breaking_reason: typeof body.change_reason === 'string' ? body.change_reason : undefined,
    },
  })
  if (error) {
    if (error.code === '40001' || error.message?.includes('active_version_changed')) {
      throw new ApiError(409, 'active_version_changed', 'The active version changed during review. Refresh the diff and approve again.')
    }
    if (error.code === '23514' && error.message?.includes('capability_resource_mismatch')) {
      throw new ApiError(
        409,
        'resource_uri_changed',
        'The reviewed manifest no longer matches the service resource URI. Synchronize a current manifest before approval.'
      )
    }
    throw error
  }

  return {
    service_key: serviceKey,
    catalog_version: catalogVersion,
    status: 'approved',
    diff,
  }
}

export async function handleReject(
  env: AuthEnv,
  serviceKey: string,
  catalogVersion: string,
  admin: AdminContext,
  body: Record<string, unknown>
): Promise<RejectionResult> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })

  await loadReviewableVersion(supabase, serviceKey, catalogVersion, false)

  const reason = typeof body.reason === 'string' ? body.reason.trim() : ''
  if (!reason) {
    throw new ApiError(400, 'missing_field', 'reason is required for rejection.')
  }

  const { error } = await supabase.rpc('reject_service_capability_version', {
    p_service_key: serviceKey,
    p_catalog_version: catalogVersion,
    p_actor: admin.user.id,
    p_reason: reason,
  })
  if (error) throw error

  return {
    service_key: serviceKey,
    catalog_version: catalogVersion,
    status: 'rejected',
  }
}

async function loadReviewableVersion(
  supabase: SupabaseClient,
  serviceKey: string,
  catalogVersion: string,
  allowHistorical: boolean
): Promise<VersionRow> {
  const { data, error } = await supabase
    .from('service_capability_versions')
    .select('id,service_key,catalog_version,manifest,import_status')
    .eq('service_key', serviceKey)
    .eq('catalog_version', catalogVersion)
    .maybeSingle<VersionRow>()

  if (error) throw error
  if (!data) {
    throw new ApiError(
      404,
      'version_not_found',
      `Capability version "${catalogVersion}" not found for service "${serviceKey}".`
    )
  }
  const allowed = allowHistorical
    ? ['pending_review', 'superseded', 'rejected']
    : ['pending_review']
  if (!allowed.includes(data.import_status)) {
    throw new ApiError(
      409,
      'invalid_version_status',
      `Version "${catalogVersion}" has status "${data.import_status}" and cannot be reviewed for this action.`
    )
  }
  return data
}

async function loadActiveVersion(
  supabase: SupabaseClient,
  serviceKey: string
): Promise<VersionRow | null> {
  const { data, error } = await supabase
    .from('service_capability_versions')
    .select('id,service_key,catalog_version,manifest,import_status')
    .eq('service_key', serviceKey)
    .eq('import_status', 'approved')
    .maybeSingle<VersionRow>()

  if (error) throw error
  return data ?? null
}

export function classifyDiff(
  oldManifest: ManifestJson | null | undefined,
  newManifest: ManifestJson
): DiffClassification {
  const result: DiffClassification = {
    change_type: 'additive',
    added_permissions: [],
    removed_permissions: [],
    added_scopes: [],
    removed_scopes: [],
    added_roles: [],
    removed_roles: [],
    changed_role_memberships: [],
    description_changes: [],
  }

  if (!oldManifest?.dondone_capabilities) {
    result.added_permissions = (newManifest.dondone_capabilities?.permissions ?? []).map((p) => p.key)
    result.added_roles = (newManifest.dondone_capabilities?.roles ?? []).map((r) => r.key)
    result.added_scopes = [...new Set(newManifest.scopes_supported ?? [])].sort()
    return result
  }

  const oldPerms = new Map(
    (oldManifest.dondone_capabilities.permissions ?? []).map((p) => [p.key, p])
  )
  const newPerms = new Map(
    (newManifest.dondone_capabilities?.permissions ?? []).map((p) => [p.key, p])
  )

  for (const key of newPerms.keys()) {
    if (!oldPerms.has(key)) result.added_permissions.push(key)
  }
  for (const [key, oldP] of oldPerms) {
    if (!newPerms.has(key)) {
      result.removed_permissions.push(key)
    } else {
      const newP = newPerms.get(key)!
      if (oldP.description !== newP.description) {
        result.description_changes.push(key)
      }
    }
  }

  const oldRoles = new Map(
    (oldManifest.dondone_capabilities.roles ?? []).map((r) => [r.key, r])
  )
  const newRoles = new Map(
    (newManifest.dondone_capabilities?.roles ?? []).map((r) => [r.key, r])
  )

  for (const key of newRoles.keys()) {
    if (!oldRoles.has(key)) result.added_roles.push(key)
  }
  for (const [key, oldR] of oldRoles) {
    if (!newRoles.has(key)) {
      result.removed_roles.push(key)
    } else {
      const newR = newRoles.get(key)!
      const oldPks = [...oldR.permission_keys].sort().join(',')
      const newPks = [...newR.permission_keys].sort().join(',')
      if (oldPks !== newPks) result.changed_role_memberships.push(key)
      if (oldR.name !== newR.name || oldR.description !== newR.description) {
        if (!result.description_changes.includes(key)) {
          result.description_changes.push(key)
        }
      }
    }
  }

  const oldScopes = new Set(oldManifest.scopes_supported ?? [])
  const newScopes = new Set(newManifest.scopes_supported ?? [])
  for (const s of newScopes) {
    if (!oldScopes.has(s)) result.added_scopes.push(s)
  }
  for (const s of oldScopes) {
    if (!newScopes.has(s)) result.removed_scopes.push(s)
  }

  const hasBreaking =
    result.removed_permissions.length > 0 ||
    result.removed_scopes.length > 0 ||
    result.removed_roles.length > 0 ||
    result.changed_role_memberships.length > 0

  if (hasBreaking) {
    result.change_type = 'breaking'
  } else if (
    result.added_permissions.length === 0 &&
    result.added_roles.length === 0 &&
    result.added_scopes.length === 0 &&
    result.description_changes.length > 0
  ) {
    result.change_type = 'benign'
  }

  return result
}
