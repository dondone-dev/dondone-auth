import { createClient, type SupabaseClient } from '@supabase/supabase-js'
import { ApiError } from './errors'
import {
  capabilityMetadataUrl,
  manifestSha256,
  parseCapabilityManifest,
  type CapabilityManifest,
} from './capability-manifest'
import type { AdminContext } from './admin-auth'
import type { AuthEnv } from './types'

const FETCH_TIMEOUT_MS = 10_000

export interface SyncResult {
  service_key: string
  catalog_version: string
  status: 'pending_review' | 'approved' | 'rejected' | 'superseded' | 'failed'
}

interface ServiceRow {
  key: string
  status: string
  resource_uri: string | null
}

export interface SyncDeps {
  fetchManifest: (url: string) => Promise<Response>
}

const defaultDeps: SyncDeps = {
  fetchManifest: (url) =>
    fetch(url, {
      headers: { Accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    }),
}

export async function handleCapabilitySync(
  env: AuthEnv,
  serviceKey: string,
  admin: AdminContext,
  deps: SyncDeps = defaultDeps
): Promise<SyncResult> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })

  const service = await loadService(supabase, serviceKey)
  const url = capabilityMetadataUrl(service.resource_uri!)
  const fetched = await fetchAndParse(url, serviceKey, service.resource_uri!, deps)
  const hash = await manifestSha256(fetched.raw)
  const catalogVersion = fetched.parsed.dondone_capabilities.catalog_version

  const { data, error } = await supabase.rpc('import_service_capability_version', {
    p_service_key: serviceKey,
    p_catalog_version: catalogVersion,
    p_manifest_sha256: hash,
    p_manifest: fetched.raw,
    p_actor: admin.user.id,
  })
  if (error) {
    if (error.code === '23505' || error.message?.includes('catalog_version_conflict')) {
      throw new ApiError(409, 'catalog_version_conflict', `catalog_version "${catalogVersion}" already exists with different content.`)
    }
    if (error.code === '23514' && error.message?.includes('capability_resource_mismatch')) {
      throw new ApiError(
        409,
        'resource_uri_changed',
        'The service resource URI changed while its capability manifest was being synchronized. Retry with the current resource URI.'
      )
    }
    throw error
  }
  const row = Array.isArray(data) ? data[0] : data
  const status = row?.import_status as SyncResult['status'] | undefined
  if (!status || !['pending_review', 'approved', 'rejected', 'superseded', 'failed'].includes(status)) {
    throw new ApiError(500, 'registry_unavailable', 'Capability import returned an invalid status.')
  }
  return { service_key: serviceKey, catalog_version: catalogVersion, status }
}

async function loadService(
  supabase: SupabaseClient,
  serviceKey: string
): Promise<ServiceRow> {
  const { data, error } = await supabase
    .from('services')
    .select('key,status,resource_uri')
    .eq('key', serviceKey)
    .maybeSingle<ServiceRow>()

  if (error) throw error
  if (!data) {
    throw new ApiError(404, 'service_not_found', `Service "${serviceKey}" not found.`)
  }
  if (data.status !== 'active') {
    throw new ApiError(404, 'service_not_found', `Service "${serviceKey}" is not active.`)
  }
  if (!data.resource_uri) {
    throw new ApiError(
      422,
      'invalid_capability_manifest',
      `Service "${serviceKey}" has no resource_uri configured.`
    )
  }
  return data
}

async function fetchAndParse(
  url: string,
  serviceKey: string,
  resourceUri: string,
  deps: SyncDeps
): Promise<{ raw: Record<string, unknown>; parsed: CapabilityManifest }> {
  let response: Response
  try {
    response = await deps.fetchManifest(url)
  } catch {
    throw new ApiError(502, 'capability_source_unavailable', `Could not reach ${url}.`)
  }

  if (!response.ok) {
    throw new ApiError(
      502,
      'capability_source_unavailable',
      `Manifest endpoint returned HTTP ${response.status}.`
    )
  }

  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw new ApiError(502, 'capability_source_unavailable', 'Manifest response was not valid JSON.')
  }

  const parsed = parseCapabilityManifest(body, serviceKey, resourceUri)
  return { raw: body as Record<string, unknown>, parsed }
}

export async function recordSyncFailure(
  env: AuthEnv,
  serviceKey: string,
  actorId: string | undefined,
  errorMessage: string
): Promise<void> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })

  const { error } = await supabase.rpc('record_service_capability_sync_failure', {
    p_service_key: serviceKey,
    p_actor: actorId ?? null,
    p_error: errorMessage,
  })
  if (error) throw error
}
