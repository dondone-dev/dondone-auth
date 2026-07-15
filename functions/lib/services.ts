import { ApiError } from './errors'
import type { AuthApp, AuthEnv, ServiceRegistry } from './types'

const REGISTRY_CACHE_TTL_SECONDS = 30

interface RegistryRow {
  key: unknown
  name: unknown
  redirect_uris: unknown
}

let inFlightFetch: Promise<ServiceRegistry> | null = null

export async function loadServiceRegistry(env: AuthEnv): Promise<ServiceRegistry> {
  const cached = await readFromCache(env)
  if (cached) return cached

  const registry = await fetchServiceRegistryFromDb(env)
  await writeToCache(env, registry)
  return registry
}

function cacheKeyFor(env: AuthEnv): Request {
  return new Request(
    `https://cache.dondone-auth.internal/service-registry?project=${encodeURIComponent(env.SUPABASE_URL)}`
  )
}

async function readFromCache(env: AuthEnv): Promise<ServiceRegistry | null> {
  try {
    const cached = await caches.default.match(cacheKeyFor(env))
    if (!cached) return null
    const parsed: unknown = await cached.json()
    return isServiceRegistry(parsed) ? parsed : null
  } catch {
    return null
  }
}

async function writeToCache(env: AuthEnv, registry: ServiceRegistry): Promise<void> {
  try {
    const response = new Response(JSON.stringify(registry), {
      headers: { 'Cache-Control': `max-age=${REGISTRY_CACHE_TTL_SECONDS}` },
    })
    void caches.default.put(cacheKeyFor(env), response).catch(() => {})
  } catch {
    // caches.default itself unavailable
  }
}

function isServiceRegistry(value: unknown): value is ServiceRegistry {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  return Object.values(value).every((app) => {
    if (app === null || typeof app !== 'object') return false
    const candidate = app as { name?: unknown; redirectUris?: unknown }
    return (
      typeof candidate.name === 'string' &&
      Array.isArray(candidate.redirectUris) &&
      candidate.redirectUris.length > 0 &&
      candidate.redirectUris.every(
        (uri) => typeof uri === 'string' && isStrictlyValidRedirectUri(uri)
      )
    )
  })
}

function fetchServiceRegistryFromDb(env: AuthEnv): Promise<ServiceRegistry> {
  if (inFlightFetch) return inFlightFetch
  inFlightFetch = fetchServiceRegistryFromDbUncached(env).finally(() => {
    inFlightFetch = null
  })
  return inFlightFetch
}

async function fetchServiceRegistryFromDbUncached(env: AuthEnv): Promise<ServiceRegistry> {
  let response: Response
  try {
    response = await fetch(
      `${env.SUPABASE_URL}/rest/v1/oauth_client_registry?select=key,name,redirect_uris`,
      { headers: { apikey: env.SUPABASE_PUBLISHABLE_KEY } }
    )
  } catch {
    throw new ApiError(500, 'registry_unavailable', 'Could not reach the service registry.')
  }
  if (!response.ok) {
    throw new ApiError(500, 'registry_unavailable', 'Could not load the service registry.')
  }

  let rows: unknown
  try {
    rows = await response.json()
  } catch {
    throw new ApiError(500, 'registry_unavailable', 'Service registry response was not valid JSON.')
  }
  if (!Array.isArray(rows)) {
    throw new ApiError(500, 'registry_unavailable', 'Service registry response had an unexpected shape.')
  }

  const registry: ServiceRegistry = {}
  for (const row of rows as RegistryRow[]) {
    if (typeof row.key !== 'string' || typeof row.name !== 'string' || !Array.isArray(row.redirect_uris)) {
      continue
    }
    const redirectUris = row.redirect_uris
      .filter((uri): uri is string => typeof uri === 'string')
      .filter(isStrictlyValidRedirectUri)
      .map((uri) => new URL(uri).toString())
    if (redirectUris.length === 0) continue
    registry[row.key] = { name: row.name, redirectUris }
  }
  return registry
}

function isStrictlyValidRedirectUri(uri: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(uri)
  } catch {
    return false
  }
  const isLoopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopback)) return false
  if (parsed.hash) return false
  if (parsed.username || parsed.password) return false
  return true
}

export function findRegisteredService(
  registry: ServiceRegistry,
  clientId: string,
  redirectUri: string
): AuthApp | null {
  const app = registry[clientId]
  if (!app) return null

  const normalizedRedirectUri = normalizeUrl(redirectUri)
  return app.redirectUris.includes(normalizedRedirectUri) ? app : null
}

export function assertRegisteredService(
  registry: ServiceRegistry,
  clientId: string,
  redirectUri: string
): AuthApp {
  const app = findRegisteredService(registry, clientId, redirectUri)
  if (!app) {
    throw new ApiError(
      403,
      'redirect_not_allowed',
      'Client or redirect_uri is not registered.'
    )
  }

  return app
}

export function normalizeUrl(value: string): string {
  try {
    return new URL(value).toString()
  } catch {
    throw new ApiError(400, 'invalid_redirect_uri', 'redirect_uri must be a valid URL.')
  }
}

interface ActiveResourceCapabilityRow {
  service_key: string
  resource_uri: string
  key: string
}

/**
 * Load the approved capability catalog for a resource URI.
 * Returns the set of valid scope keys for the resource.
 */
export async function loadApprovedScopes(
  env: AuthEnv,
  resourceUri: string
): Promise<{ serviceKey: string; scopes: Set<string> }> {
  const response = await fetch(
    `${env.SUPABASE_URL}/rest/v1/active_resource_capabilities?resource_uri=eq.${encodeURIComponent(resourceUri)}&oauth_scope=eq.true&select=service_key,resource_uri,key`,
    { headers: { apikey: env.SUPABASE_PUBLISHABLE_KEY } }
  )
  if (!response.ok) {
    throw new ApiError(500, 'registry_unavailable', 'Could not load service registry.')
  }
  const rows = (await response.json()) as ActiveResourceCapabilityRow[]
  if (rows.length === 0) {
    throw new ApiError(400, 'invalid_target', `No active service registered for resource "${resourceUri}".`)
  }
  const serviceKey = rows[0].service_key
  if (!rows.every((row) => row.service_key === serviceKey && row.resource_uri === resourceUri)) {
    throw new ApiError(500, 'registry_unavailable', 'Resource registry response was inconsistent.')
  }
  return { serviceKey, scopes: new Set(rows.map((r) => r.key)) }
}

/**
 * Validate requested scopes against the approved catalog.
 * Returns only the scopes that are both requested and approved.
 */
export function validateRequestedScopes(
  requested: string[],
  approved: Set<string>
): string[] {
  const normalized = [...new Set(requested)].sort()
  const invalid = normalized.filter((s) => !approved.has(s))
  if (invalid.length > 0) {
    throw new ApiError(
      400,
      'invalid_scope',
      `Scope(s) not in approved catalog: ${invalid.join(', ')}.`
    )
  }
  return normalized
}
