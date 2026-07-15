import canonicalize from 'canonicalize'
import { ApiError } from './errors'

const AUTH_ISSUER = 'https://auth.dondone.dev'

export interface CapabilityPermission {
  key: string
  description: string
}

export interface CapabilityRole {
  key: string
  name: string
  description?: string
  permission_keys: string[]
}

export interface DondoneCapabilities {
  schema_version: 1
  catalog_version: string
  permissions: CapabilityPermission[]
  roles: CapabilityRole[]
}

export interface CapabilityManifest {
  resource: string
  resource_name?: string
  authorization_servers: string[]
  scopes_supported: string[]
  dondone_capabilities: DondoneCapabilities
}

/**
 * Derive the well-known metadata URL from a resource URI per RFC 9728.
 * The .well-known segment is inserted after the authority, before the path.
 */
export function capabilityMetadataUrl(resourceUri: string): string {
  let parsed: URL
  try {
    parsed = new URL(resourceUri)
  } catch {
    throw new ApiError(422, 'invalid_resource_uri', 'resource_uri is not a valid URL.')
  }

  if (parsed.protocol !== 'https:') {
    throw new ApiError(422, 'invalid_resource_uri', 'resource_uri must use HTTPS.')
  }

  const path = parsed.pathname === '/' ? '' : parsed.pathname
  return `${parsed.origin}/.well-known/oauth-protected-resource${path}`
}

/**
 * Parse and validate a capability manifest against the registered service.
 */
export function parseCapabilityManifest(
  input: unknown,
  serviceKey: string,
  resourceUri: string
): CapabilityManifest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new ApiError(422, 'invalid_capability_manifest', 'Manifest must be a JSON object.')
  }

  const obj = input as Record<string, unknown>

  if (typeof obj.resource !== 'string' || obj.resource !== resourceUri) {
    throw new ApiError(
      422,
      'invalid_capability_manifest',
      `Manifest resource must exactly equal the registered resource URI "${resourceUri}".`
    )
  }

  if (
    !Array.isArray(obj.authorization_servers) ||
    !obj.authorization_servers.includes(AUTH_ISSUER)
  ) {
    throw new ApiError(
      422,
      'invalid_capability_manifest',
      `authorization_servers must include "${AUTH_ISSUER}".`
    )
  }

  if (!Array.isArray(obj.scopes_supported) || !obj.scopes_supported.every((s: unknown) => typeof s === 'string')) {
    throw new ApiError(422, 'invalid_capability_manifest', 'scopes_supported must be an array of strings.')
  }

  const caps = obj.dondone_capabilities
  if (!caps || typeof caps !== 'object' || Array.isArray(caps)) {
    throw new ApiError(422, 'invalid_capability_manifest', 'dondone_capabilities must be a JSON object.')
  }

  const capsObj = caps as Record<string, unknown>

  if (capsObj.schema_version !== 1) {
    throw new ApiError(
      422,
      'invalid_capability_manifest',
      `Unsupported schema_version: ${JSON.stringify(capsObj.schema_version)}. Only version 1 is supported.`
    )
  }

  if (
    typeof capsObj.catalog_version !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(capsObj.catalog_version)
  ) {
    throw new ApiError(
      422,
      'invalid_capability_manifest',
      'catalog_version must be 1-128 URL-safe ASCII characters matching [A-Za-z0-9][A-Za-z0-9._-]*.'
    )
  }

  const permissions = parsePermissions(capsObj.permissions, serviceKey)
  const permissionKeys = new Set(permissions.map((p) => p.key))

  const scopesSupported = obj.scopes_supported as string[]
  for (const scope of scopesSupported) {
    if (!permissionKeys.has(scope)) {
      throw new ApiError(
        422,
        'invalid_capability_manifest',
        `scopes_supported contains "${scope}" which is not declared in permissions.`
      )
    }
  }

  const roles = parseRoles(capsObj.roles, serviceKey, permissionKeys)

  return {
    resource: obj.resource as string,
    resource_name: typeof obj.resource_name === 'string' ? obj.resource_name : undefined,
    authorization_servers: obj.authorization_servers as string[],
    scopes_supported: scopesSupported,
    dondone_capabilities: {
      schema_version: 1,
      catalog_version: capsObj.catalog_version as string,
      permissions,
      roles,
    },
  }
}

function parsePermissions(input: unknown, serviceKey: string): CapabilityPermission[] {
  if (!Array.isArray(input)) {
    throw new ApiError(422, 'invalid_capability_manifest', 'permissions must be an array.')
  }

  const keys = new Set<string>()
  const result: CapabilityPermission[] = []

  for (const item of input) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new ApiError(422, 'invalid_capability_manifest', 'Each permission must be a JSON object.')
    }
    const p = item as Record<string, unknown>

    if (typeof p.key !== 'string' || p.key.trim() === '') {
      throw new ApiError(422, 'invalid_capability_manifest', 'Each permission must have a non-empty key.')
    }
    if (typeof p.description !== 'string') {
      throw new ApiError(422, 'invalid_capability_manifest', `Permission "${p.key}" must have a description string.`)
    }

    const prefix = p.key.split(':')[0]
    if (prefix !== serviceKey) {
      throw new ApiError(
        422,
        'invalid_capability_manifest',
        `Permission key "${p.key}" must start with the service namespace "${serviceKey}:".`
      )
    }

    if (keys.has(p.key)) {
      throw new ApiError(422, 'invalid_capability_manifest', `Duplicate permission key: "${p.key}".`)
    }

    keys.add(p.key)
    result.push({ key: p.key, description: p.description })
  }

  return result
}

function parseRoles(
  input: unknown,
  _serviceKey: string,
  permissionKeys: Set<string>
): CapabilityRole[] {
  if (!Array.isArray(input)) {
    throw new ApiError(422, 'invalid_capability_manifest', 'roles must be an array.')
  }

  const keys = new Set<string>()
  const result: CapabilityRole[] = []

  for (const item of input) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new ApiError(422, 'invalid_capability_manifest', 'Each role must be a JSON object.')
    }
    const r = item as Record<string, unknown>

    if (typeof r.key !== 'string' || r.key.trim() === '') {
      throw new ApiError(422, 'invalid_capability_manifest', 'Each role must have a non-empty key.')
    }
    if (typeof r.name !== 'string') {
      throw new ApiError(422, 'invalid_capability_manifest', `Role "${r.key}" must have a name string.`)
    }
    if (!Array.isArray(r.permission_keys)) {
      throw new ApiError(422, 'invalid_capability_manifest', `Role "${r.key}" must have a permission_keys array.`)
    }

    if (keys.has(r.key)) {
      throw new ApiError(422, 'invalid_capability_manifest', `Duplicate role key: "${r.key}".`)
    }

    for (const pk of r.permission_keys) {
      if (typeof pk !== 'string') {
        throw new ApiError(422, 'invalid_capability_manifest', `Role "${r.key}" has a non-string permission_key.`)
      }
      if (!permissionKeys.has(pk)) {
        throw new ApiError(
          422,
          'invalid_capability_manifest',
          `Role "${r.key}" references unknown permission "${pk}".`
        )
      }
    }

    keys.add(r.key)
    result.push({
      key: r.key,
      name: r.name,
      description: typeof r.description === 'string' ? r.description : undefined,
      permission_keys: r.permission_keys as string[],
    })
  }

  return result
}

/**
 * Compute sha256 over the RFC 8785 (JCS) canonical form of the manifest.
 * Used for the immutability check and de-duplication.
 */
export async function manifestSha256(manifest: unknown): Promise<string> {
  assertValidUnicode(manifest)
  const canonical = canonicalize(manifest)
  if (canonical === undefined) {
    throw new ApiError(500, 'canonicalization_failed', 'Failed to canonicalize the manifest.')
  }
  const bytes = new TextEncoder().encode(canonical)
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function assertValidUnicode(value: unknown): void {
  if (typeof value === 'string') {
    for (let i = 0; i < value.length; i += 1) {
      const code = value.charCodeAt(i)
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = value.charCodeAt(i + 1)
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          throw new ApiError(422, 'invalid_capability_manifest', 'Manifest contains a lone Unicode surrogate.')
        }
        i += 1
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        throw new ApiError(422, 'invalid_capability_manifest', 'Manifest contains a lone Unicode surrogate.')
      }
    }
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) assertValidUnicode(item)
    return
  }
  if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      assertValidUnicode(key)
      assertValidUnicode(item)
    }
  }
}

/**
 * Check whether a permission key is listed in scopes_supported.
 */
export function isOAuthScope(key: string, scopesSupported: string[]): boolean {
  return scopesSupported.includes(key)
}
