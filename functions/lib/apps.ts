import { ApiError } from './errors'
import type { AuthApp, AuthAppRegistry, AuthEnv } from './types'

export function parseAuthApps(raw: string): AuthAppRegistry {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new ApiError(500, 'invalid_app_registry', 'AUTH_APPS_JSON is not valid JSON.')
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ApiError(500, 'invalid_app_registry', 'AUTH_APPS_JSON must be an object.')
  }

  const registry: AuthAppRegistry = {}
  for (const [clientId, value] of Object.entries(parsed)) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue
    const app = value as Partial<AuthApp>
    if (
      typeof app.name !== 'string' ||
      !Array.isArray(app.redirectUris) ||
      !app.redirectUris.every((uri) => typeof uri === 'string')
    ) {
      continue
    }

    const redirectUris = app.redirectUris
      .map((uri) => safeNormalizeUrl(uri))
      .filter((uri): uri is string => uri !== null)
    if (redirectUris.length === 0) continue

    registry[clientId] = {
      name: app.name,
      redirectUris,
    }
  }

  return registry
}

export function findRegisteredApp(
  registry: AuthAppRegistry,
  clientId: string,
  redirectUri: string
): AuthApp | null {
  const app = registry[clientId]
  if (!app) return null

  const normalizedRedirectUri = normalizeUrl(redirectUri)
  return app.redirectUris.includes(normalizedRedirectUri) ? app : null
}

export function requireRegisteredApp(
  env: AuthEnv,
  clientId: string,
  redirectUri: string
): AuthApp {
  const app = findRegisteredApp(parseAuthApps(env.AUTH_APPS_JSON), clientId, redirectUri)
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

// 用于规整注册表（服务端配置）里的 URI：非法值跳过而非按客户端错误抛 400。
function safeNormalizeUrl(value: string): string | null {
  try {
    return new URL(value).toString()
  } catch {
    return null
  }
}
