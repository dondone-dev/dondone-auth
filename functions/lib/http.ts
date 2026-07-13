import { ApiError } from './errors'
import { loadServiceRegistry } from './services'
import type { AuthEnv } from './types'

export { ApiError }

export async function jsonResponse(
  request: Request,
  env: AuthEnv,
  data: unknown,
  init: ResponseInit = {}
): Promise<Response> {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: await responseHeaders(request, env, init.headers),
  })
}

export async function errorResponse(
  request: Request,
  env: AuthEnv,
  error: unknown
): Promise<Response> {
  if (error instanceof ApiError) {
    return jsonResponse(
      request,
      env,
      { error: error.error, message: error.message },
      { status: error.status }
    )
  }

  return jsonResponse(
    request,
    env,
    { error: 'internal_error', message: 'Unexpected server error.' },
    { status: 500 }
  )
}

export async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  let value: unknown
  try {
    value = await request.json()
  } catch {
    throw new ApiError(400, 'invalid_json', 'Request body must be valid JSON.')
  }

  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiError(400, 'invalid_json', 'Request body must be a JSON object.')
  }

  return value as Record<string, unknown>
}

export function requireString(
  body: Record<string, unknown>,
  key: string
): string {
  const value = body[key]
  if (typeof value !== 'string' || value.trim() === '') {
    throw new ApiError(400, 'missing_field', `Missing required field: ${key}.`)
  }

  return value
}

export function requireNumber(
  body: Record<string, unknown>,
  key: string
): number {
  const value = body[key]
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ApiError(400, 'missing_field', `Missing required field: ${key}.`)
  }

  return value
}

export async function handleOptions(request: Request, env: AuthEnv): Promise<Response> {
  return new Response(null, {
    status: 204,
    headers: await responseHeaders(request, env, {
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'authorization,content-type',
      'Access-Control-Max-Age': '600',
    }),
  })
}

async function responseHeaders(
  request: Request,
  env: AuthEnv,
  extra?: HeadersInit
): Promise<Headers> {
  const headers = new Headers(extra)
  headers.set('Content-Type', headers.get('Content-Type') ?? 'application/json')
  headers.set('Cache-Control', 'no-store')
  headers.set('Vary', appendVary(headers.get('Vary'), 'Origin'))

  const origin = request.headers.get('Origin')
  if (origin && (await isAllowedOrigin(env, origin))) {
    headers.set('Access-Control-Allow-Origin', origin)
  }

  return headers
}

async function isAllowedOrigin(env: AuthEnv, origin: string): Promise<boolean> {
  try {
    const registry = await loadServiceRegistry(env)
    return Object.values(registry).some((app) =>
      app.redirectUris.some((redirectUri) => new URL(redirectUri).origin === origin)
    )
  } catch {
    return false
  }
}

function appendVary(current: string | null, value: string): string {
  if (!current) return value
  return current
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .includes(value.toLowerCase())
    ? current
    : `${current}, ${value}`
}
