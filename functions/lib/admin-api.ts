import { requireAdmin } from './admin-auth'
import { ApiError } from './errors'
import { handleCapabilitySync, recordSyncFailure } from './capability-sync'
import { handleApprove, handleReject, handleDiffPreview } from './capability-approval'
import type { AuthEnv } from './types'

export async function handleAdminApi(
  request: Request,
  env: AuthEnv
): Promise<Response> {
  if (request.method === 'OPTIONS') return optionsResponse(request, env)

  try {
    const url = new URL(request.url)
    const path = url.pathname.replace(/^\/api\/admin\/?/, '')
    const admin = await requireAdmin(request, env)

    const syncMatch = path.match(/^services\/([^/]+)\/capability-sync$/)
    if (request.method === 'POST' && syncMatch) {
      const serviceKey = syncMatch[1]
      try {
        const result = await handleCapabilitySync(env, serviceKey, admin)
        return jsonResponse(request, env, result)
      } catch (error) {
        const message = error instanceof ApiError ? error.message : 'Unexpected sync error.'
        await recordSyncFailure(env, serviceKey, admin.user.id, message)
        throw error
      }
    }

    const diffMatch = path.match(
      /^services\/([^/]+)\/capability-versions\/([^/]+)\/diff$/
    )
    if (request.method === 'GET' && diffMatch) {
      const result = await handleDiffPreview(env, diffMatch[1], diffMatch[2])
      return jsonResponse(request, env, result)
    }

    const approveMatch = path.match(
      /^services\/([^/]+)\/capability-versions\/([^/]+)\/approve$/
    )
    if (request.method === 'POST' && approveMatch) {
      const body = await readJsonObject(request)
      const result = await handleApprove(
        env,
        approveMatch[1],
        approveMatch[2],
        admin,
        body
      )
      return jsonResponse(request, env, result)
    }

    const rejectMatch = path.match(
      /^services\/([^/]+)\/capability-versions\/([^/]+)\/reject$/
    )
    if (request.method === 'POST' && rejectMatch) {
      const body = await readJsonObject(request)
      const result = await handleReject(
        env,
        rejectMatch[1],
        rejectMatch[2],
        admin,
        body
      )
      return jsonResponse(request, env, result)
    }

    throw new ApiError(404, 'not_found', 'Admin endpoint not found.')
  } catch (error) {
    if (error instanceof ApiError) {
      return jsonResponse(
        request, env,
        { error: error.error, message: error.message },
        { status: error.status }
      )
    }
    return jsonResponse(request, env, { error: 'internal_error' }, { status: 500 })
  }
}

async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
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

function jsonResponse(
  request: Request,
  env: AuthEnv,
  data: unknown,
  init: ResponseInit = {}
): Response {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: responseHeaders(request, env, init.headers),
  })
}

function optionsResponse(request: Request, env: AuthEnv): Response {
  return new Response(null, {
    status: 204,
    headers: responseHeaders(request, env, {
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'authorization,content-type',
      'Access-Control-Max-Age': '600',
    }),
  })
}

function responseHeaders(request: Request, env: AuthEnv, extra?: HeadersInit): Headers {
  const headers = new Headers(extra)
  headers.set('Content-Type', headers.get('Content-Type') ?? 'application/json')
  headers.set('Cache-Control', 'no-store')
  headers.set('Vary', 'Origin')
  const origin = request.headers.get('Origin')
  const allowed = new Set((env.ADMIN_ALLOWED_ORIGINS ?? '').split(',').map((value) => value.trim()).filter(Boolean))
  if (origin && allowed.has(origin)) headers.set('Access-Control-Allow-Origin', origin)
  return headers
}
