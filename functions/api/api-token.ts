import {
  errorResponse,
  handleOptions,
  jsonResponse,
  readJsonObject,
} from '../lib/http'
import { signDondoneAccessToken } from '../lib/dondone-jwt'
import { ApiError } from '../lib/errors'
import { loadApprovedScopes, validateRequestedScopes } from '../lib/services'
import { getSupabaseUser } from '../lib/supabase'
import type { AuthEnv, SupabaseUser } from '../lib/types'

type VerifyAccessToken = (
  env: AuthEnv,
  accessToken: string
) => Promise<SupabaseUser>

export async function handleApiToken(
  request: Request,
  env: AuthEnv,
  verifyAccessToken: VerifyAccessToken = getSupabaseUser
): Promise<Response> {
  try {
    const authorization = request.headers.get('Authorization')
    const accessToken = authorization?.match(/^Bearer\s+(.+)$/i)?.[1]
    if (!accessToken) {
      throw new ApiError(401, 'missing_token', 'Authorization bearer token is required.')
    }

    const user = await verifyAccessToken(env, accessToken)

    const body = await readJsonObject(request)
    const resource = body.resource
    if (typeof resource !== 'string' || resource.trim() === '') {
      throw new ApiError(400, 'invalid_target', 'resource parameter is required.')
    }

    if (Array.isArray(body.scope) && !body.scope.every((scope) => typeof scope === 'string')) {
      throw new ApiError(400, 'invalid_scope', 'scope array must contain only strings.')
    }
    const requestedScopes = Array.isArray(body.scope)
      ? body.scope as string[]
      : typeof body.scope === 'string'
        ? body.scope.split(' ').filter(Boolean)
        : []

    if (requestedScopes.length === 0) {
      throw new ApiError(400, 'invalid_scope', 'A non-empty scope is required.')
    }

    const { scopes: approvedScopes } = await loadApprovedScopes(env, resource)
    const validScopes = validateRequestedScopes(requestedScopes, approvedScopes)

    const token = await signDondoneAccessToken({
      env,
      user,
      clientId: 'auth',
      resource,
      scopes: validScopes,
    })

    return jsonResponse(request, env, token)
  } catch (error) {
    return errorResponse(request, env, error)
  }
}

export const onRequest: PagesFunction<AuthEnv> = async ({ request, env }) => {
  if (request.method === 'OPTIONS') return handleOptions(request, env)
  if (request.method !== 'POST') {
    return jsonResponse(
      request,
      env,
      { error: 'method_not_allowed', message: 'Use POST.' },
      { status: 405 }
    )
  }

  return handleApiToken(request, env)
}
