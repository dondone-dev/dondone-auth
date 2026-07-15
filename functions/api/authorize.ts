import { createAuthorizationCode } from '../lib/codes'
import {
  errorResponse,
  handleOptions,
  jsonResponse,
  readJsonObject,
  requireNumber,
  requireString,
} from '../lib/http'
import { assertSupportedPkceMethod } from '../lib/pkce'
import {
  assertRegisteredService,
  loadApprovedScopes,
  loadServiceRegistry,
  validateRequestedScopes,
} from '../lib/services'
import { ApiError } from '../lib/errors'
import { getSupabaseUser } from '../lib/supabase'
import {
  assertScopesGranted,
  loadEffectivePermissions,
  type LoadEffectivePermissions,
} from '../lib/admin-auth'
import type { AuthEnv, SupabaseUser } from '../lib/types'

type VerifyAccessToken = (
  env: AuthEnv,
  accessToken: string
) => Promise<SupabaseUser>

export async function handleAuthorize(
  request: Request,
  env: AuthEnv,
  verifyAccessToken: VerifyAccessToken = getSupabaseUser,
  loadPermissions: LoadEffectivePermissions = loadEffectivePermissions
): Promise<Response> {
  try {
    const body = await readJsonObject(request)
    const clientId = requireString(body, 'client_id')
    const redirectUri = requireString(body, 'redirect_uri')
    const state = requireString(body, 'state')
    const codeChallenge = requireString(body, 'code_challenge')
    const accessToken = requireString(body, 'access_token')
    const refreshToken = requireString(body, 'refresh_token')
    const expiresAt = requireNumber(body, 'expires_at')
    const tokenType = requireString(body, 'token_type')

    assertSupportedPkceMethod(
      typeof body.code_challenge_method === 'string'
        ? body.code_challenge_method
        : undefined
    )
    if (typeof body.resource !== 'string' || body.resource.trim() === '') {
      throw new ApiError(400, 'invalid_target', 'resource must be a non-empty string.')
    }
    const resource = body.resource.trim()
    const rawScopes = typeof body.scope === 'string'
      ? [body.scope]
      : Array.isArray(body.scope) && body.scope.every((scope) => typeof scope === 'string')
        ? body.scope
        : null
    if (!rawScopes) {
      throw new ApiError(400, 'invalid_scope', 'scope must be a string or an array of strings.')
    }
    let scopes = [...new Set(rawScopes.flatMap((scope) => scope.split(/\s+/)).filter(Boolean))].sort()
    if (scopes.length === 0) {
      throw new ApiError(400, 'invalid_scope', 'scope must contain at least one scope value.')
    }
    const registry = await loadServiceRegistry(env)
    assertRegisteredService(registry, clientId, redirectUri)
    const { scopes: approvedScopes } = await loadApprovedScopes(env, resource)
    scopes = validateRequestedScopes(scopes, approvedScopes)

    const user = await verifyAccessToken(env, accessToken)
    const permissions = await loadPermissions(env, user.id)
    assertScopesGranted(scopes, permissions)
    const code = await createAuthorizationCode(env.AUTH_CODES, {
      clientId,
      redirectUri,
      state,
      codeChallenge,
      userId: user.id,
      userEmail: user.email,
      session: {
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_at: expiresAt,
        token_type: tokenType,
      },
      resource,
      scopes,
    })

    const target = new URL(redirectUri)
    target.searchParams.set('code', code)
    target.searchParams.set('state', state)

    return jsonResponse(request, env, { redirect_to: target.toString() })
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

  return handleAuthorize(request, env)
}
