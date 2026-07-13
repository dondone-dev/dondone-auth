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
import { assertRegisteredService, loadServiceRegistry } from '../lib/services'
import { getSupabaseUser } from '../lib/supabase'
import type { AuthEnv, SupabaseUser } from '../lib/types'

type VerifyAccessToken = (
  env: AuthEnv,
  accessToken: string
) => Promise<SupabaseUser>

export async function handleAuthorize(
  request: Request,
  env: AuthEnv,
  verifyAccessToken: VerifyAccessToken = getSupabaseUser
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
    const registry = await loadServiceRegistry(env)
    assertRegisteredService(registry, clientId, redirectUri)
    const user = await verifyAccessToken(env, accessToken)
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
