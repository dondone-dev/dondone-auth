import {
  errorResponse,
  handleOptions,
  jsonResponse,
} from '../lib/http'
import { signDondoneApiToken } from '../lib/dondone-jwt'
import { ApiError } from '../lib/errors'
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
    return jsonResponse(request, env, await signDondoneApiToken(env, user, 'auth'))
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
