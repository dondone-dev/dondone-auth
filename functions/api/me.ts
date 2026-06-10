import { ApiError } from '../lib/errors'
import {
  errorResponse,
  handleOptions,
  jsonResponse,
} from '../lib/http'
import { getSupabaseUser } from '../lib/supabase'
import type { AuthEnv } from '../lib/types'

export async function handleMe(
  request: Request,
  env: AuthEnv
): Promise<Response> {
  try {
    const authorization = request.headers.get('Authorization')
    const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1]
    if (!token) {
      throw new ApiError(401, 'missing_token', 'Authorization bearer token is required.')
    }

    const user = await getSupabaseUser(env, token)
    return jsonResponse(request, env, { user })
  } catch (error) {
    return errorResponse(request, env, error)
  }
}

export const onRequest: PagesFunction<AuthEnv> = async ({ request, env }) => {
  if (request.method === 'OPTIONS') return handleOptions(request, env)
  if (request.method !== 'GET') {
    return jsonResponse(
      request,
      env,
      { error: 'method_not_allowed', message: 'Use GET.' },
      { status: 405 }
    )
  }

  return handleMe(request, env)
}
