import {
  errorResponse,
  handleOptions,
  jsonResponse,
} from '../lib/http'
import { publicJwks } from '../lib/dondone-jwt'
import type { AuthEnv } from '../lib/types'

export async function handleJwks(
  request: Request,
  env: AuthEnv
): Promise<Response> {
  try {
    return jsonResponse(request, env, await publicJwks(env))
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

  return handleJwks(request, env)
}
