import { consumeAuthorizationCode } from '../lib/codes'
import { signDondoneApiToken } from '../lib/dondone-jwt'
import { ApiError } from '../lib/errors'
import { verifyPkce } from '../lib/pkce'
import {
  errorResponse,
  handleOptions,
  jsonResponse,
  readJsonObject,
  requireString,
} from '../lib/http'
import { assertRegisteredService, loadServiceRegistry } from '../lib/services'
import type { AuthEnv } from '../lib/types'

export async function handleToken(
  request: Request,
  env: AuthEnv
): Promise<Response> {
  try {
    const body = await readJsonObject(request)
    const clientId = requireString(body, 'client_id')
    const redirectUri = requireString(body, 'redirect_uri')
    const code = requireString(body, 'code')
    const codeVerifier = requireString(body, 'code_verifier')

    const registry = await loadServiceRegistry(env)
    assertRegisteredService(registry, clientId, redirectUri)
    // 先消费 code：无论后续校验是否通过，code 都立即失效，保证单次使用。
    const record = await consumeAuthorizationCode(env.AUTH_CODES, code)
    if (!record) {
      throw new ApiError(410, 'code_expired', 'Authorization code is expired or used.')
    }

    if (record.clientId !== clientId || record.redirectUri !== redirectUri) {
      throw new ApiError(
        403,
        'code_mismatch',
        'Authorization code does not match this client or redirect_uri.'
      )
    }

    await verifyPkce(record.codeChallenge, codeVerifier)
    const apiToken = await signDondoneApiToken(
      env,
      { id: record.userId, email: record.userEmail },
      clientId
    )

    return jsonResponse(request, env, { ...record.session, ...apiToken })
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

  return handleToken(request, env)
}
