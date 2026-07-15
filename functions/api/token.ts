import { consumeAuthorizationCode } from '../lib/codes'
import {
  isResourceTokensEnabled,
  signDondoneAccessToken,
  signDondoneApiToken,
} from '../lib/dondone-jwt'
import { ApiError } from '../lib/errors'
import { verifyPkce } from '../lib/pkce'
import {
  errorResponse,
  handleOptions,
  jsonResponse,
  readJsonObject,
  requireString,
} from '../lib/http'
import {
  assertRegisteredService,
  loadApprovedScopes,
  loadServiceRegistry,
  validateRequestedScopes,
} from '../lib/services'
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

    const user = { id: record.userId, email: record.userEmail }

    if (isResourceTokensEnabled(env)) {
      if (!record.resource) {
        throw new ApiError(400, 'invalid_target', 'Authorization code is not bound to a resource.')
      }
      if (body.resource !== undefined && typeof body.resource !== 'string') {
        throw new ApiError(400, 'invalid_target', 'resource must be a string.')
      }
      const tokenResource = typeof body.resource === 'string' ? body.resource : record.resource
      if (tokenResource !== record.resource) {
        throw new ApiError(400, 'invalid_target', 'Token resource must match the authorization code resource.')
      }
      if (body.scope !== undefined && typeof body.scope !== 'string') {
        throw new ApiError(400, 'invalid_scope', 'scope must be a space-delimited string.')
      }
      const boundScopes = [...new Set(record.scopes ?? [])].sort()
      const requestedScopes = typeof body.scope === 'string'
        ? [...new Set(body.scope.split(/\s+/).filter(Boolean))].sort()
        : boundScopes
      const boundScopeSet = new Set(boundScopes)
      const widenedScopes = requestedScopes.filter((scope) => !boundScopeSet.has(scope))
      if (widenedScopes.length > 0) {
        throw new ApiError(400, 'invalid_scope', `Token scope exceeds the authorization code scope: ${widenedScopes.join(', ')}.`)
      }
      const { scopes: approvedScopes } = await loadApprovedScopes(env, record.resource)
      const validScopes = validateRequestedScopes(requestedScopes, approvedScopes)

      const apiToken = await signDondoneAccessToken({
        env,
        user,
        clientId,
        resource: record.resource,
        scopes: validScopes,
      })
      return jsonResponse(request, env, { ...record.session, ...apiToken })
    }

    const apiToken = await signDondoneApiToken(env, user, clientId)
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
