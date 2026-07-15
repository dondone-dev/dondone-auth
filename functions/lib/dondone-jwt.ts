import { exportJWK, importJWK, SignJWT } from 'jose'
import type { JWK } from 'jose'
import { ApiError } from './errors'
import type { AuthEnv, SupabaseUser } from './types'

export const API_TOKEN_EXPIRES_IN_SECONDS = 15 * 60
export const API_TOKEN_SCOPE = 'api:echo'

export interface DondoneApiToken {
  api_access_token: string
  api_token_type: 'Bearer'
  api_expires_in: number
}

export function isResourceTokensEnabled(env: AuthEnv): boolean {
  return env.RESOURCE_ACCESS_TOKENS_ENABLED === 'true'
}

/**
 * Legacy token signing — fixed audience and scope.
 * Used when RESOURCE_ACCESS_TOKENS_ENABLED is not 'true'.
 */
export async function signDondoneApiToken(
  env: AuthEnv,
  user: SupabaseUser,
  clientId: string
): Promise<DondoneApiToken> {
  const privateJwk = parsePrivateJwk(env.DONDONE_JWT_PRIVATE_JWK)
  const key = await importJWK(privateJwk, 'ES256')

  const jwt = await new SignJWT({
    email: user.email,
    client_id: clientId,
    scope: API_TOKEN_SCOPE,
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid: env.DONDONE_JWT_KID,
      typ: 'JWT',
    })
    .setIssuer(env.DONDONE_JWT_ISSUER)
    .setAudience(env.DONDONE_API_AUDIENCE)
    .setSubject(user.id)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${API_TOKEN_EXPIRES_IN_SECONDS}s`)
    .sign(key)

  return {
    api_access_token: jwt,
    api_token_type: 'Bearer',
    api_expires_in: API_TOKEN_EXPIRES_IN_SECONDS,
  }
}

export interface ResourceTokenParams {
  env: AuthEnv
  user: SupabaseUser
  clientId: string
  resource: string
  scopes: string[]
}

/**
 * Resource-aware token signing — per-resource audience, typ=at+jwt,
 * scopes filtered against the approved catalog.
 */
export async function signDondoneAccessToken(
  params: ResourceTokenParams
): Promise<DondoneApiToken> {
  const { env, user, clientId, resource, scopes } = params
  const privateJwk = parsePrivateJwk(env.DONDONE_JWT_PRIVATE_JWK)
  const key = await importJWK(privateJwk, 'ES256')

  const jwt = await new SignJWT({
    email: user.email,
    client_id: clientId,
    scope: scopes.join(' '),
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid: env.DONDONE_JWT_KID,
      typ: 'at+jwt',
    })
    .setIssuer(env.DONDONE_JWT_ISSUER)
    .setAudience(resource)
    .setSubject(user.id)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${API_TOKEN_EXPIRES_IN_SECONDS}s`)
    .sign(key)

  return {
    api_access_token: jwt,
    api_token_type: 'Bearer',
    api_expires_in: API_TOKEN_EXPIRES_IN_SECONDS,
  }
}

export async function publicJwks(env: AuthEnv): Promise<{ keys: JWK[] }> {
  const privateJwk = parsePrivateJwk(env.DONDONE_JWT_PRIVATE_JWK)
  const key = await importJWK(privateJwk, 'ES256')
  const publicJwk = await exportJWK(key)
  delete publicJwk.d

  return {
    keys: [
      {
        ...publicJwk,
        alg: 'ES256',
        use: 'sig',
        kid: env.DONDONE_JWT_KID,
      },
    ],
  }
}

function parsePrivateJwk(raw: string): JWK {
  try {
    const parsed = JSON.parse(raw) as JWK
    if (
      parsed.kty !== 'EC' ||
      parsed.crv !== 'P-256' ||
      typeof parsed.x !== 'string' ||
      typeof parsed.y !== 'string' ||
      typeof parsed.d !== 'string'
    ) {
      throw new Error('Invalid private JWK.')
    }
    return parsed
  } catch {
    throw new ApiError(500, 'invalid_jwt_key', 'Dondone JWT private key is invalid.')
  }
}
