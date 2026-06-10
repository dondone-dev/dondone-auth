import type { Session } from '@supabase/supabase-js'

const CLIENT_ID_PARAM = 'client_id'
const REDIRECT_URI_PARAM = 'redirect_uri'
const STATE_PARAM = 'state'
const CODE_CHALLENGE_PARAM = 'code_challenge'
const CODE_CHALLENGE_METHOD_PARAM = 'code_challenge_method'

export interface AuthorizationRequest {
  clientId: string
  redirectUri: string
  state: string
  codeChallenge: string
}

export function hasAuthorizationParams(): boolean {
  const params = new URLSearchParams(window.location.search)
  return (
    params.has(CLIENT_ID_PARAM) ||
    params.has(REDIRECT_URI_PARAM) ||
    params.has(STATE_PARAM) ||
    params.has(CODE_CHALLENGE_PARAM)
  )
}

export function parseAuthorizationRequest(): AuthorizationRequest | null {
  const params = new URLSearchParams(window.location.search)
  const clientId = params.get(CLIENT_ID_PARAM)
  const redirectUri = params.get(REDIRECT_URI_PARAM)
  const state = params.get(STATE_PARAM)
  const codeChallenge = params.get(CODE_CHALLENGE_PARAM)
  const codeChallengeMethod = params.get(CODE_CHALLENGE_METHOD_PARAM)

  if (!clientId || !redirectUri || !state || !codeChallenge) return null
  // 仅支持 S256；缺省视为 S256。
  if (codeChallengeMethod && codeChallengeMethod !== 'S256') return null

  try {
    new URL(redirectUri)
  } catch {
    return null
  }

  return { clientId, redirectUri, state, codeChallenge }
}

export function originOf(url: string): string {
  return new URL(url).origin
}

export async function createAuthorizationRedirect(
  request: AuthorizationRequest,
  session: Session
): Promise<string> {
  const response = await fetch('/api/authorize', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id: request.clientId,
      redirect_uri: request.redirectUri,
      state: request.state,
      code_challenge: request.codeChallenge,
      code_challenge_method: 'S256',
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      expires_at: session.expires_at ?? 0,
      token_type: session.token_type,
    }),
  })

  const body = (await response.json()) as {
    redirect_to?: string
    error?: string
    message?: string
  }

  if (!response.ok || !body.redirect_to) {
    throw new Error(body.message ?? body.error ?? 'Authorization failed.')
  }

  return body.redirect_to
}
