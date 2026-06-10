import { base64UrlEncode } from './encoding'
import { ApiError } from './errors'

// 仅支持 S256。业务应用生成 code_verifier，并以 base64url(sha256(verifier)) 作为 code_challenge。
export const PKCE_METHOD = 'S256'

export async function computeS256Challenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return base64UrlEncode(new Uint8Array(digest))
}

export function assertSupportedPkceMethod(method: string | undefined): void {
  if (method !== undefined && method !== PKCE_METHOD) {
    throw new ApiError(
      400,
      'unsupported_pkce_method',
      'Only the S256 code_challenge_method is supported.'
    )
  }
}

export async function verifyPkce(
  codeChallenge: string,
  codeVerifier: string
): Promise<void> {
  const computed = await computeS256Challenge(codeVerifier)
  if (computed !== codeChallenge) {
    throw new ApiError(
      403,
      'invalid_grant',
      'PKCE code_verifier does not match the authorization request.'
    )
  }
}
