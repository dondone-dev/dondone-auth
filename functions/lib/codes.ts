import { base64UrlEncode } from './encoding'
import type { AuthorizationCodeRecord } from './types'

export const AUTH_CODE_TTL_SECONDS = 120

export async function createAuthorizationCode(
  kv: KVNamespace,
  record: AuthorizationCodeRecord
): Promise<string> {
  const code = randomBase64Url(32)
  await kv.put(code, JSON.stringify(record), {
    expirationTtl: AUTH_CODE_TTL_SECONDS,
  })

  return code
}

export async function consumeAuthorizationCode(
  kv: KVNamespace,
  code: string
): Promise<AuthorizationCodeRecord | null> {
  const raw = await kv.get(code)
  if (!raw) return null

  await kv.delete(code)
  return JSON.parse(raw) as AuthorizationCodeRecord
}

function randomBase64Url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes)
}
