import canonicalize from 'canonicalize'

export async function hashRequest(payload: unknown): Promise<string> {
  const text = canonicalize(payload) ?? ''
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}
