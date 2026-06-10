import { describe, expect, it } from 'vitest'
import { handleAuthorize } from './authorize'
import { ApiError } from '../lib/errors'
import type { AuthEnv, SupabaseUser } from '../lib/types'

class MemoryKV {
  readonly values = new Map<string, string>()

  async get(key: string) {
    return this.values.get(key) ?? null
  }

  async put(key: string, value: string) {
    this.values.set(key, value)
  }

  async delete(key: string) {
    this.values.delete(key)
  }
}

function env(): AuthEnv {
  return {
    AUTH_CODES: new MemoryKV() as unknown as KVNamespace,
    AUTH_APPS_JSON: JSON.stringify({
      time: {
        name: 'Time',
        redirectUris: ['https://time.dondone.dev/auth/callback'],
      },
    }),
    SUPABASE_URL: 'https://project.supabase.co',
    SUPABASE_PUBLISHABLE_KEY: 'publishable-key',
  }
}

describe('POST /api/authorize', () => {
  it('returns a redirect URL with only code and state for a valid session', async () => {
    const verify = async (): Promise<SupabaseUser> => ({
      id: 'user-123',
      email: 'user@example.com',
    })
    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          state: 'state-123',
          code_challenge: 'challenge-123',
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_at: 123,
          token_type: 'bearer',
        }),
      }),
      env(),
      verify
    )

    const body = (await response.json()) as { redirect_to: string }
    const redirectTo = new URL(body.redirect_to)

    expect(response.status).toBe(200)
    expect(redirectTo.origin).toBe('https://time.dondone.dev')
    expect(redirectTo.searchParams.get('code')).toHaveLength(43)
    expect(redirectTo.searchParams.get('state')).toBe('state-123')
    expect(body.redirect_to).not.toContain('access-token')
    expect(body.redirect_to).not.toContain('refresh-token')
  })

  it('rejects unknown clients before creating a code', async () => {
    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'unknown',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          state: 'state-123',
          code_challenge: 'challenge-123',
          access_token: 'access-token',
          refresh_token: 'refresh-token',
          expires_at: 123,
          token_type: 'bearer',
        }),
      }),
      env(),
      async () => ({ id: 'user-123' })
    )

    expect(response.status).toBe(403)
  })

  it('rejects an invalid Supabase access token', async () => {
    const response = await handleAuthorize(
      new Request('https://auth.dondone.dev/api/authorize', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          state: 'state-123',
          code_challenge: 'challenge-123',
          access_token: 'bad-token',
          refresh_token: 'refresh-token',
          expires_at: 123,
          token_type: 'bearer',
        }),
      }),
      env(),
      async () => {
        throw new ApiError(401, 'invalid_token', 'Supabase access token is invalid.')
      }
    )

    expect(response.status).toBe(401)
  })
})
