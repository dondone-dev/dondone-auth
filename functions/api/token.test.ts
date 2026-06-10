import { describe, expect, it } from 'vitest'
import { createAuthorizationCode } from '../lib/codes'
import { computeS256Challenge } from '../lib/pkce'
import type { AuthEnv, AuthorizationCodeRecord } from '../lib/types'
import { handleToken } from './token'

const CODE_VERIFIER = 'verifier-abc-123'

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

function env(kv: KVNamespace): AuthEnv {
  return {
    AUTH_CODES: kv,
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

describe('POST /api/token', () => {
  it('exchanges a code once for a Supabase session', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const session = {
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      expires_at: 123,
      token_type: 'bearer',
    }
    const record: AuthorizationCodeRecord = {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER),
      userId: 'user-123',
      session,
    }
    const code = await createAuthorizationCode(kv, record)

    const request = () =>
      new Request('https://auth.dondone.dev/api/token', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          code,
          code_verifier: CODE_VERIFIER,
        }),
      })

    const response = await handleToken(request(), env(kv))
    const secondResponse = await handleToken(request(), env(kv))

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual(session)
    expect(secondResponse.status).toBe(410)
  })

  it('rejects a code redeemed with the wrong redirect URI', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER),
      userId: 'user-123',
      session: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 123,
        token_type: 'bearer',
      },
    })

    const response = await handleToken(
      new Request('https://auth.dondone.dev/api/token', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/wrong',
          code,
          code_verifier: CODE_VERIFIER,
        }),
      }),
      env(kv)
    )

    expect(response.status).toBe(403)
  })

  it('rejects a code redeemed with the wrong client', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER),
      userId: 'user-123',
      session: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 123,
        token_type: 'bearer',
      },
    })

    const response = await handleToken(
      new Request('https://auth.dondone.dev/api/token', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'notes',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          code,
          code_verifier: CODE_VERIFIER,
        }),
      }),
      {
        ...env(kv),
        AUTH_APPS_JSON: JSON.stringify({
          notes: {
            name: 'Notes',
            redirectUris: ['https://time.dondone.dev/auth/callback'],
          },
          time: {
            name: 'Time',
            redirectUris: ['https://time.dondone.dev/auth/callback'],
          },
        }),
      }
    )

    expect(response.status).toBe(403)
  })

  it('rejects a code redeemed with the wrong PKCE verifier', async () => {
    const kv = new MemoryKV() as unknown as KVNamespace
    const code = await createAuthorizationCode(kv, {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      codeChallenge: await computeS256Challenge(CODE_VERIFIER),
      userId: 'user-123',
      session: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 123,
        token_type: 'bearer',
      },
    })

    const response = await handleToken(
      new Request('https://auth.dondone.dev/api/token', {
        method: 'POST',
        body: JSON.stringify({
          client_id: 'time',
          redirect_uri: 'https://time.dondone.dev/auth/callback',
          code,
          code_verifier: 'wrong-verifier',
        }),
      }),
      env(kv)
    )

    expect(response.status).toBe(403)
  })
})
