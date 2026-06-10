import { describe, expect, it } from 'vitest'
import {
  AUTH_CODE_TTL_SECONDS,
  consumeAuthorizationCode,
  createAuthorizationCode,
} from './codes'
import type { AuthorizationCodeRecord } from './types'

class MemoryKV {
  readonly values = new Map<string, string>()
  lastTtl: number | undefined

  async get(key: string) {
    return this.values.get(key) ?? null
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }) {
    this.values.set(key, value)
    this.lastTtl = options?.expirationTtl
  }

  async delete(key: string) {
    this.values.delete(key)
  }
}

describe('authorization codes', () => {
  it('stores an authorization code with a short ttl and consumes it once', async () => {
    const kv = new MemoryKV()
    const record: AuthorizationCodeRecord = {
      clientId: 'time',
      redirectUri: 'https://time.dondone.dev/auth/callback',
      state: 'state-123',
      userId: 'user-123',
      session: {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_at: 123,
        token_type: 'bearer',
      },
    }

    const code = await createAuthorizationCode(kv as KVNamespace, record)
    const consumed = await consumeAuthorizationCode(kv as KVNamespace, code)
    const consumedAgain = await consumeAuthorizationCode(kv as KVNamespace, code)

    expect(code).toHaveLength(43)
    expect(kv.lastTtl).toBe(AUTH_CODE_TTL_SECONDS)
    expect(consumed).toEqual(record)
    expect(consumedAgain).toBeNull()
  })
})
