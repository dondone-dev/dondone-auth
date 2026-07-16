import { describe, expect, it, vi } from 'vitest'
import { adjustWithLedger, consumeWithLedger, statusWithLedger } from './usage-ledger-client'
import type { AuthEnv } from './types'

function makeEnv(fetchImpl: ReturnType<typeof vi.fn>): AuthEnv {
  const stub = { fetch: fetchImpl }
  const namespace = {
    idFromName: vi.fn().mockReturnValue('id'),
    get: vi.fn().mockReturnValue(stub),
  }
  return { USAGE_LEDGER: namespace as unknown as DurableObjectNamespace } as AuthEnv
}

describe('usage-ledger-client', () => {
  it('consumeWithLedger posts to /consume', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      Response.json({
        allowed: true,
        reason: 'allowed',
        replayed: false,
        operation_id: '11111111-1111-4111-8111-111111111111',
        policy_key: 'basic',
        limits: [],
      })
    )
    const env = makeEnv(fetchMock)

    const result = await consumeWithLedger(env, 'user-1', 'api', {
      operation_id: '11111111-1111-4111-8111-111111111111',
      request_hash: 'abc',
      policy_key: 'basic',
      rules: [],
      now_ms: Date.now(),
    })

    expect(fetchMock).toHaveBeenCalledWith(
      'https://do/consume',
      expect.objectContaining({ method: 'POST' })
    )
    expect(result.allowed).toBe(true)
  })

  it('throws operation_conflict on 409', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      Response.json({ error: 'operation_conflict' }, { status: 409 })
    )
    const env = makeEnv(fetchMock)

    await expect(
      consumeWithLedger(env, 'user-1', 'api', {
        operation_id: '11111111-1111-4111-8111-111111111111',
        request_hash: 'abc',
        policy_key: 'basic',
        rules: [],
        now_ms: Date.now(),
      })
    ).rejects.toMatchObject({ status: 409, error: 'operation_conflict' })
  })

  it('statusWithLedger posts to /status', async () => {
    const fetchMock = vi.fn().mockResolvedValue(Response.json({ limits: [] }))
    const env = makeEnv(fetchMock)

    const result = await statusWithLedger(env, 'user-1', 'api', {
      rules: [],
      now_ms: Date.now(),
    })

    expect(fetchMock).toHaveBeenCalledWith(
      'https://do/status',
      expect.objectContaining({ method: 'POST' })
    )
    expect(result.limits).toEqual([])
  })

  it('adjustWithLedger posts to /adjust', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      Response.json({
        operation_id: '11111111-1111-4111-8111-111111111111',
        replayed: false,
        previous_used: 1,
        used: 3,
        delta: 2,
      })
    )
    const env = makeEnv(fetchMock)

    const result = await adjustWithLedger(env, 'user-1', 'api', {
      operation_id: '11111111-1111-4111-8111-111111111111',
      request_hash: 'abc',
      control_key: 'daily',
      kind: 'quota',
      delta: 2,
      window_start: 0,
      window_end: null,
      now_ms: Date.now(),
    })

    expect(fetchMock).toHaveBeenCalledWith(
      'https://do/adjust',
      expect.objectContaining({ method: 'POST' })
    )
    expect(result.used).toBe(3)
  })

  it('throws when USAGE_LEDGER binding is missing', async () => {
    await expect(
      consumeWithLedger({} as AuthEnv, 'user-1', 'api', {
        operation_id: '11111111-1111-4111-8111-111111111111',
        request_hash: 'abc',
        policy_key: 'basic',
        rules: [],
        now_ms: Date.now(),
      })
    ).rejects.toThrow('USAGE_LEDGER binding not configured')
  })
})
