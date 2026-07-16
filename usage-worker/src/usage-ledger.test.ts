import { describe, expect, it } from 'vitest'
import {
  buildLimit,
  processAdjust,
  processConsume,
  processStatus,
  validateClockSkew,
  validateLedgerAdjustmentRequest,
  validateLedgerRequest,
} from './usage-ledger-logic'

const operationId = '11111111-1111-4111-8111-111111111111'
const nowMs = Date.parse('2026-07-16T12:00:00.000Z')

function memoryStores() {
  const counters = new Map<string, number>()
  const operations = new Map<string, { request_hash: string; response_json: string }>()

  return {
    counters: {
      getUsed: (controlKey: string, windowStart: number) =>
        counters.get(`${controlKey}:${windowStart}`) ?? 0,
      setUsed: (controlKey: string, windowStart: number, used: number) => {
        counters.set(`${controlKey}:${windowStart}`, used)
      },
    },
    operations: {
      find: (operationId: string) => operations.get(operationId) ?? null,
      insert: (operationId: string, requestHash: string, responseJson: string) => {
        operations.set(operationId, { request_hash: requestHash, response_json: responseJson })
      },
    },
    countersMap: counters,
    operationsMap: operations,
  }
}

describe('validateClockSkew', () => {
  it('accepts now_ms within five minutes', () => {
    expect(validateClockSkew(nowMs, nowMs + 60_000)).toBeNull()
  })

  it('rejects now_ms outside five minutes', () => {
    expect(validateClockSkew(nowMs, nowMs + 6 * 60_000)).toBe(
      'now_ms is outside allowed clock skew'
    )
  })
})

describe('validateLedgerRequest', () => {
  it('accepts valid consume requests', () => {
    const parsed = validateLedgerRequest({
      operation_id: operationId,
      request_hash: 'hash',
      policy_key: 'basic',
      now_ms: nowMs,
      rules: [
        {
          control_key: 'daily',
          kind: 'quota',
          limit: 10,
          amount: 1,
          window_start: 0,
          window_end: null,
        },
      ],
    })
    expect(parsed?.rules).toHaveLength(1)
  })
})

describe('processConsume', () => {
  it('allows and increments counters when within limits', () => {
    const { counters, operations } = memoryStores()
    const request = {
      operation_id: operationId,
      request_hash: 'hash-1',
      policy_key: 'basic',
      now_ms: nowMs,
      rules: [
        {
          control_key: 'daily',
          kind: 'quota' as const,
          limit: 5,
          amount: 2,
          window_start: 0,
          window_end: null,
        },
      ],
    }

    const result = processConsume(request, counters, operations, nowMs)
    expect(result).toMatchObject({ allowed: true, reason: 'allowed', replayed: false })
    expect(counters.getUsed('daily', 0)).toBe(2)
  })

  it('denies when quota would be exceeded without updating counters', () => {
    const { counters, operations } = memoryStores()
    counters.setUsed('daily', 0, 5, nowMs)

    const result = processConsume(
      {
        operation_id: operationId,
        request_hash: 'hash-1',
        policy_key: 'basic',
        now_ms: nowMs,
        rules: [
          {
            control_key: 'daily',
            kind: 'quota',
            limit: 5,
            amount: 1,
            window_start: 0,
            window_end: null,
          },
        ],
      },
      counters,
      operations,
      nowMs
    )

    expect(result).toMatchObject({ allowed: false, reason: 'quota_exhausted' })
    expect(counters.getUsed('daily', 0)).toBe(5)
  })

  it('replays identical operations', () => {
    const { counters, operations } = memoryStores()
    const request = {
      operation_id: operationId,
      request_hash: 'hash-1',
      policy_key: 'basic',
      now_ms: nowMs,
      rules: [
        {
          control_key: 'daily',
          kind: 'quota' as const,
          limit: 5,
          amount: 1,
          window_start: 0,
          window_end: null,
        },
      ],
    }

    const first = processConsume(request, counters, operations, nowMs)
    const second = processConsume(request, counters, operations, nowMs)

    expect(first).toMatchObject({ replayed: false })
    expect(second).toMatchObject({ replayed: true, allowed: true })
    expect(counters.getUsed('daily', 0)).toBe(1)
  })

  it('returns conflict for same operation_id with different hash', () => {
    const { counters, operations } = memoryStores()
    const base = {
      operation_id: operationId,
      policy_key: 'basic',
      now_ms: nowMs,
      rules: [
        {
          control_key: 'daily',
          kind: 'quota' as const,
          limit: 5,
          amount: 1,
          window_start: 0,
          window_end: null,
        },
      ],
    }

    processConsume({ ...base, request_hash: 'hash-1' }, counters, operations, nowMs)
    const conflict = processConsume({ ...base, request_hash: 'hash-2' }, counters, operations, nowMs)
    expect(conflict).toEqual({ conflict: true })
  })
})

describe('processStatus', () => {
  it('returns limits without writing counters', () => {
    const { counters } = memoryStores()
    counters.setUsed('daily', 0, 3, nowMs)

    const result = processStatus(
      {
        now_ms: nowMs,
        rules: [
          {
            control_key: 'daily',
            kind: 'quota',
            limit: 10,
            window_start: 0,
            window_end: null,
          },
        ],
      },
      counters
    )

    expect(result.limits[0]).toMatchObject({ used: 3, remaining: 7 })
    expect(counters.getUsed('daily', 0)).toBe(3)
  })
})

describe('processAdjust', () => {
  it('applies delta and clamps to zero', () => {
    const { counters, operations } = memoryStores()
    counters.setUsed('daily', 0, 2, nowMs)

    const result = processAdjust(
      {
        operation_id: operationId,
        request_hash: 'hash-1',
        control_key: 'daily',
        kind: 'quota',
        delta: -5,
        window_start: 0,
        window_end: null,
        now_ms: nowMs,
      },
      counters,
      operations,
      nowMs
    )

    expect(result).toMatchObject({ previous_used: 2, used: 0, delta: -5 })
  })
})

describe('buildLimit', () => {
  it('computes reset_at for rate limits', () => {
    const windowEnd = nowMs + 60_000
    const limit = buildLimit(
      {
        control_key: 'rpm',
        kind: 'rate_limit',
        limit: 10,
        window_start: nowMs,
        window_end: windowEnd,
      },
      4,
      nowMs
    )
    expect(limit.reset_at).toBe(new Date(windowEnd).toISOString())
  })
})

describe('validateLedgerAdjustmentRequest', () => {
  it('rejects zero delta', () => {
    expect(
      validateLedgerAdjustmentRequest({
        operation_id: operationId,
        request_hash: 'hash',
        control_key: 'daily',
        kind: 'quota',
        delta: 0,
        window_start: 0,
        window_end: null,
        now_ms: nowMs,
      })
    ).toBeNull()
  })
})
