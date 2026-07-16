import { describe, expect, it } from 'vitest'
import { ApiError } from './errors'
import {
  computeCounterWindow,
  evaluateConstraints,
  nextUtcMidnightMs,
  parseAdjustUsageRequest,
  parseCheckAndConsumeRequest,
  parseUsageStatusRequest,
  resolveCounterRules,
  resolveStatusCounterRules,
  utcMidnightMs,
} from './usage-policy'
import type { ResolvedUsageControl } from './usage-store'

const operationId = '11111111-1111-4111-8111-111111111111'
const userId = '22222222-2222-4222-8222-222222222222'

describe('parseCheckAndConsumeRequest', () => {
  it('parses a valid request', () => {
    const result = parseCheckAndConsumeRequest({
      service_key: 'api',
      permission_key: 'api:echo',
      operation_id: operationId,
      consume: { requests: 1 },
      context: { tier: 'pro', enabled: true, count: 2, tags: ['a'] },
    })

    expect(result).toEqual({
      service_key: 'api',
      permission_key: 'api:echo',
      operation_id: operationId,
      consume: { requests: 1 },
      context: { tier: 'pro', enabled: true, count: 2, tags: ['a'] },
    })
  })

  it('rejects invalid operation_id', () => {
    expect(() =>
      parseCheckAndConsumeRequest({
        service_key: 'api',
        permission_key: 'api:echo',
        operation_id: 'not-a-uuid',
        consume: {},
      })
    ).toThrow(ApiError)
  })

  it('rejects non-positive consume values', () => {
    expect(() =>
      parseCheckAndConsumeRequest({
        service_key: 'api',
        permission_key: 'api:echo',
        operation_id: operationId,
        consume: { requests: 0 },
      })
    ).toThrow(ApiError)
  })
})

describe('parseUsageStatusRequest', () => {
  it('parses status request without consume', () => {
    expect(
      parseUsageStatusRequest({
        service_key: 'api',
        permission_key: 'api:echo',
      })
    ).toEqual({
      service_key: 'api',
      permission_key: 'api:echo',
      context: undefined,
    })
  })
})

describe('parseAdjustUsageRequest', () => {
  it('parses a valid adjust request', () => {
    expect(
      parseAdjustUsageRequest({
        operation_id: operationId,
        user_id: userId,
        service_key: 'api',
        permission_key: 'api:echo',
        control_key: 'requests',
        delta: -2,
        reason: 'support ticket',
      })
    ).toMatchObject({ delta: -2, reason: 'support ticket' })
  })
})

describe('evaluateConstraints', () => {
  const controls: ResolvedUsageControl[] = [
    { key: 'tier', kind: 'enum_one', value: 'pro' },
    { key: 'regions', kind: 'enum_many', value: ['us', 'eu'] },
    { key: 'beta', kind: 'boolean', value: true },
    { key: 'max_items', kind: 'numeric_ceiling', value: 10 },
  ]

  it('allows matching constraints', () => {
    expect(
      evaluateConstraints(controls, {
        tier: 'pro',
        regions: ['us'],
        beta: true,
        max_items: 8,
      })
    ).toEqual({ allowed: true })
  })

  it('denies enum_one mismatch', () => {
    expect(evaluateConstraints(controls, { tier: 'free' })).toEqual({
      allowed: false,
      controlKey: 'tier',
    })
  })

  it('denies enum_many with unknown value', () => {
    expect(
      evaluateConstraints(
        [{ key: 'regions', kind: 'enum_many', value: ['us', 'eu'] }],
        { regions: ['us', 'ap'] }
      )
    ).toEqual({
      allowed: false,
      controlKey: 'regions',
    })
  })

  it('denies boolean when context is false', () => {
    expect(
      evaluateConstraints([{ key: 'beta', kind: 'boolean', value: true }], { beta: false })
    ).toEqual({
      allowed: false,
      controlKey: 'beta',
    })
  })

  it('denies numeric_ceiling overflow', () => {
    expect(
      evaluateConstraints(
        [{ key: 'max_items', kind: 'numeric_ceiling', value: 10 }],
        { max_items: 11 }
      )
    ).toEqual({
      allowed: false,
      controlKey: 'max_items',
    })
  })
})

describe('window calculation', () => {
  const now = Date.parse('2026-07-16T15:30:00.000Z')

  it('computes UTC calendar day window', () => {
    expect(utcMidnightMs(now)).toBe(Date.parse('2026-07-16T00:00:00.000Z'))
    expect(nextUtcMidnightMs(now)).toBe(Date.parse('2026-07-17T00:00:00.000Z'))
    expect(
      computeCounterWindow({ key: 'daily', kind: 'quota', window: 'calendar_day', value: 5 }, now)
    ).toEqual({
      window_start: Date.parse('2026-07-16T00:00:00.000Z'),
      window_end: null,
    })
  })

  it('computes lifetime window', () => {
    expect(
      computeCounterWindow({ key: 'lifetime', kind: 'quota', window: 'lifetime', value: 100 }, now)
    ).toEqual({ window_start: 0, window_end: null })
  })

  it('computes fixed rate_limit window aligned to epoch', () => {
    const windowSeconds = 60
    const windowMs = windowSeconds * 1000
    const windowStart = Math.floor(now / windowMs) * windowMs
    expect(
      computeCounterWindow(
        { key: 'rpm', kind: 'rate_limit', window_seconds: 60, value: 30 },
        now
      )
    ).toEqual({
      window_start: windowStart,
      window_end: windowStart + windowMs,
    })
  })
})

describe('resolveCounterRules', () => {
  const controls: ResolvedUsageControl[] = [
    { key: 'daily', kind: 'quota', window: 'calendar_day', value: 10 },
    { key: 'rpm', kind: 'rate_limit', window_seconds: 60, value: 5 },
  ]
  const now = Date.parse('2026-07-16T12:00:00.000Z')

  it('resolves consume entries to ledger rules', () => {
    const rules = resolveCounterRules(controls, { daily: 2, rpm: 1 }, now)
    expect(rules).toHaveLength(2)
    expect(rules[0]).toMatchObject({ control_key: 'daily', kind: 'quota', limit: 10, amount: 2 })
    expect(rules[1]).toMatchObject({ control_key: 'rpm', kind: 'rate_limit', limit: 5, amount: 1 })
  })

  it('rejects unknown consume keys', () => {
    expect(() => resolveCounterRules(controls, { unknown: 1 }, now)).toThrow(ApiError)
  })
})

describe('resolveStatusCounterRules', () => {
  it('includes all counter controls without amounts', () => {
    const controls: ResolvedUsageControl[] = [
      { key: 'daily', kind: 'quota', window: 'calendar_day', value: 10 },
      { key: 'tier', kind: 'enum_one', value: 'pro' },
    ]
    const rules = resolveStatusCounterRules(controls, Date.now())
    expect(rules).toHaveLength(1)
    expect(rules[0].control_key).toBe('daily')
    expect('amount' in rules[0]).toBe(false)
  })
})
