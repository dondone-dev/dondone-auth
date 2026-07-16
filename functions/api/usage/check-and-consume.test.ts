import { describe, expect, it, vi } from 'vitest'
import { onRequestPost as checkAndConsumeHandler } from './check-and-consume'
import { onRequestPost as statusHandler } from './status'

vi.mock('../../lib/usage-api', () => ({
  checkAndConsume: vi.fn(),
  getUsageStatus: vi.fn(),
}))

import { checkAndConsume, getUsageStatus } from '../../lib/usage-api'

const operationId = '11111111-1111-4111-8111-111111111111'

describe('usage HTTP endpoints', () => {
  it('check-and-consume returns 401 without bearer token', async () => {
    const response = await checkAndConsumeHandler({
      request: new Request('https://auth.dondone.dev/api/usage/check-and-consume', {
        method: 'POST',
        body: JSON.stringify({}),
      }),
      env: {} as never,
    } as never)

    expect(response.status).toBe(401)
    expect(response.headers.get('Cache-Control')).toBe('no-store')
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('check-and-consume returns result with no-store header', async () => {
    vi.mocked(checkAndConsume).mockResolvedValue({
      allowed: true,
      reason: 'allowed',
      operation_id: operationId,
      replayed: false,
      policy_key: 'basic',
      limits: [],
    })

    const response = await checkAndConsumeHandler({
      request: new Request('https://auth.dondone.dev/api/usage/check-and-consume', {
        method: 'POST',
        headers: { Authorization: 'Bearer token', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_key: 'api',
          permission_key: 'api:echo',
          operation_id: operationId,
          consume: {},
        }),
      }),
      env: {} as never,
    } as never)

    expect(response.status).toBe(200)
    expect(response.headers.get('Cache-Control')).toBe('no-store')
    expect(await response.json()).toMatchObject({ allowed: true })
  })

  it('check-and-consume maps thrown errors to HTTP status', async () => {
    vi.mocked(checkAndConsume).mockRejectedValue(
      Object.assign(new Error('bad token'), { status: 401, error: 'invalid_token' })
    )

    const response = await checkAndConsumeHandler({
      request: new Request('https://auth.dondone.dev/api/usage/check-and-consume', {
        method: 'POST',
        headers: { Authorization: 'Bearer token', 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      }),
      env: {} as never,
    } as never)

    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: 'invalid_token' })
  })

  it('status endpoint returns usage status with no-store header', async () => {
    vi.mocked(getUsageStatus).mockResolvedValue({
      allowed: true,
      reason: 'allowed',
      policy_key: 'basic',
      limits: [],
      constraints: [],
    })

    const response = await statusHandler({
      request: new Request('https://auth.dondone.dev/api/usage/status', {
        method: 'POST',
        headers: { Authorization: 'Bearer token', 'Content-Type': 'application/json' },
        body: JSON.stringify({ service_key: 'api', permission_key: 'api:echo' }),
      }),
      env: {} as never,
    } as never)

    expect(response.status).toBe(200)
    expect(response.headers.get('Cache-Control')).toBe('no-store')
  })
})
