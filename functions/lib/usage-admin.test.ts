import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  hashRequest: vi.fn(),
  adjustWithLedger: vi.fn(),
  loadUsageDecisionContext: vi.fn(),
  upsertUsageAdjustmentAudit: vi.fn(),
}))

vi.mock('./usage-hash', () => ({ hashRequest: mocks.hashRequest }))
vi.mock('./usage-ledger-client', () => ({ adjustWithLedger: mocks.adjustWithLedger }))
vi.mock('./usage-store', () => ({
  loadUsageDecisionContext: mocks.loadUsageDecisionContext,
  upsertUsageAdjustmentAudit: mocks.upsertUsageAdjustmentAudit,
}))

import { handleAdminUsageAdjust } from './usage-admin'

describe('handleAdminUsageAdjust', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.loadUsageDecisionContext.mockResolvedValue({
      controls: [
        {
          key: 'daily_calls',
          kind: 'quota',
          window: 'calendar_day',
          value: 10,
          has_rule: true,
        },
      ],
    })
    mocks.hashRequest.mockResolvedValue('request-hash')
    mocks.adjustWithLedger.mockResolvedValue({
      operation_id: '11111111-1111-4111-8111-111111111111',
      replayed: false,
      previous_used: 4,
      used: 3,
      delta: -1,
    })
    mocks.upsertUsageAdjustmentAudit.mockResolvedValue(undefined)
  })

  it('hashes the complete stable adjustment identity', async () => {
    await handleAdminUsageAdjust(
      {} as never,
      { user: { id: '00000000-0000-4000-8000-000000000001' } } as never,
      {
        operation_id: '11111111-1111-4111-8111-111111111111',
        user_id: '22222222-2222-4222-8222-222222222222',
        service_key: 'api',
        permission_key: 'api:echo',
        control_key: 'daily_calls',
        delta: -1,
        reason: 'manual correction',
      }
    )

    expect(mocks.hashRequest).toHaveBeenCalledWith({
      operation_id: '11111111-1111-4111-8111-111111111111',
      user_id: '22222222-2222-4222-8222-222222222222',
      service_key: 'api',
      permission_key: 'api:echo',
      control_key: 'daily_calls',
      kind: 'quota',
      delta: -1,
    })
  })
})
