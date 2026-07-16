import { afterEach, describe, expect, it, vi } from 'vitest'

const rpcMock = vi.fn()
const fromMock = vi.fn()

vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(() => ({
    rpc: rpcMock,
    from: fromMock,
  })),
}))

import {
  ensureDefaultGroup,
  insertUsageAdjustmentAudit,
  loadUsageDecisionContext,
  upsertUsageAdjustmentAudit,
  updateUsageAdjustmentAudit,
} from './usage-store'

const env = {
  SUPABASE_URL: 'https://project.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: 'service-role-key',
} as const

describe('usage-store', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('ensureDefaultGroup calls ensure_default_service_group RPC', async () => {
    rpcMock.mockResolvedValue({ data: 'group-uuid', error: null })

    const result = await ensureDefaultGroup(env as never, 'user-1', 'api')

    expect(result).toBe('group-uuid')
    expect(rpcMock).toHaveBeenCalledWith('ensure_default_service_group', {
      p_user_id: 'user-1',
      p_service_key: 'api',
    })
  })

  it('ensureDefaultGroup throws on RPC error', async () => {
    rpcMock.mockResolvedValue({ data: null, error: { message: 'boom' } })
    await expect(ensureDefaultGroup(env as never, 'user-1', 'api')).rejects.toThrow(
      'ensure_default_service_group failed: boom'
    )
  })

  it('loadUsageDecisionContext returns parsed context', async () => {
    const context = {
      service_status: 'active',
      profile_status: 'active',
      group_id: 'group-1',
      group_key: 'default',
      group_status: 'active',
      membership_expires_at: null,
      permission_granted: true,
      policy_id: 'policy-1',
      policy_key: 'basic',
      policy_status: 'active',
      controls: [],
    }
    rpcMock.mockResolvedValue({ data: context, error: null })

    const result = await loadUsageDecisionContext(env as never, 'user-1', 'api', 'api:echo')

    expect(result).toEqual(context)
    expect(rpcMock).toHaveBeenCalledWith('load_usage_decision_context', {
      p_user_id: 'user-1',
      p_service_key: 'api',
      p_permission_key: 'api:echo',
    })
  })

  it('insertUsageAdjustmentAudit inserts pending row', async () => {
    const insertMock = vi.fn().mockResolvedValue({ error: null })
    fromMock.mockReturnValue({ insert: insertMock })

    await insertUsageAdjustmentAudit(env as never, {
      operation_id: '11111111-1111-4111-8111-111111111111',
      actor: 'actor-1',
      user_id: 'user-1',
      service_key: 'api',
      permission_key: 'api:echo',
      control_key: 'requests',
      delta: 5,
      reason: 'manual correction',
    })

    expect(insertMock).toHaveBeenCalledWith({
      operation_id: '11111111-1111-4111-8111-111111111111',
      actor: 'actor-1',
      user_id: 'user-1',
      service_key: 'api',
      permission_key: 'api:echo',
      control_key: 'requests',
      delta: 5,
      reason: 'manual correction',
      status: 'pending',
    })
  })

  it('updateUsageAdjustmentAudit updates status and result', async () => {
    const eqMock = vi.fn().mockResolvedValue({ error: null })
    const updateMock = vi.fn().mockReturnValue({ eq: eqMock })
    fromMock.mockReturnValue({ update: updateMock })

    await updateUsageAdjustmentAudit(
      env as never,
      '11111111-1111-4111-8111-111111111111',
      'applied',
      { used: 3 }
    )

    expect(updateMock).toHaveBeenCalledWith({ status: 'applied', result: { used: 3 } })
    expect(eqMock).toHaveBeenCalledWith('operation_id', '11111111-1111-4111-8111-111111111111')
  })

  it('never overwrites the original adjustment audit on operation replay or conflict', async () => {
    const upsertMock = vi.fn().mockResolvedValue({ error: null })
    fromMock.mockReturnValue({ upsert: upsertMock })
    const row = {
      operation_id: '11111111-1111-4111-8111-111111111111',
      actor: 'actor-1',
      user_id: 'user-1',
      service_key: 'api',
      permission_key: 'api:echo',
      control_key: 'requests',
      delta: 5,
      reason: 'manual correction',
      status: 'applied' as const,
      result: { used: 3 },
    }

    await upsertUsageAdjustmentAudit(env as never, row)

    expect(upsertMock).toHaveBeenCalledWith(row, {
      onConflict: 'operation_id',
      ignoreDuplicates: true,
    })
  })
})
