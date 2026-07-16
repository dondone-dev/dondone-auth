import { ApiError } from './errors'
import type { AuthEnv } from './types'
import { hashRequest } from './usage-hash'
import { adjustWithLedger } from './usage-ledger-client'
import { computeCounterWindow, parseAdjustUsageRequest } from './usage-policy'
import { loadUsageDecisionContext, upsertUsageAdjustmentAudit } from './usage-store'
import type { AdminContext } from './admin-auth'

export async function handleAdminUsageAdjust(
  env: AuthEnv,
  admin: AdminContext,
  input: unknown
): Promise<{
  operation_id: string
  replayed: boolean
  previous_used: number
  used: number
  delta: number
}> {
  const request = parseAdjustUsageRequest(input)
  const nowMs = Date.now()

  try {
    const ctx = await loadUsageDecisionContext(
      env,
      request.user_id,
      request.service_key,
      request.permission_key
    )

    const control = ctx.controls.find((entry) => entry.key === request.control_key)
    if (!control || (control.kind !== 'quota' && control.kind !== 'rate_limit')) {
      throw new ApiError(400, 'invalid_request', 'control_key is not a counter control.')
    }

    const { window_start, window_end } = computeCounterWindow(control, nowMs)
    const requestHash = await hashRequest({
      operation_id: request.operation_id,
      user_id: request.user_id,
      service_key: request.service_key,
      permission_key: request.permission_key,
      control_key: request.control_key,
      kind: control.kind,
      delta: request.delta,
    })

    const result = await adjustWithLedger(env, request.user_id, request.service_key, {
      operation_id: request.operation_id,
      request_hash: requestHash,
      control_key: request.control_key,
      kind: control.kind,
      delta: request.delta,
      window_start,
      window_end,
      now_ms: nowMs,
    })

    await upsertUsageAdjustmentAudit(env, {
      operation_id: request.operation_id,
      actor: admin.user.id,
      user_id: request.user_id,
      service_key: request.service_key,
      permission_key: request.permission_key,
      control_key: request.control_key,
      delta: request.delta,
      reason: request.reason,
      status: 'applied',
      result,
    })
    return result
  } catch (error) {
    const message = error instanceof Error ? error.message : 'adjustment failed'
    await upsertUsageAdjustmentAudit(env, {
      operation_id: request.operation_id,
      actor: admin.user.id,
      user_id: request.user_id,
      service_key: request.service_key,
      permission_key: request.permission_key,
      control_key: request.control_key,
      delta: request.delta,
      reason: request.reason,
      status: 'failed',
      result: { error: message },
    })
    if (error instanceof ApiError) throw error
    const status = (error as { status?: number }).status ?? 503
    const code = (error as { error?: string }).error ?? 'usage_service_unavailable'
    throw new ApiError(status, code, 'Usage adjustment failed.')
  }
}
