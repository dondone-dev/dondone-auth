import type { AuthEnv } from './types'
import type {
  LedgerAdjustmentRequest,
  LedgerAdjustmentResponse,
  LedgerRequest,
  LedgerResponse,
  LedgerStatusRequest,
  LedgerStatusResponse,
} from '../../usage-worker/src/types'

function getDurableObjectStub(env: AuthEnv, serviceKey: string, userId: string) {
  if (!env.USAGE_LEDGER) throw new Error('USAGE_LEDGER binding not configured')
  const name = `v1:${serviceKey}:${userId}`
  const id = env.USAGE_LEDGER.idFromName(name)
  return env.USAGE_LEDGER.get(id)
}

async function readLedgerError(response: Response): Promise<never> {
  if (response.status === 409) {
    const body = (await response.json()) as { error?: string }
    throw Object.assign(new Error(body.error ?? 'operation_conflict'), {
      status: 409,
      error: 'operation_conflict',
    })
  }
  throw Object.assign(new Error('usage_service_unavailable'), {
    status: 503,
    error: 'usage_service_unavailable',
  })
}

export async function consumeWithLedger(
  env: AuthEnv,
  userId: string,
  serviceKey: string,
  request: LedgerRequest
): Promise<LedgerResponse> {
  const stub = getDurableObjectStub(env, serviceKey, userId)
  const response = await stub.fetch('https://do/consume', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  if (!response.ok) return readLedgerError(response)
  return response.json() as Promise<LedgerResponse>
}

export async function statusWithLedger(
  env: AuthEnv,
  userId: string,
  serviceKey: string,
  request: LedgerStatusRequest
): Promise<LedgerStatusResponse> {
  const stub = getDurableObjectStub(env, serviceKey, userId)
  const response = await stub.fetch('https://do/status', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  if (!response.ok) return readLedgerError(response)
  return response.json() as Promise<LedgerStatusResponse>
}

export async function adjustWithLedger(
  env: AuthEnv,
  userId: string,
  serviceKey: string,
  request: LedgerAdjustmentRequest
): Promise<LedgerAdjustmentResponse> {
  const stub = getDurableObjectStub(env, serviceKey, userId)
  const response = await stub.fetch('https://do/adjust', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  if (!response.ok) return readLedgerError(response)
  return response.json() as Promise<LedgerAdjustmentResponse>
}
