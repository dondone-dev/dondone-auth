import type {
  LedgerAdjustmentRequest,
  LedgerAdjustmentResponse,
  LedgerRequest,
  LedgerResponse,
  LedgerRule,
  LedgerStatusRequest,
  LedgerStatusResponse,
  LedgerStatusRule,
} from './types'

export const OPERATION_TTL_MS = 48 * 60 * 60 * 1000
export const CLOCK_SKEW_MS = 5 * 60 * 1000

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export function validateClockSkew(nowMs: number, serverNowMs: number): string | null {
  if (!Number.isFinite(nowMs)) return 'now_ms must be a finite number'
  if (Math.abs(serverNowMs - nowMs) > CLOCK_SKEW_MS) return 'now_ms is outside allowed clock skew'
  return null
}

export function validateLedgerRequest(input: unknown): LedgerRequest | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null
  const body = input as Record<string, unknown>
  if (typeof body.operation_id !== 'string' || !UUID_RE.test(body.operation_id)) return null
  if (typeof body.request_hash !== 'string' || body.request_hash.length === 0) return null
  if (typeof body.policy_key !== 'string' || body.policy_key.length === 0) return null
  if (typeof body.now_ms !== 'number' || !Number.isFinite(body.now_ms)) return null
  if (!Array.isArray(body.rules)) return null

  const rules: LedgerRule[] = []
  for (const rule of body.rules) {
    const parsed = parseLedgerRule(rule)
    if (!parsed) return null
    rules.push(parsed)
  }

  return {
    operation_id: body.operation_id,
    request_hash: body.request_hash,
    policy_key: body.policy_key,
    rules,
    now_ms: body.now_ms,
  }
}

function parseLedgerRule(input: unknown): LedgerRule | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null
  const rule = input as Record<string, unknown>
  if (typeof rule.control_key !== 'string' || rule.control_key.length === 0) return null
  if (rule.kind !== 'quota' && rule.kind !== 'rate_limit') return null
  if (typeof rule.limit !== 'number' || !Number.isSafeInteger(rule.limit) || rule.limit < 0) return null
  if (typeof rule.amount !== 'number' || !Number.isSafeInteger(rule.amount) || rule.amount <= 0) return null
  if (typeof rule.window_start !== 'number' || !Number.isSafeInteger(rule.window_start) || rule.window_start < 0) {
    return null
  }
  if (rule.window_end !== null) {
    if (typeof rule.window_end !== 'number' || !Number.isSafeInteger(rule.window_end)) return null
  }
  return {
    control_key: rule.control_key,
    kind: rule.kind,
    limit: rule.limit,
    amount: rule.amount,
    window_start: rule.window_start,
    window_end: rule.window_end as number | null,
  }
}

export function validateLedgerStatusRequest(input: unknown): LedgerStatusRequest | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null
  const body = input as Record<string, unknown>
  if (typeof body.now_ms !== 'number' || !Number.isFinite(body.now_ms)) return null
  if (!Array.isArray(body.rules)) return null

  const rules: LedgerStatusRule[] = []
  for (const rule of body.rules) {
    const parsed = parseLedgerStatusRule(rule)
    if (!parsed) return null
    rules.push(parsed)
  }

  return { rules, now_ms: body.now_ms }
}

function parseLedgerStatusRule(input: unknown): LedgerStatusRule | null {
  const parsed = parseLedgerRule({ ...(input as object), amount: 1 })
  if (!parsed) return null
  return {
    control_key: parsed.control_key,
    kind: parsed.kind,
    limit: parsed.limit,
    window_start: parsed.window_start,
    window_end: parsed.window_end,
  }
}

export function validateLedgerAdjustmentRequest(input: unknown): LedgerAdjustmentRequest | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null
  const body = input as Record<string, unknown>
  if (typeof body.operation_id !== 'string' || !UUID_RE.test(body.operation_id)) return null
  if (typeof body.request_hash !== 'string' || body.request_hash.length === 0) return null
  if (typeof body.control_key !== 'string' || body.control_key.length === 0) return null
  if (body.kind !== 'quota' && body.kind !== 'rate_limit') return null
  if (typeof body.delta !== 'number' || !Number.isSafeInteger(body.delta) || body.delta === 0) return null
  if (typeof body.window_start !== 'number' || !Number.isSafeInteger(body.window_start) || body.window_start < 0) {
    return null
  }
  if (body.window_end !== null) {
    if (typeof body.window_end !== 'number' || !Number.isSafeInteger(body.window_end)) return null
  }
  if (typeof body.now_ms !== 'number' || !Number.isFinite(body.now_ms)) return null

  return {
    operation_id: body.operation_id,
    request_hash: body.request_hash,
    control_key: body.control_key,
    kind: body.kind,
    delta: body.delta,
    window_start: body.window_start,
    window_end: body.window_end as number | null,
    now_ms: body.now_ms,
  }
}

export function utcMidnightMs(nowMs: number): number {
  const date = new Date(nowMs)
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate())
}

export function nextUtcMidnightMs(nowMs: number): number {
  return utcMidnightMs(nowMs) + 24 * 60 * 60 * 1000
}

export function computeResetAt(rule: LedgerRule | LedgerStatusRule, nowMs: number): string | null {
  if (rule.kind === 'rate_limit' && rule.window_end !== null) {
    return new Date(rule.window_end).toISOString()
  }
  if (rule.kind === 'quota' && rule.window_start > 0 && rule.window_end === null) {
    return new Date(nextUtcMidnightMs(nowMs)).toISOString()
  }
  return null
}

export function buildLimit(
  rule: LedgerRule | LedgerStatusRule,
  used: number,
  nowMs: number
): LedgerResponse['limits'][number] {
  const remaining = Math.max(0, rule.limit - used)
  return {
    control_key: rule.control_key,
    limit: rule.limit,
    used,
    remaining,
    reset_at: computeResetAt(rule, nowMs),
  }
}

export interface CounterStore {
  getUsed(controlKey: string, windowStart: number): number
  setUsed(controlKey: string, windowStart: number, used: number, updatedAt: number): void
}

export interface OperationStore {
  find(operationId: string): { request_hash: string; response_json: string } | null
  insert(
    operationId: string,
    requestHash: string,
    responseJson: string,
    createdAt: number,
    expiresAt: number
  ): void
}

export function processConsume(
  request: LedgerRequest,
  counters: CounterStore,
  operations: OperationStore,
  serverNowMs: number
): LedgerResponse | { conflict: true } {
  const existing = operations.find(request.operation_id)
  if (existing) {
    if (existing.request_hash !== request.request_hash) {
      return { conflict: true }
    }
    const stored = JSON.parse(existing.response_json) as LedgerResponse
    return { ...stored, replayed: true }
  }

  const usedByRule = request.rules.map((rule) => ({
    rule,
    used: counters.getUsed(rule.control_key, rule.window_start),
  }))

  for (const { rule, used } of usedByRule) {
    if (used + rule.amount > rule.limit) {
      const reason = rule.kind === 'quota' ? 'quota_exhausted' : 'rate_limited'
      const response: LedgerResponse = {
        allowed: false,
        reason,
        replayed: false,
        operation_id: request.operation_id,
        policy_key: request.policy_key,
        limits: usedByRule.map(({ rule: currentRule, used: currentUsed }) =>
          buildLimit(currentRule, currentUsed, request.now_ms)
        ),
      }
      operations.insert(
        request.operation_id,
        request.request_hash,
        JSON.stringify(response),
        serverNowMs,
        serverNowMs + OPERATION_TTL_MS
      )
      return response
    }
  }

  for (const { rule, used } of usedByRule) {
    counters.setUsed(rule.control_key, rule.window_start, used + rule.amount, serverNowMs)
  }

  const response: LedgerResponse = {
    allowed: true,
    reason: 'allowed',
    replayed: false,
    operation_id: request.operation_id,
    policy_key: request.policy_key,
    limits: usedByRule.map(({ rule, used }) =>
      buildLimit(rule, used + rule.amount, request.now_ms)
    ),
  }

  operations.insert(
    request.operation_id,
    request.request_hash,
    JSON.stringify(response),
    serverNowMs,
    serverNowMs + OPERATION_TTL_MS
  )

  return response
}

export function processStatus(
  request: LedgerStatusRequest,
  counters: CounterStore
): LedgerStatusResponse {
  return {
    limits: request.rules.map((rule) =>
      buildLimit(rule, counters.getUsed(rule.control_key, rule.window_start), request.now_ms)
    ),
  }
}

export function processAdjust(
  request: LedgerAdjustmentRequest,
  counters: CounterStore,
  operations: OperationStore,
  serverNowMs: number
): LedgerAdjustmentResponse | { conflict: true } {
  const existing = operations.find(request.operation_id)
  if (existing) {
    if (existing.request_hash !== request.request_hash) {
      return { conflict: true }
    }
    const stored = JSON.parse(existing.response_json) as LedgerAdjustmentResponse
    return { ...stored, replayed: true }
  }

  const previousUsed = counters.getUsed(request.control_key, request.window_start)
  const used = Math.max(0, previousUsed + request.delta)
  counters.setUsed(request.control_key, request.window_start, used, serverNowMs)

  const response: LedgerAdjustmentResponse = {
    operation_id: request.operation_id,
    replayed: false,
    previous_used: previousUsed,
    used,
    delta: request.delta,
  }

  operations.insert(
    request.operation_id,
    request.request_hash,
    JSON.stringify(response),
    serverNowMs,
    serverNowMs + OPERATION_TTL_MS
  )

  return response
}
