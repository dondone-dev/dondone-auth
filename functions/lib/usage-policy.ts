import { ApiError } from './errors'
import type { ResolvedUsageControl } from './usage-store'

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

const COUNTER_KINDS = new Set(['quota', 'rate_limit'])
const CONSTRAINT_KINDS = new Set(['enum_one', 'enum_many', 'boolean', 'numeric_ceiling'])

export interface CheckAndConsumeRequest {
  service_key: string
  permission_key: string
  operation_id: string
  consume: Record<string, number>
  context?: Record<string, string | number | boolean | string[]>
}

export interface UsageStatusRequest {
  service_key: string
  permission_key: string
  context?: Record<string, string | number | boolean | string[]>
}

export interface AdjustUsageRequest {
  operation_id: string
  user_id: string
  service_key: string
  permission_key: string
  control_key: string
  delta: number
  reason: string
}

export interface CheckAndConsumeResponse {
  allowed: boolean
  reason:
    | 'allowed'
    | 'access_not_granted'
    | 'user_disabled'
    | 'service_disabled'
    | 'group_disabled'
    | 'membership_expired'
    | 'permission_denied'
    | 'usage_policy_not_configured'
    | 'constraint_denied'
    | 'quota_exhausted'
    | 'rate_limited'
  operation_id: string
  replayed: boolean
  policy_key: string | null
  limits: Array<{
    control_key: string
    limit: number
    used: number
    remaining: number
    reset_at: string | null
  }>
}

export interface UsageStatusResponse {
  allowed: boolean
  reason: Exclude<CheckAndConsumeResponse['reason'], 'quota_exhausted' | 'rate_limited'>
  policy_key: string | null
  limits: CheckAndConsumeResponse['limits']
  constraints: Array<{
    control_key: string
    kind: 'enum_one' | 'enum_many' | 'boolean' | 'numeric_ceiling'
    value: string | string[] | boolean | number
  }>
}

export type UsageAccessReason = Exclude<
  CheckAndConsumeResponse['reason'],
  'quota_exhausted' | 'rate_limited' | 'allowed'
>

export interface LedgerRule {
  control_key: string
  kind: 'quota' | 'rate_limit'
  limit: number
  amount: number
  window_start: number
  window_end: number | null
}

export type LedgerStatusRule = Omit<LedgerRule, 'amount'>

function parseNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new ApiError(400, 'invalid_request', `${field} must be a non-empty string.`)
  }
  return value.trim()
}

function parseContext(
  value: unknown
): Record<string, string | number | boolean | string[]> | undefined {
  if (value === undefined) return undefined
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiError(400, 'invalid_request', 'context must be a JSON object.')
  }

  const result: Record<string, string | number | boolean | string[]> = {}
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (typeof key !== 'string' || key.trim() === '') {
      throw new ApiError(400, 'invalid_request', 'context keys must be non-empty strings.')
    }
    if (
      typeof entry === 'string' ||
      typeof entry === 'boolean' ||
      (typeof entry === 'number' && Number.isFinite(entry))
    ) {
      result[key] = entry
      continue
    }
    if (Array.isArray(entry) && entry.every((item) => typeof item === 'string')) {
      result[key] = entry
      continue
    }
    throw new ApiError(
      400,
      'invalid_request',
      `context value for "${key}" must be a string, number, boolean, or string array.`
    )
  }
  return result
}

function parseConsume(value: unknown): Record<string, number> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiError(400, 'invalid_request', 'consume must be a JSON object.')
  }

  const result: Record<string, number> = {}
  for (const [key, amount] of Object.entries(value as Record<string, unknown>)) {
    if (typeof key !== 'string' || key.trim() === '') {
      throw new ApiError(400, 'invalid_request', 'consume keys must be non-empty strings.')
    }
    if (typeof amount !== 'number' || !Number.isSafeInteger(amount) || amount <= 0) {
      throw new ApiError(
        400,
        'invalid_request',
        `consume value for "${key}" must be a positive safe integer.`
      )
    }
    result[key] = amount
  }
  return result
}

function parseRequestObject(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new ApiError(400, 'invalid_request', 'Request body must be a JSON object.')
  }
  return input as Record<string, unknown>
}

export function parseCheckAndConsumeRequest(input: unknown): CheckAndConsumeRequest {
  const body = parseRequestObject(input)
  const operationId = parseNonEmptyString(body.operation_id, 'operation_id')
  if (!UUID_RE.test(operationId)) {
    throw new ApiError(400, 'invalid_request', 'operation_id must be a UUID.')
  }

  return {
    service_key: parseNonEmptyString(body.service_key, 'service_key'),
    permission_key: parseNonEmptyString(body.permission_key, 'permission_key'),
    operation_id: operationId,
    consume: parseConsume(body.consume ?? {}),
    context: parseContext(body.context),
  }
}

export function parseUsageStatusRequest(input: unknown): UsageStatusRequest {
  const body = parseRequestObject(input)
  return {
    service_key: parseNonEmptyString(body.service_key, 'service_key'),
    permission_key: parseNonEmptyString(body.permission_key, 'permission_key'),
    context: parseContext(body.context),
  }
}

export function parseAdjustUsageRequest(input: unknown): AdjustUsageRequest {
  const body = parseRequestObject(input)
  const operationId = parseNonEmptyString(body.operation_id, 'operation_id')
  if (!UUID_RE.test(operationId)) {
    throw new ApiError(400, 'invalid_request', 'operation_id must be a UUID.')
  }
  const userId = parseNonEmptyString(body.user_id, 'user_id')
  if (!UUID_RE.test(userId)) {
    throw new ApiError(400, 'invalid_request', 'user_id must be a UUID.')
  }
  const delta = body.delta
  if (typeof delta !== 'number' || !Number.isSafeInteger(delta) || delta === 0) {
    throw new ApiError(400, 'invalid_request', 'delta must be a non-zero safe integer.')
  }

  return {
    operation_id: operationId,
    user_id: userId,
    service_key: parseNonEmptyString(body.service_key, 'service_key'),
    permission_key: parseNonEmptyString(body.permission_key, 'permission_key'),
    control_key: parseNonEmptyString(body.control_key, 'control_key'),
    delta,
    reason: parseNonEmptyString(body.reason, 'reason'),
  }
}

export function evaluateConstraints(
  controls: ResolvedUsageControl[],
  context: CheckAndConsumeRequest['context']
): { allowed: true } | { allowed: false; controlKey: string } {
  for (const control of controls) {
    if (!CONSTRAINT_KINDS.has(control.kind)) continue

    const contextValue = context?.[control.key]
    switch (control.kind) {
      case 'enum_one': {
        if (typeof contextValue !== 'string' || contextValue !== control.value) {
          return { allowed: false, controlKey: control.key }
        }
        break
      }
      case 'enum_many': {
        if (!Array.isArray(contextValue) || !Array.isArray(control.value)) {
          return { allowed: false, controlKey: control.key }
        }
        const allowed = new Set(control.value as string[])
        if (contextValue.some((value) => !allowed.has(value))) {
          return { allowed: false, controlKey: control.key }
        }
        break
      }
      case 'boolean': {
        if (control.value !== true || contextValue !== true) {
          return { allowed: false, controlKey: control.key }
        }
        break
      }
      case 'numeric_ceiling': {
        if (typeof contextValue !== 'number' || typeof control.value !== 'number') {
          return { allowed: false, controlKey: control.key }
        }
        if (contextValue > control.value) {
          return { allowed: false, controlKey: control.key }
        }
        break
      }
    }
  }
  return { allowed: true }
}

export function utcMidnightMs(nowMs: number): number {
  const date = new Date(nowMs)
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate())
}

export function nextUtcMidnightMs(nowMs: number): number {
  const midnight = utcMidnightMs(nowMs)
  return midnight + 24 * 60 * 60 * 1000
}

export function computeCounterWindow(
  control: ResolvedUsageControl,
  nowMs: number
): { window_start: number; window_end: number | null } {
  if (control.kind === 'quota') {
    if (control.window === 'calendar_day') {
      return { window_start: utcMidnightMs(nowMs), window_end: null }
    }
    if (control.window === 'lifetime') {
      return { window_start: 0, window_end: null }
    }
    throw new Error(`unsupported quota window: ${String(control.window)}`)
  }

  if (control.kind === 'rate_limit') {
    const windowSeconds = control.window_seconds
    if (typeof windowSeconds !== 'number' || windowSeconds <= 0) {
      throw new Error(`invalid rate_limit window_seconds for control ${control.key}`)
    }
    const windowMs = windowSeconds * 1000
    const windowStart = Math.floor(nowMs / windowMs) * windowMs
    return { window_start: windowStart, window_end: windowStart + windowMs }
  }

  throw new Error(`unsupported counter kind: ${control.kind}`)
}

function parseControlLimit(control: ResolvedUsageControl): number {
  if (typeof control.value !== 'number' || !Number.isSafeInteger(control.value) || control.value < 0) {
    throw new Error(`invalid limit for control ${control.key}`)
  }
  return control.value
}

export function resolveCounterRules(
  controls: ResolvedUsageControl[],
  consume: Record<string, number>,
  nowMs: number
): LedgerRule[] {
  const controlByKey = new Map(controls.filter((c) => COUNTER_KINDS.has(c.kind)).map((c) => [c.key, c]))
  const rules: LedgerRule[] = []

  for (const [controlKey, amount] of Object.entries(consume)) {
    const control = controlByKey.get(controlKey)
    if (!control) {
      throw new ApiError(400, 'invalid_request', `Unknown counter control "${controlKey}".`)
    }
    const { window_start, window_end } = computeCounterWindow(control, nowMs)
    rules.push({
      control_key: controlKey,
      kind: control.kind as 'quota' | 'rate_limit',
      limit: parseControlLimit(control),
      amount,
      window_start,
      window_end,
    })
  }

  return rules
}

export function resolveStatusCounterRules(
  controls: ResolvedUsageControl[],
  nowMs: number
): LedgerStatusRule[] {
  return controls
    .filter((control) => COUNTER_KINDS.has(control.kind))
    .map((control) => {
      const { window_start, window_end } = computeCounterWindow(control, nowMs)
      return {
        control_key: control.key,
        kind: control.kind as 'quota' | 'rate_limit',
        limit: parseControlLimit(control),
        window_start,
        window_end,
      }
    })
}

export function buildStatusConstraints(
  controls: ResolvedUsageControl[]
): UsageStatusResponse['constraints'] {
  return controls
    .filter((control) => CONSTRAINT_KINDS.has(control.kind))
    .map((control) => ({
      control_key: control.key,
      kind: control.kind as UsageStatusResponse['constraints'][number]['kind'],
      value: control.value as string | string[] | boolean | number,
    }))
}

export function computeResetAt(
  rule: Pick<LedgerRule, 'kind' | 'window_start' | 'window_end'>,
  nowMs: number,
  control?: ResolvedUsageControl
): string | null {
  if (rule.kind === 'rate_limit' && rule.window_end !== null) {
    return new Date(rule.window_end).toISOString()
  }
  if (rule.kind === 'quota' && control?.window === 'calendar_day') {
    return new Date(nextUtcMidnightMs(nowMs)).toISOString()
  }
  return null
}

export function emptyLimits(): CheckAndConsumeResponse['limits'] {
  return []
}

export function deniedResponse(
  reason: CheckAndConsumeResponse['reason'],
  operationId: string,
  policyKey: string | null
): CheckAndConsumeResponse {
  return {
    allowed: false,
    reason,
    operation_id: operationId,
    replayed: false,
    policy_key: policyKey,
    limits: emptyLimits(),
  }
}

export function allowedResponse(
  operationId: string,
  policyKey: string | null,
  limits: CheckAndConsumeResponse['limits'] = emptyLimits(),
  replayed = false
): CheckAndConsumeResponse {
  return {
    allowed: true,
    reason: 'allowed',
    operation_id: operationId,
    replayed,
    policy_key: policyKey,
    limits,
  }
}

export function isMembershipExpired(expiresAt: string | null, nowMs: number): boolean {
  if (!expiresAt) return false
  return Date.parse(expiresAt) <= nowMs
}

export function hasCounterControls(controls: ResolvedUsageControl[]): boolean {
  return controls.some((control) => COUNTER_KINDS.has(control.kind))
}

export function hasConstraintControls(controls: ResolvedUsageControl[]): boolean {
  return controls.some((control) => CONSTRAINT_KINDS.has(control.kind))
}

export function validateConsumeCompleteness(
  controls: ResolvedUsageControl[],
  consume: Record<string, number>
): void {
  const requiredKeys = controls
    .filter((c) => c.kind === 'quota' || c.kind === 'rate_limit')
    .map((c) => c.key)
  const missing = requiredKeys.filter((key) => !(key in consume))
  if (missing.length > 0) {
    throw new ApiError(
      400,
      'invalid_request',
      `Missing required consume keys: ${missing.join(', ')}.`
    )
  }
}
