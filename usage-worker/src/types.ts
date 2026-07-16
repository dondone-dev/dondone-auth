export interface LedgerRule {
  control_key: string
  kind: 'quota' | 'rate_limit'
  limit: number
  amount: number
  window_start: number
  window_end: number | null
}

export type LedgerStatusRule = Omit<LedgerRule, 'amount'>

export interface LedgerRequest {
  operation_id: string
  request_hash: string
  policy_key: string
  rules: LedgerRule[]
  now_ms: number
}

export interface LedgerResponse {
  allowed: boolean
  reason: 'allowed' | 'quota_exhausted' | 'rate_limited'
  replayed: boolean
  operation_id: string
  policy_key: string
  limits: Array<{
    control_key: string
    limit: number
    used: number
    remaining: number
    reset_at: string | null
  }>
}

export interface LedgerAdjustmentRequest {
  operation_id: string
  request_hash: string
  control_key: string
  kind: 'quota' | 'rate_limit'
  delta: number
  window_start: number
  window_end: number | null
  now_ms: number
}

export interface LedgerAdjustmentResponse {
  operation_id: string
  replayed: boolean
  previous_used: number
  used: number
  delta: number
}

export interface LedgerStatusRequest {
  rules: LedgerStatusRule[]
  now_ms: number
}

export interface LedgerStatusResponse {
  limits: Array<{
    control_key: string
    limit: number
    used: number
    remaining: number
    reset_at: string | null
  }>
}
