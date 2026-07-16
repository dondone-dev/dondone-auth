import { createClient } from '@supabase/supabase-js'
import type { AuthEnv } from './types'

export interface UsageDecisionContext {
  service_status: string | null
  profile_status: string | null
  group_id: string | null
  group_key: string | null
  group_status: string | null
  membership_expires_at: string | null
  permission_granted: boolean
  policy_id: string | null
  policy_key: string | null
  policy_status: string | null
  controls: ResolvedUsageControl[]
}

export interface UsageTargetContext {
  service_key: string | null
  service_status: string | null
  resource_uri: string | null
  permission_key: string | null
  permission_oauth_scope: boolean | null
  permission_control_count: number | null
}

export interface ResolvedUsageControl {
  key: string
  kind: string
  unit?: string
  window?: string
  window_seconds?: number
  value: unknown
  has_rule?: boolean
}

export async function ensureDefaultGroup(
  env: AuthEnv,
  userId: string,
  serviceKey: string
): Promise<string | null> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })
  const { data, error } = await supabase.rpc('ensure_default_service_group', {
    p_user_id: userId,
    p_service_key: serviceKey,
  })
  if (error) throw new Error(`ensure_default_service_group failed: ${error.message}`)
  return data as string | null
}

export async function loadUsageTargetContext(
  env: AuthEnv,
  serviceKey: string,
  permissionKey: string
): Promise<UsageTargetContext | null> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })
  const { data, error } = await supabase.rpc('load_usage_target_context', {
    p_service_key: serviceKey,
    p_permission_key: permissionKey,
  })
  if (error) throw new Error(`load_usage_target_context failed: ${error.message}`)
  return data as UsageTargetContext | null
}

export async function loadUsageDecisionContext(
  env: AuthEnv,
  userId: string,
  serviceKey: string,
  permissionKey: string
): Promise<UsageDecisionContext> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })
  const { data, error } = await supabase.rpc('load_usage_decision_context', {
    p_user_id: userId,
    p_service_key: serviceKey,
    p_permission_key: permissionKey,
  })
  if (error) throw new Error(`load_usage_decision_context failed: ${error.message}`)
  return data as UsageDecisionContext
}

export interface UsageAdjustmentAuditInsert {
  operation_id: string
  actor: string
  user_id: string
  service_key: string
  permission_key: string
  control_key: string
  delta: number
  reason: string
}

export async function insertUsageAdjustmentAudit(
  env: AuthEnv,
  row: UsageAdjustmentAuditInsert
): Promise<void> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })
  const { error } = await supabase.from('usage_adjustment_audit').insert({
    ...row,
    status: 'pending',
  })
  if (error) throw new Error(`insert usage_adjustment_audit failed: ${error.message}`)
}

export async function updateUsageAdjustmentAudit(
  env: AuthEnv,
  operationId: string,
  status: 'applied' | 'failed',
  result: unknown
): Promise<void> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })
  const { error } = await supabase
    .from('usage_adjustment_audit')
    .update({ status, result })
    .eq('operation_id', operationId)
  if (error) throw new Error(`update usage_adjustment_audit failed: ${error.message}`)
}

export async function upsertUsageAdjustmentAudit(
  env: AuthEnv,
  row: UsageAdjustmentAuditInsert & {
    status: 'applied' | 'failed' | 'pending'
    result?: unknown
  }
): Promise<void> {
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  })
  const { error } = await supabase
    .from('usage_adjustment_audit')
    .upsert(row, { onConflict: 'operation_id', ignoreDuplicates: true })
  if (error) throw new Error(`upsert usage_adjustment_audit failed: ${error.message}`)
}
