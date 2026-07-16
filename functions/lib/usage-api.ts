import { importJWK, jwtVerify, type JWK } from 'jose'
import { ApiError } from './errors'
import type { AuthEnv } from './types'
import { hashRequest } from './usage-hash'
import {
  consumeWithLedger,
  statusWithLedger,
} from './usage-ledger-client'
import {
  allowedResponse,
  buildStatusConstraints,
  deniedResponse,
  evaluateConstraints,
  hasCounterControls,
  hasConstraintControls,
  isMembershipExpired,
  parseCheckAndConsumeRequest,
  parseUsageStatusRequest,
  resolveCounterRules,
  resolveStatusCounterRules,
  validateConsumeCompleteness,
  type CheckAndConsumeResponse,
  type UsageAccessReason,
  type UsageStatusResponse,
} from './usage-policy'
import {
  ensureDefaultGroup,
  loadUsageTargetContext,
  loadUsageDecisionContext,
  type UsageDecisionContext,
  type UsageTargetContext,
} from './usage-store'

export interface UsageApiDeps {
  loadUsageTargetContext: typeof loadUsageTargetContext
  ensureDefaultGroup: typeof ensureDefaultGroup
  loadUsageDecisionContext: typeof loadUsageDecisionContext
  consumeWithLedger: typeof consumeWithLedger
  statusWithLedger: typeof statusWithLedger
}

const defaultDeps: UsageApiDeps = {
  loadUsageTargetContext,
  ensureDefaultGroup,
  loadUsageDecisionContext,
  consumeWithLedger,
  statusWithLedger,
}

function validateUsageTarget(
  target: UsageTargetContext | null,
  audience: string,
  serviceKey: string,
  permissionKey: string,
  scopes: string[]
): asserts target is UsageTargetContext {
  if (
    !target ||
    target.service_key !== serviceKey ||
    target.resource_uri !== audience ||
    target.permission_key !== permissionKey
  ) {
    throw new ApiError(
      422,
      'service_mismatch',
      'JWT audience, Service, and Permission do not belong to the same active resource.'
    )
  }

  if (target.permission_oauth_scope === true && !scopes.includes(permissionKey)) {
    throw new ApiError(403, 'insufficient_scope', `Token lacks scope "${permissionKey}".`)
  }
}

export async function verifyUsageToken(
  token: string,
  env: AuthEnv
): Promise<{ userId: string; scopes: string[]; audience: string }> {
  let privateJwk: JWK
  try {
    privateJwk = JSON.parse(env.DONDONE_JWT_PRIVATE_JWK) as JWK
  } catch {
    throw new ApiError(500, 'invalid_jwt_key', 'Dondone JWT private key is invalid.')
  }

  const publicJwk: JWK = {
    kty: privateJwk.kty,
    crv: privateJwk.crv,
    x: privateJwk.x,
    y: privateJwk.y,
    kid: privateJwk.kid,
  }

  try {
    const key = await importJWK(publicJwk, 'ES256')
    const { payload, protectedHeader } = await jwtVerify(token, key, {
      issuer: env.DONDONE_JWT_ISSUER,
    })

    if (protectedHeader.alg !== 'ES256') {
      throw new Error('invalid algorithm')
    }
    if (protectedHeader.typ !== 'at+jwt') {
      throw new Error('invalid token type')
    }
    if (!protectedHeader.kid) {
      throw new Error('missing kid')
    }
    if (typeof payload.aud !== 'string') {
      throw new Error('audience must be single string')
    }
    if (typeof payload.sub !== 'string') {
      throw new Error('missing subject')
    }

    const scopes =
      typeof payload.scope === 'string' ? payload.scope.split(' ').filter(Boolean) : []
    return { userId: payload.sub, scopes, audience: payload.aud as string }
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw new ApiError(401, 'invalid_token', 'Access token is invalid or expired.')
  }
}

function evaluateAccess(
  ctx: UsageDecisionContext,
  nowMs: number
): UsageAccessReason | null {
  if (!ctx.service_status) return 'service_disabled'
  if (ctx.service_status !== 'active') return 'service_disabled'
  if (!ctx.profile_status) return 'user_disabled'
  if (ctx.profile_status !== 'active') return 'user_disabled'
  if (!ctx.group_id) return 'access_not_granted'
  if (ctx.group_status !== 'active') return 'group_disabled'
  if (isMembershipExpired(ctx.membership_expires_at, nowMs)) return 'membership_expired'
  if (!ctx.permission_granted) return 'permission_denied'
  return null
}

function evaluatePolicy(
  ctx: UsageDecisionContext
): UsageAccessReason | null {
  if (!ctx.policy_id || !ctx.policy_key) return 'usage_policy_not_configured'
  if (ctx.policy_status !== 'active') return 'usage_policy_not_configured'
  return null
}

export async function checkAndConsume(
  token: string,
  input: unknown,
  env: AuthEnv,
  deps: Partial<UsageApiDeps> = {}
): Promise<CheckAndConsumeResponse> {
  const resolvedDeps = { ...defaultDeps, ...deps }
  const { userId, scopes, audience } = await verifyUsageToken(token, env)
  const request = parseCheckAndConsumeRequest(input)

  const nowMs = Date.now()

  try {
    const target = await resolvedDeps.loadUsageTargetContext(
      env,
      request.service_key,
      request.permission_key
    )
    validateUsageTarget(target, audience, request.service_key, request.permission_key, scopes)
    await resolvedDeps.ensureDefaultGroup(env, userId, request.service_key)
    const ctx = await resolvedDeps.loadUsageDecisionContext(
      env,
      userId,
      request.service_key,
      request.permission_key
    )

    const accessReason = evaluateAccess(ctx, nowMs)
    if (accessReason) {
      return deniedResponse(accessReason, request.operation_id, ctx.policy_key)
    }

    if (target.permission_control_count === 0) {
      return allowedResponse(request.operation_id, ctx.policy_key)
    }

    const policyReason = evaluatePolicy(ctx)
    if (policyReason) {
      return deniedResponse(policyReason, request.operation_id, ctx.policy_key)
    }

    const missingRules = ctx.controls.filter((c) => c.has_rule === false)
    if (
      ctx.controls.length !== target.permission_control_count ||
      missingRules.length > 0
    ) {
      return deniedResponse(
        'usage_policy_not_configured',
        request.operation_id,
        ctx.policy_key
      )
    }

    if (hasConstraintControls(ctx.controls)) {
      const constraintResult = evaluateConstraints(ctx.controls, request.context)
      if (!constraintResult.allowed) {
        return deniedResponse('constraint_denied', request.operation_id, ctx.policy_key)
      }
    }

    if (hasCounterControls(ctx.controls)) {
      validateConsumeCompleteness(ctx.controls, request.consume)
      const rules = resolveCounterRules(ctx.controls, request.consume, nowMs)
      const requestHash = await hashRequest({
        operation_id: request.operation_id,
        policy_key: ctx.policy_key,
        rules: rules.map((r) => ({
          control_key: r.control_key,
          kind: r.kind,
          limit: r.limit,
          amount: r.amount,
        })),
      })

      const ledger = await resolvedDeps.consumeWithLedger(env, userId, request.service_key, {
        operation_id: request.operation_id,
        request_hash: requestHash,
        policy_key: ctx.policy_key!,
        rules,
        now_ms: nowMs,
      })

      if (!ledger.allowed) {
        return {
          allowed: false,
          reason: ledger.reason,
          operation_id: request.operation_id,
          replayed: ledger.replayed,
          policy_key: ctx.policy_key,
          limits: ledger.limits,
        }
      }

      return allowedResponse(request.operation_id, ctx.policy_key, ledger.limits, ledger.replayed)
    }

    return allowedResponse(request.operation_id, ctx.policy_key)
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw new ApiError(503, 'usage_service_unavailable', 'Usage service is temporarily unavailable.')
  }
}

export async function getUsageStatus(
  token: string,
  input: unknown,
  env: AuthEnv,
  deps: Partial<UsageApiDeps> = {}
): Promise<UsageStatusResponse> {
  const resolvedDeps = { ...defaultDeps, ...deps }
  const { userId, scopes, audience } = await verifyUsageToken(token, env)
  const request = parseUsageStatusRequest(input)

  const nowMs = Date.now()

  try {
    const target = await resolvedDeps.loadUsageTargetContext(
      env,
      request.service_key,
      request.permission_key
    )
    validateUsageTarget(target, audience, request.service_key, request.permission_key, scopes)
    await resolvedDeps.ensureDefaultGroup(env, userId, request.service_key)
    const ctx = await resolvedDeps.loadUsageDecisionContext(
      env,
      userId,
      request.service_key,
      request.permission_key
    )

    const accessReason = evaluateAccess(ctx, nowMs)
    if (accessReason) {
      return {
        allowed: false,
        reason: accessReason,
        policy_key: ctx.policy_key,
        limits: [],
        constraints: [],
      }
    }

    if (target.permission_control_count === 0) {
      return {
        allowed: true,
        reason: 'allowed',
        policy_key: ctx.policy_key,
        limits: [],
        constraints: [],
      }
    }

    const policyReason = evaluatePolicy(ctx)
    if (policyReason) {
      return {
        allowed: false,
        reason: policyReason,
        policy_key: ctx.policy_key,
        limits: [],
        constraints: buildStatusConstraints(ctx.controls),
      }
    }

    const missingRules = ctx.controls.filter((c) => c.has_rule === false)
    if (
      ctx.controls.length !== target.permission_control_count ||
      missingRules.length > 0
    ) {
      return {
        allowed: false,
        reason: 'usage_policy_not_configured',
        policy_key: ctx.policy_key,
        limits: [],
        constraints: buildStatusConstraints(ctx.controls),
      }
    }

    if (hasConstraintControls(ctx.controls)) {
      const constraintResult = evaluateConstraints(ctx.controls, request.context)
      if (!constraintResult.allowed) {
        return {
          allowed: false,
          reason: 'constraint_denied',
          policy_key: ctx.policy_key,
          limits: [],
          constraints: buildStatusConstraints(ctx.controls),
        }
      }
    }

    const status = await resolvedDeps.statusWithLedger(env, userId, request.service_key, {
      rules: resolveStatusCounterRules(ctx.controls, nowMs),
      now_ms: nowMs,
    })

    return {
      allowed: true,
      reason: 'allowed',
      policy_key: ctx.policy_key,
      limits: status.limits,
      constraints: buildStatusConstraints(ctx.controls),
    }
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw new ApiError(503, 'usage_service_unavailable', 'Usage service is temporarily unavailable.')
  }
}
