import { afterEach, describe, expect, it, vi } from 'vitest'
import { SignJWT } from 'jose'
import { checkAndConsume, getUsageStatus } from './usage-api'
import type { AuthEnv } from './types'
import type { UsageDecisionContext } from './usage-store'

const operationId = '11111111-1111-4111-8111-111111111111'

async function makeEnvAndToken(
  userId = 'user-123',
  options: { audience?: string; scope?: string } = {}
): Promise<{ env: AuthEnv; token: string }> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
  const env = {
    DONDONE_JWT_PRIVATE_JWK: JSON.stringify(privateJwk),
    DONDONE_JWT_ISSUER: 'https://auth.dondone.dev',
    DONDONE_JWT_KID: 'test-kid',
    SUPABASE_URL: 'https://project.supabase.co',
    SUPABASE_SERVICE_ROLE_KEY: 'service-role',
  } as AuthEnv

  const jwt = await new SignJWT({ scope: options.scope ?? 'api:echo' })
    .setProtectedHeader({ alg: 'ES256', kid: 'test-kid', typ: 'at+jwt' })
    .setIssuer(env.DONDONE_JWT_ISSUER)
    .setAudience(options.audience ?? 'https://api.dondone.dev')
    .setSubject(userId)
    .setExpirationTime('15m')
    .sign(keyPair.privateKey)

  return { env, token: jwt }
}

function activeContext(overrides: Partial<UsageDecisionContext> = {}): UsageDecisionContext {
  return {
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
    ...overrides,
  }
}

function activeTarget(overrides: Record<string, unknown> = {}) {
  return {
    service_key: 'api',
    service_status: 'active',
    resource_uri: 'https://api.dondone.dev',
    permission_key: 'api:echo',
    permission_oauth_scope: true,
    permission_control_count: 0,
    ...overrides,
  }
}

describe('checkAndConsume', () => {
  afterEach(() => vi.restoreAllMocks())

  it('denies when service is disabled', async () => {
    const { env, token } = await makeEnvAndToken()
    const result = await checkAndConsume(
      token,
      {
        service_key: 'api',
        permission_key: 'api:echo',
        operation_id: operationId,
        consume: {},
      },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue(activeTarget()),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(
          activeContext({ service_status: 'disabled' })
        ),
        consumeWithLedger: vi.fn(),
        statusWithLedger: vi.fn(),
      }
    )

    expect(result).toMatchObject({
      allowed: false,
      reason: 'service_disabled',
      operation_id: operationId,
    })
  })

  it('denies when permission is not granted', async () => {
    const { env, token } = await makeEnvAndToken()
    const result = await checkAndConsume(
      token,
      {
        service_key: 'api',
        permission_key: 'api:echo',
        operation_id: operationId,
        consume: {},
      },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue(activeTarget()),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(
          activeContext({ permission_granted: false })
        ),
        consumeWithLedger: vi.fn(),
        statusWithLedger: vi.fn(),
      }
    )

    expect(result.reason).toBe('permission_denied')
  })

  it('allows when there are no controls', async () => {
    const { env, token } = await makeEnvAndToken()
    const result = await checkAndConsume(
      token,
      {
        service_key: 'api',
        permission_key: 'api:echo',
        operation_id: operationId,
        consume: {},
      },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue(activeTarget()),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(
          activeContext({ policy_id: null, policy_key: null, policy_status: null })
        ),
        consumeWithLedger: vi.fn(),
        statusWithLedger: vi.fn(),
      }
    )

    expect(result).toMatchObject({ allowed: true, reason: 'allowed', policy_key: null })
  })

  it('denies constraint violations', async () => {
    const { env, token } = await makeEnvAndToken()
    const result = await checkAndConsume(
      token,
      {
        service_key: 'api',
        permission_key: 'api:echo',
        operation_id: operationId,
        consume: {},
        context: { tier: 'free' },
      },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue(
          activeTarget({ permission_control_count: 1 })
        ),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(
          activeContext({
            controls: [
              { key: 'tier', kind: 'enum_one', value: 'pro', has_rule: true },
            ],
          })
        ),
        consumeWithLedger: vi.fn(),
        statusWithLedger: vi.fn(),
      }
    )

    expect(result.reason).toBe('constraint_denied')
  })

  it('returns quota_exhausted from ledger', async () => {
    const { env, token } = await makeEnvAndToken()
    const result = await checkAndConsume(
      token,
      {
        service_key: 'api',
        permission_key: 'api:echo',
        operation_id: operationId,
        consume: { daily: 1 },
      },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue(
          activeTarget({ permission_control_count: 1 })
        ),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(
          activeContext({
            controls: [
              { key: 'daily', kind: 'quota', window: 'calendar_day', value: 1, has_rule: true },
            ],
          })
        ),
        consumeWithLedger: vi.fn().mockResolvedValue({
          allowed: false,
          reason: 'quota_exhausted',
          replayed: false,
          operation_id: operationId,
          policy_key: 'basic',
          limits: [{ control_key: 'daily', limit: 1, used: 1, remaining: 0, reset_at: null }],
        }),
        statusWithLedger: vi.fn(),
      }
    )

    expect(result.reason).toBe('quota_exhausted')
    expect(result.allowed).toBe(false)
  })

  it('rejects invalid tokens', async () => {
    const { env } = await makeEnvAndToken()
    await expect(
      checkAndConsume(
        'invalid.token.value',
        {
          service_key: 'api',
          permission_key: 'api:echo',
          operation_id: operationId,
          consume: {},
        },
        env
      )
    ).rejects.toMatchObject({ status: 401, error: 'invalid_token' })
  })

  it('rejects a token audience that does not own the requested Service before assigning a default Group', async () => {
    const { env, token } = await makeEnvAndToken('user-123', {
      audience: 'https://time.dondone.dev',
    })
    const ensureDefaultGroup = vi.fn()

    await expect(
      checkAndConsume(
        token,
        {
          service_key: 'api',
          permission_key: 'api:echo',
          operation_id: operationId,
          consume: {},
        },
        env,
        {
          loadUsageTargetContext: vi.fn().mockResolvedValue({
            service_key: 'api',
            service_status: 'active',
            resource_uri: 'https://api.dondone.dev',
            permission_key: 'api:echo',
            permission_oauth_scope: true,
          }),
          ensureDefaultGroup,
          loadUsageDecisionContext: vi.fn(),
          consumeWithLedger: vi.fn(),
          statusWithLedger: vi.fn(),
        }
      )
    ).rejects.toMatchObject({ status: 422, error: 'service_mismatch' })
    expect(ensureDefaultGroup).not.toHaveBeenCalled()
  })

  it('does not require a JWT scope for a non-OAuth Permission', async () => {
    const { env, token } = await makeEnvAndToken('user-123', { scope: '' })

    const result = await checkAndConsume(
      token,
      {
        service_key: 'api',
        permission_key: 'api:internal',
        operation_id: operationId,
        consume: {},
      },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue({
          service_key: 'api',
          service_status: 'active',
          resource_uri: 'https://api.dondone.dev',
          permission_key: 'api:internal',
          permission_oauth_scope: false,
          permission_control_count: 0,
        }),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(
          activeContext({ policy_id: null, policy_key: null, policy_status: null })
        ),
        consumeWithLedger: vi.fn(),
        statusWithLedger: vi.fn(),
      }
    )

    expect(result).toMatchObject({ allowed: true, reason: 'allowed' })
  })

  it('fails closed when the active Permission declares controls but the Group has no policy', async () => {
    const { env, token } = await makeEnvAndToken()
    const result = await checkAndConsume(
      token,
      {
        service_key: 'api',
        permission_key: 'api:echo',
        operation_id: operationId,
        consume: { daily_calls: 1 },
      },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue(
          activeTarget({ permission_control_count: 1 })
        ),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(
          activeContext({ policy_id: null, policy_key: null, policy_status: null, controls: [] })
        ),
        consumeWithLedger: vi.fn(),
        statusWithLedger: vi.fn(),
      }
    )

    expect(result).toMatchObject({
      allowed: false,
      reason: 'usage_policy_not_configured',
    })
  })

  it('allows an uncontrolled Permission even when its Group binds a policy for another Permission', async () => {
    const { env, token } = await makeEnvAndToken()
    const result = await checkAndConsume(
      token,
      {
        service_key: 'api',
        permission_key: 'api:echo',
        operation_id: operationId,
        consume: {},
      },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue(activeTarget()),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(activeContext({ controls: [] })),
        consumeWithLedger: vi.fn(),
        statusWithLedger: vi.fn(),
      }
    )

    expect(result).toMatchObject({ allowed: true, reason: 'allowed' })
  })
})

describe('getUsageStatus', () => {
  it('returns constraints and limits when allowed', async () => {
    const { env, token } = await makeEnvAndToken()
    const result = await getUsageStatus(
      token,
      { service_key: 'api', permission_key: 'api:echo', context: { tier: 'pro' } },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue(
          activeTarget({ permission_control_count: 2 })
        ),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(
          activeContext({
            controls: [
              { key: 'tier', kind: 'enum_one', value: 'pro', has_rule: true },
              { key: 'daily', kind: 'quota', window: 'calendar_day', value: 5, has_rule: true },
            ],
          })
        ),
        consumeWithLedger: vi.fn(),
        statusWithLedger: vi.fn().mockResolvedValue({
          limits: [{ control_key: 'daily', limit: 5, used: 2, remaining: 3, reset_at: null }],
        }),
      }
    )

    expect(result.allowed).toBe(true)
    expect(result.constraints).toHaveLength(1)
    expect(result.limits).toHaveLength(1)
  })

  it('denies membership expiry without counter reasons', async () => {
    const { env, token } = await makeEnvAndToken()
    const result = await getUsageStatus(
      token,
      { service_key: 'api', permission_key: 'api:echo' },
      env,
      {
        loadUsageTargetContext: vi.fn().mockResolvedValue(activeTarget()),
        ensureDefaultGroup: vi.fn(),
        loadUsageDecisionContext: vi.fn().mockResolvedValue(
          activeContext({
            membership_expires_at: '2020-01-01T00:00:00.000Z',
          })
        ),
        consumeWithLedger: vi.fn(),
        statusWithLedger: vi.fn(),
      }
    )

    expect(result.reason).toBe('membership_expired')
  })
})
