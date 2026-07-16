import { describe, it, expect } from 'vitest'
import canonicalize from 'canonicalize'
import {
  capabilityMetadataUrl,
  parseCapabilityManifest,
  manifestSha256,
  isOAuthScope,
  parseUsageControls,
  type CapabilityManifest,
  type DondoneCapabilitiesV2,
} from './capability-manifest'

function validManifestInput() {
  return {
    resource: 'https://api.dondone.dev',
    resource_name: 'Dondone API',
    authorization_servers: ['https://auth.dondone.dev'],
    scopes_supported: ['api:echo', 'api:read'],
    dondone_capabilities: {
      schema_version: 1,
      catalog_version: '2026-07-14.1',
      permissions: [
        { key: 'api:echo', description: 'Call the echo API.' },
        { key: 'api:read', description: 'Read API data.' },
      ],
      roles: [
        { key: 'reader', name: 'Reader', permission_keys: ['api:read'] },
        {
          key: 'operator',
          name: 'Operator',
          description: 'Full access',
          permission_keys: ['api:echo', 'api:read'],
        },
      ],
    },
  }
}

// ---------- capabilityMetadataUrl ----------

describe('capabilityMetadataUrl', () => {
  it('derives well-known URL for root resource', () => {
    expect(capabilityMetadataUrl('https://api.dondone.dev')).toBe(
      'https://api.dondone.dev/.well-known/oauth-protected-resource'
    )
  })

  it('derives well-known URL with trailing slash', () => {
    expect(capabilityMetadataUrl('https://api.dondone.dev/')).toBe(
      'https://api.dondone.dev/.well-known/oauth-protected-resource'
    )
  })

  it('inserts well-known before path per RFC 9728', () => {
    expect(capabilityMetadataUrl('https://api.dondone.dev/v1')).toBe(
      'https://api.dondone.dev/.well-known/oauth-protected-resource/v1'
    )
  })

  it('rejects non-HTTPS URIs', () => {
    expect(() => capabilityMetadataUrl('http://api.dondone.dev')).toThrow('HTTPS')
  })

  it('rejects invalid URIs', () => {
    expect(() => capabilityMetadataUrl('not a url')).toThrow('not a valid URL')
  })
})

// ---------- parseCapabilityManifest ----------

describe('parseCapabilityManifest', () => {
  it('parses a valid manifest', () => {
    const result = parseCapabilityManifest(validManifestInput(), 'api', 'https://api.dondone.dev')

    expect(result.resource).toBe('https://api.dondone.dev')
    expect(result.authorization_servers).toContain('https://auth.dondone.dev')
    expect(result.dondone_capabilities.schema_version).toBe(1)
    expect(result.dondone_capabilities.catalog_version).toBe('2026-07-14.1')
    expect(result.dondone_capabilities.permissions).toHaveLength(2)
    expect(result.dondone_capabilities.roles).toHaveLength(2)
    expect(result.dondone_capabilities.roles[1].description).toBe('Full access')
  })

  it('preserves optional resource_name', () => {
    const result = parseCapabilityManifest(validManifestInput(), 'api', 'https://api.dondone.dev')
    expect(result.resource_name).toBe('Dondone API')
  })

  it('rejects non-object input', () => {
    expect(() => parseCapabilityManifest('string', 'api', 'https://api.dondone.dev')).toThrow('JSON object')
    expect(() => parseCapabilityManifest(null, 'api', 'https://api.dondone.dev')).toThrow('JSON object')
    expect(() => parseCapabilityManifest([], 'api', 'https://api.dondone.dev')).toThrow('JSON object')
  })

  it('rejects mismatched resource', () => {
    const input = validManifestInput()
    input.resource = 'https://other.dondone.dev'
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('exactly equal')
  })

  it('rejects missing auth issuer', () => {
    const input = validManifestInput()
    input.authorization_servers = ['https://other.auth.dev']
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('auth.dondone.dev')
  })

  it('rejects unsupported schema_version', () => {
    const input = validManifestInput()
    ;(input.dondone_capabilities as Record<string, unknown>).schema_version = 99
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('schema_version')
  })

  it('rejects empty catalog_version', () => {
    const input = validManifestInput()
    input.dondone_capabilities.catalog_version = '  '
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('catalog_version')
  })

  it.each([
    ['release/1', 'slash'],
    ['release%201', 'percent'],
    ['版本1', 'Unicode'],
    [`v${'a'.repeat(128)}`, 'overlong'],
  ])('rejects non URL-safe catalog_version %s (%s)', (catalogVersion) => {
    const input = validManifestInput()
    input.dondone_capabilities.catalog_version = catalogVersion
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev'))
      .toThrow('catalog_version')
  })

  it('rejects duplicate permission keys', () => {
    const input = validManifestInput()
    input.dondone_capabilities.permissions.push({ key: 'api:echo', description: 'dup' })
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('Duplicate permission')
  })

  it('rejects permission from another namespace', () => {
    const input = validManifestInput()
    input.dondone_capabilities.permissions.push({ key: 'other:read', description: 'wrong ns' })
    input.scopes_supported.push('other:read')
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('namespace "api:"')
  })

  it('rejects role referencing unknown permission', () => {
    const input = validManifestInput()
    input.dondone_capabilities.roles.push({
      key: 'bad',
      name: 'Bad',
      permission_keys: ['api:nonexistent'],
    })
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('unknown permission')
  })

  it('rejects scopes_supported referencing undeclared permission', () => {
    const input = validManifestInput()
    input.scopes_supported.push('api:undeclared')
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('not declared')
  })

  it('rejects duplicate role keys', () => {
    const input = validManifestInput()
    input.dondone_capabilities.roles.push({
      key: 'reader',
      name: 'Reader 2',
      permission_keys: ['api:read'],
    })
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('Duplicate role')
  })
})

// ---------- JCS canonicalization and hash ----------

describe('JCS canonicalization (RFC 8785)', () => {
  function ieee754(hex: string): number {
    const bytes = Uint8Array.from(hex.match(/../g)!.map((pair) => Number.parseInt(pair, 16)))
    return new DataView(bytes.buffer).getFloat64(0, false)
  }
  it('sorts object keys', () => {
    const canonical = canonicalize({ b: 1, a: 2 })
    expect(canonical).toBe('{"a":2,"b":1}')
  })

  it('sorts nested objects recursively while preserving array order', () => {
    const canonical = canonicalize({ z: { b: 1, a: 2 }, y: [3, 1, 2] })
    expect(canonical).toBe('{"y":[3,1,2],"z":{"a":2,"b":1}}')
  })

  it('serializes -0 as 0', () => {
    const canonical = canonicalize({ value: -0 })
    expect(canonical).toBe('{"value":0}')
  })

  it('serializes integers without decimal point', () => {
    expect(canonicalize({ n: 1 })).toBe('{"n":1}')
    expect(canonicalize({ n: 0 })).toBe('{"n":0}')
    expect(canonicalize({ n: -1 })).toBe('{"n":-1}')
  })

  it('serializes fractional numbers in shortest form', () => {
    expect(canonicalize({ n: 1.5 })).toBe('{"n":1.5}')
    expect(canonicalize({ n: 0.1 })).toBe('{"n":0.1}')
    expect(canonicalize({ n: 1e20 })).toBe('{"n":100000000000000000000}')
  })

  it('uses exponential notation for very large/small numbers', () => {
    expect(canonicalize({ n: 1e21 })).toBe('{"n":1e+21}')
    expect(canonicalize({ n: 1e-7 })).toBe('{"n":1e-7}')
  })

  it('rejects NaN and Infinity (canonicalize@3 strict mode)', () => {
    expect(() => canonicalize({ a: NaN })).toThrow()
    expect(() => canonicalize({ a: Infinity })).toThrow()
    expect(() => canonicalize({ a: -Infinity })).toThrow()
  })

  it('preserves Unicode without normalization', () => {
    const precomposed = '\u00e9'
    const decomposed = 'e\u0301'
    const c1 = canonicalize({ key: precomposed })
    const c2 = canonicalize({ key: decomposed })
    expect(c1).not.toBe(c2)
  })

  it('escapes control characters in strings', () => {
    const result = canonicalize({ a: '\u0008\u000c\n\r\t' })
    expect(result).toBe('{"a":"\\b\\f\\n\\r\\t"}')
  })

  it('does not escape non-BMP characters (surrogate pairs)', () => {
    const emoji = '\ud83d\ude00'
    const result = canonicalize({ a: emoji })!
    expect(result).toBe(`{"a":"${emoji}"}`)
    expect(result).not.toContain('\\u')
  })

  it('rejects lone surrogates before hashing', async () => {
    const manifest = parseCapabilityManifest(validManifestInput(), 'api', 'https://api.dondone.dev')
    manifest.resource_name = '\ud800'
    await expect(manifestSha256(manifest)).rejects.toMatchObject({
      error: 'invalid_capability_manifest',
    })
  })

  it('sorts property names by UTF-16 code unit order', () => {
    const input = {
      '\u20ac': 'euro',
      '\r': 'carriage-return',
      '\ufb33': 'hebrew-letter-dalet-with-dagesh',
      '1': 'ascii-digit',
      '\ud83d\ude00': 'emoji',
      '\u0080': 'control',
      '\u00f6': 'latin-small-o-diaeresis',
    }
    const canonical = canonicalize(input)!
    const positions = ['"\\r"', '"1"', '"\u0080"', '"\u00f6"', '"\u20ac"', '"\ud83d\ude00"', '"\ufb33"']
      .map((key) => canonical.indexOf(`${key}:`))
    expect(positions.every((position) => position >= 0)).toBe(true)
    expect(positions).toEqual([...positions].sort((a, b) => a - b))
  })

  it('handles deeply nested structures', () => {
    const input = { a: { b: { c: { d: 1 } } } }
    expect(canonicalize(input)).toBe('{"a":{"b":{"c":{"d":1}}}}')
  })

  it('handles null, true, false, empty string, empty object, empty array', () => {
    expect(canonicalize({ a: null })).toBe('{"a":null}')
    expect(canonicalize({ a: true })).toBe('{"a":true}')
    expect(canonicalize({ a: false })).toBe('{"a":false}')
    expect(canonicalize({ a: '' })).toBe('{"a":""}')
    expect(canonicalize({ a: {} })).toBe('{"a":{}}')
    expect(canonicalize({ a: [] })).toBe('{"a":[]}')
  })

  it('RFC 8785 Section 3.2.3 number vectors', () => {
    const vectors: Array<[number, string]> = [
      [0, '0'],
      [-0, '0'],
      [1, '1'],
      [-1, '-1'],
      [0.5, '0.5'],
      [9007199254740992, '9007199254740992'],
      [-9007199254740992, '-9007199254740992'],
      [1e-6, '0.000001'],
      [1e-7, '1e-7'],
      [1e20, '100000000000000000000'],
      [1e21, '1e+21'],
      [Number.MIN_SAFE_INTEGER, '-9007199254740991'],
      [Number.MAX_SAFE_INTEGER, '9007199254740991'],
    ]
    for (const [input, expected] of vectors) {
      const result = canonicalize({ n: input })
      expect(result).toBe(`{"n":${expected}}`)
    }
  })

  it('matches RFC 8785 Appendix B boundary and rounding vectors', () => {
    const vectors: Array<[string, string]> = [
      ['0000000000000000', '0'],
      ['8000000000000000', '0'],
      ['0000000000000001', '5e-324'],
      ['8000000000000001', '-5e-324'],
      ['7fefffffffffffff', '1.7976931348623157e+308'],
      ['ffefffffffffffff', '-1.7976931348623157e+308'],
      ['4340000000000000', '9007199254740992'],
      ['c340000000000000', '-9007199254740992'],
      ['4430000000000000', '295147905179352830000'],
      ['44b52d02c7e14af5', '9.999999999999997e+22'],
      ['44b52d02c7e14af6', '1e+23'],
      ['44b52d02c7e14af7', '1.0000000000000001e+23'],
      ['444b1ae4d6e2ef4e', '999999999999999700000'],
      ['444b1ae4d6e2ef4f', '999999999999999900000'],
      ['444b1ae4d6e2ef50', '1e+21'],
      ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
      ['3eb0c6f7a0b5ed8d', '0.000001'],
      ['41b3de4355555553', '333333333.3333332'],
      ['41b3de4355555554', '333333333.33333325'],
      ['41b3de4355555555', '333333333.3333333'],
      ['41b3de4355555556', '333333333.3333334'],
      ['41b3de4355555557', '333333333.33333343'],
      ['becbf647612f3696', '-0.0000033333333333333333'],
      ['43143ff3c1cb0959', '1424953923781206.2'],
    ]
    for (const [bits, expected] of vectors) {
      expect(canonicalize(ieee754(bits))).toBe(expected)
    }
  })
})

describe('manifestSha256', () => {
  it('produces consistent hash for the same manifest', async () => {
    const manifest = parseCapabilityManifest(validManifestInput(), 'api', 'https://api.dondone.dev')
    const h1 = await manifestSha256(manifest)
    const h2 = await manifestSha256(manifest)
    expect(h1).toBe(h2)
    expect(h1).toMatch(/^[0-9a-f]{64}$/)
  })

  it('produces same hash regardless of property order', async () => {
    const m1 = parseCapabilityManifest(validManifestInput(), 'api', 'https://api.dondone.dev')
    const reordered = {
      dondone_capabilities: m1.dondone_capabilities,
      scopes_supported: m1.scopes_supported,
      resource: m1.resource,
      resource_name: m1.resource_name,
      authorization_servers: m1.authorization_servers,
    } as CapabilityManifest

    const h1 = await manifestSha256(m1)
    const h2 = await manifestSha256(reordered)
    expect(h1).toBe(h2)
  })

  it('produces different hash for different content', async () => {
    const m1 = parseCapabilityManifest(validManifestInput(), 'api', 'https://api.dondone.dev')
    const input2 = validManifestInput()
    input2.dondone_capabilities.catalog_version = '2026-07-15.1'
    const m2 = parseCapabilityManifest(input2, 'api', 'https://api.dondone.dev')

    const h1 = await manifestSha256(m1)
    const h2 = await manifestSha256(m2)
    expect(h1).not.toBe(h2)
  })
})

// ---------- schema v2 parsing ----------

function validV2ManifestInput() {
  return {
    resource: 'https://api.dondone.dev',
    resource_name: 'Dondone API',
    authorization_servers: ['https://auth.dondone.dev'],
    scopes_supported: ['api:echo'],
    dondone_capabilities: {
      schema_version: 2,
      catalog_version: '2026-07-16.1',
      permissions: [
        {
          key: 'api:echo',
          name: 'Echo API',
          description: 'Call the echo API.',
          usage_controls: [
            { key: 'daily_calls', name: 'Daily calls', kind: 'quota', unit: 'request', window: 'calendar_day', minimum: 0, maximum: 1000000 },
            { key: 'request_rate', name: 'Requests per minute', kind: 'rate_limit', unit: 'request', window_seconds: 60, minimum: 0, maximum: 10000 },
          ],
        },
        {
          key: 'api:tier:vip',
          name: 'VIP Tier',
          description: 'Receive the VIP API response tier.',
        },
      ],
      roles: [
        { key: 'caller', name: 'Caller', permission_keys: ['api:echo'] },
        { key: 'vip', name: 'VIP Caller', permission_keys: ['api:echo', 'api:tier:vip'] },
      ],
    },
  }
}

describe('parseCapabilityManifest v2', () => {
  it('parses a valid v2 manifest with usage controls', () => {
    const result = parseCapabilityManifest(validV2ManifestInput(), 'api', 'https://api.dondone.dev')
    expect(result.dondone_capabilities.schema_version).toBe(2)
    const caps = result.dondone_capabilities as DondoneCapabilitiesV2
    expect(caps.permissions).toHaveLength(2)
    expect(caps.permissions[0].name).toBe('Echo API')
    expect(caps.permissions[0].usage_controls).toHaveLength(2)
    expect(caps.permissions[0].usage_controls![0].kind).toBe('quota')
    expect(caps.permissions[0].usage_controls![1].kind).toBe('rate_limit')
  })

  it('accepts a v2 permission without usage_controls', () => {
    const result = parseCapabilityManifest(validV2ManifestInput(), 'api', 'https://api.dondone.dev')
    const caps = result.dondone_capabilities as DondoneCapabilitiesV2
    expect(caps.permissions[1].usage_controls).toBeUndefined()
  })

  it('rejects v2 permission missing name', () => {
    const input = validV2ManifestInput()
    ;(input.dondone_capabilities.permissions[0] as Record<string, unknown>).name = undefined
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('name')
  })

  it('rejects v2 permission with name > 100 chars', () => {
    const input = validV2ManifestInput()
    input.dondone_capabilities.permissions[0].name = 'A'.repeat(101)
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('1-100')
  })

  it('rejects v2 permission with description > 500 chars', () => {
    const input = validV2ManifestInput()
    input.dondone_capabilities.permissions[0].description = 'A'.repeat(501)
    expect(() => parseCapabilityManifest(input, 'api', 'https://api.dondone.dev')).toThrow('1-500')
  })

  it('v1 manifest still works after v2 support', () => {
    const result = parseCapabilityManifest(validManifestInput(), 'api', 'https://api.dondone.dev')
    expect(result.dondone_capabilities.schema_version).toBe(1)
  })
})

describe('parseUsageControls', () => {
  it('parses all six control kinds', () => {
    const controls = [
      { key: 'daily', name: 'Daily', kind: 'quota', unit: 'req', window: 'calendar_day', minimum: 0, maximum: 100 },
      { key: 'rate', name: 'Rate', kind: 'rate_limit', unit: 'req', window_seconds: 60, minimum: 0, maximum: 50 },
      { key: 'model', name: 'Model', kind: 'enum_one', options: [{ value: 'gpt4', label: 'GPT-4' }] },
      { key: 'features', name: 'Features', kind: 'enum_many', options: [{ value: 'a', label: 'A' }, { value: 'b', label: 'B' }] },
      { key: 'advanced', name: 'Advanced', kind: 'boolean' },
      { key: 'max_tokens', name: 'Max tokens', kind: 'numeric_ceiling', unit: 'token', minimum: 1, maximum: 4096 },
    ]
    const result = parseUsageControls(controls, 'test:perm')
    expect(result).toHaveLength(6)
    expect(result.map((r) => r.kind)).toEqual(['quota', 'rate_limit', 'enum_one', 'enum_many', 'boolean', 'numeric_ceiling'])
  })

  it('rejects duplicate control keys', () => {
    const controls = [
      { key: 'daily', name: 'A', kind: 'quota', unit: 'req', window: 'calendar_day', minimum: 0, maximum: 100 },
      { key: 'daily', name: 'B', kind: 'quota', unit: 'req', window: 'lifetime', minimum: 0, maximum: 100 },
    ]
    expect(() => parseUsageControls(controls, 'test:p')).toThrow('duplicate control key')
  })

  it('rejects invalid control key format', () => {
    const controls = [
      { key: 'UPPER', name: 'Bad', kind: 'boolean' },
    ]
    expect(() => parseUsageControls(controls, 'test:p')).toThrow('control key must match')
  })

  it('rejects quota with invalid window', () => {
    const controls = [
      { key: 'q', name: 'Q', kind: 'quota', unit: 'req', window: 'monthly', minimum: 0, maximum: 10 },
    ]
    expect(() => parseUsageControls(controls, 'test:p')).toThrow('calendar_day')
  })

  it('rejects rate_limit with invalid window_seconds', () => {
    const controls = [
      { key: 'r', name: 'R', kind: 'rate_limit', unit: 'req', window_seconds: 30, minimum: 0, maximum: 10 },
    ]
    expect(() => parseUsageControls(controls, 'test:p')).toThrow('window_seconds')
  })

  it('rejects maximum > 1 billion', () => {
    const controls = [
      { key: 'q', name: 'Q', kind: 'quota', unit: 'req', window: 'calendar_day', minimum: 0, maximum: 1_000_000_001 },
    ]
    expect(() => parseUsageControls(controls, 'test:p')).toThrow('1000000000')
  })

  it('rejects numeric_ceiling with minimum > maximum', () => {
    const controls = [
      { key: 'c', name: 'C', kind: 'numeric_ceiling', unit: 'x', minimum: 100, maximum: 10 },
    ]
    expect(() => parseUsageControls(controls, 'test:p')).toThrow('minimum must be <= maximum')
  })

  it('rejects enum with duplicate option values', () => {
    const controls = [
      { key: 'e', name: 'E', kind: 'enum_one', options: [{ value: 'a', label: 'A' }, { value: 'a', label: 'A2' }] },
    ]
    expect(() => parseUsageControls(controls, 'test:p')).toThrow('duplicate option value')
  })

  it('rejects enum with empty options', () => {
    const controls = [
      { key: 'e', name: 'E', kind: 'enum_one', options: [] },
    ]
    expect(() => parseUsageControls(controls, 'test:p')).toThrow('1-100')
  })

  it('rejects unknown kind', () => {
    const controls = [
      { key: 'x', name: 'X', kind: 'unknown_kind' },
    ]
    expect(() => parseUsageControls(controls, 'test:p')).toThrow('invalid kind')
  })

  it('accepts optional description on controls', () => {
    const controls = [
      { key: 'b', name: 'B', kind: 'boolean', description: 'Toggle feature' },
    ]
    const result = parseUsageControls(controls, 'test:p')
    expect(result[0].description).toBe('Toggle feature')
  })
})

// ---------- isOAuthScope ----------

describe('isOAuthScope', () => {
  it('returns true for keys in scopes_supported', () => {
    expect(isOAuthScope('api:echo', ['api:echo', 'api:read'])).toBe(true)
  })

  it('returns false for keys not in scopes_supported', () => {
    expect(isOAuthScope('api:write', ['api:echo', 'api:read'])).toBe(false)
  })
})
