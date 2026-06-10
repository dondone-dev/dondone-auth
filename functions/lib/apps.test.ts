import { describe, expect, it } from 'vitest'
import { findRegisteredApp, parseAuthApps } from './apps'

describe('auth app registry', () => {
  it('accepts an exact registered redirect URI', () => {
    const registry = parseAuthApps(
      JSON.stringify({
        time: {
          name: 'Time',
          redirectUris: ['https://time.dondone.dev/auth/callback'],
        },
      })
    )

    const app = findRegisteredApp(
      registry,
      'time',
      'https://time.dondone.dev/auth/callback'
    )

    expect(app?.name).toBe('Time')
  })

  it('rejects an unregistered redirect URI for a known client', () => {
    const registry = parseAuthApps(
      JSON.stringify({
        time: {
          name: 'Time',
          redirectUris: ['https://time.dondone.dev/auth/callback'],
        },
      })
    )

    expect(
      findRegisteredApp(
        registry,
        'time',
        'https://evil.dondone.dev/auth/callback'
      )
    ).toBeNull()
  })
})
