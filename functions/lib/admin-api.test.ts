import { describe, expect, it } from 'vitest'
import { handleAdminApi } from './admin-api'
import type { AuthEnv } from './types'

const env = {
  ADMIN_ALLOWED_ORIGINS: 'https://console.dondone.dev,https://admin.dondone.dev',
} as AuthEnv

describe('admin API CORS', () => {
  it('does not reflect an unregistered origin', async () => {
    const response = await handleAdminApi(new Request('https://auth.dondone.dev/api/admin/x', {
      method: 'OPTIONS', headers: { Origin: 'https://evil.example' },
    }), env)
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull()
  })

  it('allows an explicitly configured origin', async () => {
    const response = await handleAdminApi(new Request('https://auth.dondone.dev/api/admin/x', {
      method: 'OPTIONS', headers: { Origin: 'https://console.dondone.dev' },
    }), env)
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://console.dondone.dev')
  })
})
