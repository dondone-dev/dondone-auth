import { afterEach, describe, expect, it, vi } from 'vitest'
import { createAuthorizationRedirect, parseAuthorizationRequest } from './redirect'

afterEach(() => vi.unstubAllGlobals())

describe('resource-aware authorization redirect', () => {
  it('parses resource and normalized scopes from the browser URL', () => {
    vi.stubGlobal('window', { location: { search: '?client_id=time&redirect_uri=https%3A%2F%2Ftime.dondone.dev%2Fauth%2Fcallback&state=s&code_challenge=c&resource=https%3A%2F%2Fapi.dondone.dev&scope=api%3Aread++api%3Aecho+api%3Aread' } })
    expect(parseAuthorizationRequest()).toMatchObject({
      resource: 'https://api.dondone.dev',
      scope: 'api:echo api:read',
    })
  })

  it('forwards resource and scope to /api/authorize', async () => {
    const fetchMock = vi.fn(async (_url, init) => {
      const body = JSON.parse(String((init as RequestInit).body))
      expect(body.resource).toBe('https://api.dondone.dev')
      expect(body.scope).toBe('api:echo')
      return new Response(JSON.stringify({ redirect_to: 'https://time.dondone.dev/auth/callback?code=x' }))
    })
    vi.stubGlobal('fetch', fetchMock)
    await createAuthorizationRedirect({
      clientId: 'time', redirectUri: 'https://time.dondone.dev/auth/callback', state: 's', codeChallenge: 'c',
      resource: 'https://api.dondone.dev', scope: 'api:echo',
    }, { access_token: 'a', refresh_token: 'r', expires_at: 1, token_type: 'bearer' } as never)
    expect(fetchMock).toHaveBeenCalledOnce()
  })
})
