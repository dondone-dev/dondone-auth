import { getUsageStatus } from '../../lib/usage-api'
import type { AuthEnv } from '../../lib/types'

export const onRequestPost: PagesFunction<AuthEnv> = async ({ request, env }) => {
  const authorization = request.headers.get('Authorization')
  const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1]
  if (!token) {
    return Response.json(
      { error: 'invalid_token' },
      { status: 401, headers: { 'Cache-Control': 'no-store' } }
    )
  }

  let body: unknown
  try {
    body = await request.json()
  } catch {
    return Response.json(
      { error: 'invalid_request', message: 'Request body must be valid JSON.' },
      { status: 400, headers: { 'Cache-Control': 'no-store' } }
    )
  }

  try {
    const result = await getUsageStatus(token, body, env)
    return Response.json(result, { headers: { 'Cache-Control': 'no-store' } })
  } catch (error: unknown) {
    const err = error as { status?: number; error?: string }
    const status = err.status ?? 503
    const errorCode = err.error ?? 'usage_service_unavailable'
    return Response.json({ error: errorCode }, { status, headers: { 'Cache-Control': 'no-store' } })
  }
}
