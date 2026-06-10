import { ApiError } from './errors'
import type { AuthEnv, SupabaseUser } from './types'

export async function getSupabaseUser(
  env: AuthEnv,
  accessToken: string
): Promise<SupabaseUser> {
  const response = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
    headers: {
      apikey: env.SUPABASE_PUBLISHABLE_KEY,
      Authorization: `Bearer ${accessToken}`,
    },
  })

  if (!response.ok) {
    throw new ApiError(401, 'invalid_token', 'Supabase access token is invalid.')
  }

  const data = (await response.json()) as { id?: unknown; email?: unknown }
  if (typeof data.id !== 'string') {
    throw new ApiError(401, 'invalid_token', 'Supabase access token is invalid.')
  }

  return {
    id: data.id,
    email: typeof data.email === 'string' ? data.email : undefined,
  }
}
