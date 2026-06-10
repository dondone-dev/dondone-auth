export interface AuthEnv {
  AUTH_CODES: KVNamespace
  AUTH_APPS_JSON: string
  SUPABASE_URL: string
  SUPABASE_PUBLISHABLE_KEY: string
}

export interface AuthApp {
  name: string
  redirectUris: string[]
}

export type AuthAppRegistry = Record<string, AuthApp>

export interface SupabaseUser {
  id: string
  email?: string
}

export interface SupabaseSessionPayload {
  access_token: string
  refresh_token: string
  expires_at: number
  token_type: string
}

export interface AuthorizationCodeRecord {
  clientId: string
  redirectUri: string
  state: string
  codeChallenge: string
  userId: string
  session: SupabaseSessionPayload
}
