export interface AuthEnv {
  AUTH_CODES: KVNamespace
  SUPABASE_URL: string
  SUPABASE_PUBLISHABLE_KEY: string
  SUPABASE_SERVICE_ROLE_KEY: string
  DONDONE_JWT_PRIVATE_JWK: string
  DONDONE_JWT_KID: string
  DONDONE_JWT_ISSUER: string
  ADMIN_ALLOWED_ORIGINS?: string
}

export interface AuthApp {
  name: string
  redirectUris: string[]
}

export type ServiceRegistry = Record<string, AuthApp>

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
  userEmail?: string
  session: SupabaseSessionPayload
  resource?: string
  scopes?: string[]
}
