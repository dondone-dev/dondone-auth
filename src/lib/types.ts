export type Pending =
  | 'signUp'
  | 'signIn'
  | 'passkeySignIn'
  | 'enrollPasskey'
  | 'getUser'
  | 'apiEcho'
  | 'refreshSession'
  | 'authorize'
  | 'signOut'
  | null

export type OAuthProvider = 'github' | 'google'

export interface Notice {
  kind: 'error' | 'success' | 'info'
  text: string
}

export interface DebugEntry {
  id: number
  time: string
  label: string
  data: unknown
}
