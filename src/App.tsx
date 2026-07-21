import { useEffect, useRef, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import {
  ArrowRight,
  CircleCheck,
  Info,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
} from 'lucide-react'
import { supabase } from './supabase'
import { cn } from '@/lib/utils'
import {
  createAuthorizationRedirect,
  hasAuthorizationParams,
  originOf,
  parseAuthorizationRequest,
} from '@/lib/redirect'
import { useI18n } from '@/lib/i18n'
import type { DebugEntry, Notice, OAuthProvider, Pending } from '@/lib/types'
import { useTheme } from '@/hooks/use-theme'
import { AccountView } from '@/components/account-view'
import { AuthCard } from '@/components/auth-card'
import { DebugPanel } from '@/components/debug-panel'
import { PageFooter } from '@/components/page-footer'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

const API_BASE =
  (import.meta.env.VITE_API_BASE as string | undefined) ?? 'https://api.dondone.dev'

const DEBUG_STORAGE_KEY = 'dondone.debug'
const MAX_DEBUG_ENTRIES = 20

function NoticeBanner({ notice }: { notice: Notice }) {
  const Icon =
    notice.kind === 'error'
      ? TriangleAlert
      : notice.kind === 'success'
        ? CircleCheck
        : Info

  return (
    <div
      className={cn(
        'flex items-start gap-2 rounded-lg border px-4 py-3 text-sm',
        notice.kind === 'error' &&
          'border-destructive/30 bg-destructive/10 text-destructive',
        notice.kind === 'success' &&
          'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400',
        notice.kind === 'info' &&
          'border-primary/25 bg-primary/5 text-muted-foreground'
      )}
    >
      <Icon className="mt-0.5 size-4 shrink-0" />
      <span>{notice.text}</span>
    </div>
  )
}

function App() {
  const { t } = useI18n()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [session, setSession] = useState<Session | null>(null)
  const [pending, setPending] = useState<Pending>(null)
  const [oauthPending, setOAuthPending] = useState<OAuthProvider | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [copied, setCopied] = useState(false)

  const { theme, toggleTheme } = useTheme()
  const [debugMode, setDebugMode] = useState(
    () => localStorage.getItem(DEBUG_STORAGE_KEY) === '1'
  )
  const [debugEntries, setDebugEntries] = useState<DebugEntry[]>([])
  const debugEntryId = useRef(0)

  // 来访时携带的授权请求参数。真正的 client/redirect 白名单由 /api/authorize 校验。
  const [authorizationRequest] = useState(() => parseAuthorizationRequest())
  const [authorizationRejected] = useState<boolean>(
    () => hasAuthorizationParams() && parseAuthorizationRequest() === null
  )

  const accessToken = session?.access_token ?? null
  const signedIn = session !== null

  function toggleDebug() {
    setDebugMode((value) => {
      const next = !value
      localStorage.setItem(DEBUG_STORAGE_KEY, next ? '1' : '0')
      return next
    })
  }

  function logDebug(label: string, data: unknown) {
    debugEntryId.current += 1
    const entry: DebugEntry = {
      id: debugEntryId.current,
      time: new Date().toLocaleTimeString(),
      label,
      data,
    }
    setDebugEntries((entries) => [entry, ...entries].slice(0, MAX_DEBUG_ENTRIES))
  }

  useEffect(() => {
    void supabase.auth.getSession().then(({ data }) => {
      setSession(data.session)
    })

    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession)
    })

    return () => {
      data.subscription.unsubscribe()
    }
  }, [])

  async function refreshSession() {
    setPending('refreshSession')
    const { data, error } = await supabase.auth.getSession()
    setPending(null)
    logDebug('auth.getSession', error ?? data.session)

    if (error) {
      setNotice({
        kind: 'error',
        text: t('session.refreshFailed', { message: error.message }),
      })
      return
    }

    setSession(data.session)
    setNotice({ kind: 'success', text: t('session.refreshed') })
  }

  // 已登录用户携带授权请求到达时，换取一次性 code 后跳回目标应用。
  async function continueAuthorization() {
    if (!authorizationRequest) return
    setPending('authorize')
    const { data, error } = await supabase.auth.getSession()

    if (error || !data.session) {
      setPending(null)
      setNotice({
        kind: 'error',
        text: t('authz.failed', {
          message: error?.message ?? t('authz.noSession'),
        }),
      })
      return
    }

    try {
      const redirectTo = await createAuthorizationRedirect(
        authorizationRequest,
        data.session
      )
      window.location.href = redirectTo
    } catch (err) {
      setPending(null)
      const message = err instanceof Error ? err.message : 'Authorization failed.'
      logDebug('authorize', { ok: false, error: message })
      setNotice({ kind: 'error', text: t('authz.failed', { message }) })
    }
  }

  async function signInWithProvider(provider: OAuthProvider) {
    setNotice(null)
    setOAuthPending(provider)
    await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo: window.location.href },
    })
    setOAuthPending(null)
  }

  async function signInWithPasskey() {
    setNotice(null)
    setPending('passkeySignIn')
    try {
      const { data, error } = await supabase.auth.signInWithPasskey({})
      if (error) throw error
      setSession(data.session)
      logDebug('auth.signInWithPasskey', data)

      if (data.session && authorizationRequest) {
        const redirectTo = await createAuthorizationRedirect(
          authorizationRequest,
          data.session
        )
        window.location.href = redirectTo
        return
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Passkey error.'
      logDebug('auth.signInWithPasskey', { ok: false, error: message })
      setNotice({ kind: 'error', text: t('passkey.signInFailed', { message }) })
    }
    setPending(null)
  }

  async function enrollPasskey() {
    setPending('enrollPasskey')
    try {
      const { data, error } = await supabase.auth.registerPasskey({})
      logDebug('auth.registerPasskey', error ?? data)
      if (error) throw error
      setNotice({ kind: 'success', text: t('passkey.enrollSuccess') })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Passkey error.'
      setNotice({ kind: 'error', text: t('passkey.enrollFailed', { message }) })
    }
    setPending(null)
  }

  async function signUp(captchaToken?: string) {
    setNotice(null)
    setPending('signUp')
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: { captchaToken },
    })
    setPending(null)
    logDebug('auth.signUp', error ?? data)

    if (error) {
      setNotice({
        kind: 'error',
        text: t('signup.failed', { message: error.message }),
      })
      return
    }

    if (data.session) {
      setSession(data.session)
      setNotice({ kind: 'success', text: t('signup.successAuto') })
    } else {
      setNotice({ kind: 'success', text: t('signup.successVerify') })
    }
  }

  async function signIn(captchaToken?: string) {
    setNotice(null)
    setPending('signIn')
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
      options: { captchaToken },
    })
    setSession(data.session)
    logDebug('auth.signInWithPassword', error ?? data)

    if (error) {
      setPending(null)
      setNotice({
        kind: 'error',
        text: t('signin.failed', { message: error.message }),
      })
      return
    }

    // 刚主动登录成功且带了有效授权请求，直接换取一次性 code 后返回。
    // 保持 pending 状态直到跳转，避免兑换期间按钮可点导致重复提交。
    if (data.session && authorizationRequest) {
      try {
        const redirectTo = await createAuthorizationRedirect(
          authorizationRequest,
          data.session
        )
        window.location.href = redirectTo
        return
      } catch (err) {
        const message =
          err instanceof Error ? err.message : 'Authorization failed.'
        logDebug('authorize', { ok: false, error: message })
        setNotice({ kind: 'error', text: t('authz.failed', { message }) })
      }
    }

    setPending(null)
  }

  async function getUser() {
    setPending('getUser')
    const { data, error } = await supabase.auth.getUser()
    setPending(null)
    logDebug('auth.getUser', error ?? data)
  }

  async function callApiEcho() {
    if (!accessToken) return
    setPending('apiEcho')
    try {
      const tokenResponse = await fetch('/api/api-token', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ resource: API_BASE, scope: 'api:echo' }),
      })
      const tokenBody = (await tokenResponse.json()) as {
        api_access_token?: string
        error?: string
        message?: string
      }

      if (!tokenResponse.ok || !tokenBody.api_access_token) {
        throw new Error(tokenBody.message ?? tokenBody.error ?? 'API token failed.')
      }

      const echoResponse = await fetch(`${API_BASE}/echo`, {
        headers: { Authorization: `Bearer ${tokenBody.api_access_token}` },
      })
      const echoBody = await echoResponse.json()
      logDebug('api.echo', echoBody)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'API Echo failed.'
      logDebug('api.echo', { ok: false, error: message })
      setNotice({ kind: 'error', text: t('apiEcho.failed', { message }) })
    }
    setPending(null)
  }

  async function signOut() {
    setPending('signOut')
    const { error } = await supabase.auth.signOut()
    setPending(null)
    setSession(null)
    logDebug('auth.signOut', { ok: !error, error })
    setNotice(
      error
        ? { kind: 'error', text: t('signout.failed', { message: error.message }) }
        : { kind: 'info', text: t('signout.done') }
    )
  }

  async function copyToken() {
    if (!accessToken) return
    await navigator.clipboard.writeText(accessToken)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="flex min-h-svh flex-col bg-background">
      <main className="flex w-full flex-1 flex-col items-center px-4 pt-14 pb-8 sm:pt-20">
        <div className="flex w-full max-w-sm flex-col gap-5">
          <div className="flex flex-col items-center gap-4">
            <div className="flex size-11 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
              <ShieldCheck className="size-6" />
            </div>
            {!signedIn && (
              <h1 className="text-xl font-semibold tracking-tight">
                {t('auth.heading')}
              </h1>
            )}
          </div>

          {authorizationRejected && (
            <NoticeBanner
              notice={{ kind: 'error', text: t('authz.invalid') }}
            />
          )}

          {authorizationRequest && !authorizationRejected && !signedIn && (
            <NoticeBanner
              notice={{
                kind: 'info',
                text: t('authz.willReturn', {
                  origin: originOf(authorizationRequest.redirectUri),
                }),
              }}
            />
          )}

          {notice && <NoticeBanner notice={notice} />}

          {session ? (
            <>
              {authorizationRequest && (
                <Card className="border-primary/30">
                  <CardHeader>
                    <CardTitle className="text-base">
                      {t('authz.continueTitle')}
                    </CardTitle>
                    <CardDescription>
                      {session.user.email
                        ? t('authz.continueDescWithEmail', {
                            email: session.user.email,
                          })
                        : t('authz.continueDesc')}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-4">
                    {(authorizationRequest.scope || authorizationRequest.resource) && (
                      <div className="rounded-lg border bg-muted/40 p-3 text-sm">
                        <p className="mb-2 font-medium">{t('authz.grantsLabel')}</p>
                        {authorizationRequest.scope && (
                          <ul className="flex flex-col gap-1">
                            {authorizationRequest.scope.split(' ').map((scope) => (
                              <li key={scope} className="flex items-center gap-2">
                                <CircleCheck className="size-3.5 shrink-0 text-primary" />
                                <code className="font-mono text-xs">{scope}</code>
                              </li>
                            ))}
                          </ul>
                        )}
                        {authorizationRequest.resource && (
                          <p className="mt-2 text-xs text-muted-foreground">
                            {t('authz.resourceLabel', {
                              host: originOf(authorizationRequest.resource),
                            })}
                          </p>
                        )}
                      </div>
                    )}
                    <Button
                      className="w-full"
                      onClick={continueAuthorization}
                      disabled={pending === 'authorize'}
                    >
                      {pending === 'authorize' && (
                        <RefreshCw className="size-4 animate-spin" />
                      )}
                      {t('authz.continueAction', {
                        origin: originOf(authorizationRequest.redirectUri),
                      })}
                      <ArrowRight className="size-4" />
                    </Button>
                  </CardContent>
                </Card>
              )}

              <AccountView
                session={session}
                pending={pending}
                onRefreshSession={refreshSession}
                onEnrollPasskey={enrollPasskey}
                onSignOut={signOut}
              />
            </>
          ) : (
            <AuthCard
              email={email}
              password={password}
              pending={pending}
              oauthPending={oauthPending}
              onEmailChange={setEmail}
              onPasswordChange={setPassword}
              onSignIn={signIn}
              onSignUp={signUp}
              onOAuth={signInWithProvider}
              onPasskey={signInWithPasskey}
            />
          )}
        </div>

        {debugMode && (
          <div className="mt-10 w-full max-w-xl">
            <DebugPanel
              signedIn={signedIn}
              accessToken={accessToken}
              entries={debugEntries}
              pending={pending}
              copied={copied}
              onCopyToken={copyToken}
              onGetUser={getUser}
              onRefreshSession={refreshSession}
              onApiEcho={callApiEcho}
              onClearEntries={() => setDebugEntries([])}
            />
          </div>
        )}
      </main>

      <PageFooter
        debugMode={debugMode}
        onToggleDebug={toggleDebug}
        theme={theme}
        onToggleTheme={toggleTheme}
      />
    </div>
  )
}

export default App
