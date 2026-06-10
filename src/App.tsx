import { useEffect, useState } from 'react'
import {
  ArrowRight,
  Check,
  Copy,
  KeyRound,
  LogOut,
  Mail,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  TriangleAlert,
  UserRound,
} from 'lucide-react'
import { supabase } from './supabase'
import { cn } from '@/lib/utils'
import {
  createAuthorizationRedirect,
  hasAuthorizationParams,
  originOf,
  parseAuthorizationRequest,
} from '@/lib/redirect'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'

type Pending =
  | 'signUp'
  | 'signIn'
  | 'getUser'
  | 'refreshSession'
  | 'authorize'
  | 'signOut'
  | null

function App() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [output, setOutput] = useState('')
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [userEmail, setUserEmail] = useState<string | null>(null)
  const [pending, setPending] = useState<Pending>(null)
  const [copied, setCopied] = useState(false)

  // 来访时携带的授权请求参数。真正的 client/redirect 白名单由 /api/authorize 校验。
  const [authorizationRequest] = useState(() => parseAuthorizationRequest())
  const [authorizationRejected] = useState<boolean>(
    () => hasAuthorizationParams() && parseAuthorizationRequest() === null
  )

  const signedIn = accessToken !== null

  async function refreshSession() {
    setPending('refreshSession')
    const { data, error } = await supabase.auth.getSession()
    setPending(null)

    if (error) {
      setOutput(JSON.stringify(error, null, 2))
      return
    }

    setAccessToken(data.session?.access_token ?? null)
    setOutput(JSON.stringify(data.session, null, 2))
  }

  useEffect(() => {
    void supabase.auth.getSession().then(({ data }) => {
      setAccessToken(data.session?.access_token ?? null)
      setUserEmail(data.session?.user.email ?? null)
    })

    const { data } = supabase.auth.onAuthStateChange((_event, session) => {
      setAccessToken(session?.access_token ?? null)
      setUserEmail(session?.user.email ?? null)
    })

    return () => {
      data.subscription.unsubscribe()
    }
  }, [])

  // 已登录用户携带授权请求到达时，换取一次性 code 后跳回目标应用。
  async function continueAuthorization() {
    if (!authorizationRequest) return
    setPending('authorize')
    const { data, error } = await supabase.auth.getSession()

    if (error || !data.session) {
      setPending(null)
      setOutput(
        JSON.stringify(
          { ok: false, error: error?.message ?? 'No active session.' },
          null,
          2
        )
      )
      return
    }

    try {
      const redirectTo = await createAuthorizationRedirect(
        authorizationRequest,
        data.session
      )
      window.location.href = redirectTo
    } catch (error) {
      setPending(null)
      setOutput(
        JSON.stringify(
          {
            ok: false,
            error: error instanceof Error ? error.message : 'Authorization failed.',
          },
          null,
          2
        )
      )
    }
  }

  async function signUp() {
    setPending('signUp')
    const { data, error } = await supabase.auth.signUp({ email, password })
    setPending(null)
    setOutput(JSON.stringify({ data, error }, null, 2))
  }

  async function signIn() {
    setPending('signIn')
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    })
    setAccessToken(data.session?.access_token ?? null)
    setUserEmail(data.session?.user.email ?? null)
    setOutput(JSON.stringify({ data, error }, null, 2))

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
      } catch (error) {
        setOutput(
          JSON.stringify(
            {
              ok: false,
              error:
                error instanceof Error ? error.message : 'Authorization failed.',
            },
            null,
            2
          )
        )
      }
    }

    setPending(null)
  }

  async function getUser() {
    setPending('getUser')
    const { data, error } = await supabase.auth.getUser()
    setPending(null)
    setOutput(JSON.stringify({ data, error }, null, 2))
  }

  async function signOut() {
    setPending('signOut')
    const { error } = await supabase.auth.signOut()
    setPending(null)
    setAccessToken(null)
    setUserEmail(null)
    setOutput(JSON.stringify({ ok: !error, error }, null, 2))
  }

  async function copyToken() {
    if (!accessToken) return
    await navigator.clipboard.writeText(accessToken)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const credentialsMissing = !email || !password

  return (
    <div className="min-h-svh w-full bg-gradient-to-br from-background via-background to-muted px-4 py-10">
      <div className="mx-auto flex max-w-2xl flex-col gap-6">
        <header className="flex flex-col items-center gap-3 text-center">
          <div className="flex size-12 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
            <ShieldCheck className="size-6" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">
              Simple Auth
            </h1>
            <p className="text-sm text-muted-foreground">
              注册、登录并查看你的 Session / JWT
            </p>
          </div>
          <span
            className={cn(
              'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium',
              signedIn
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                : 'border-border bg-muted text-muted-foreground'
            )}
          >
            {signedIn ? (
              <ShieldCheck className="size-3.5" />
            ) : (
              <ShieldX className="size-3.5" />
            )}
            {signedIn ? '已登录' : '未登录'}
          </span>
        </header>

        {authorizationRejected && (
          <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            <TriangleAlert className="size-4 shrink-0" />
            授权请求参数不完整或回调地址无效，已忽略。请检查 client_id、redirect_uri 与 state。
          </div>
        )}

        {authorizationRequest && !authorizationRejected && (
          <div className="rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 text-sm text-muted-foreground">
            登录后将返回{' '}
            <strong className="text-foreground">
              {originOf(authorizationRequest.redirectUri)}
            </strong>
          </div>
        )}

        {authorizationRequest && signedIn && (
          <Card className="border-primary/30">
            <CardHeader>
              <CardTitle className="text-base">继续登录</CardTitle>
              <CardDescription>
                你已登录{userEmail ? `为 ${userEmail}` : ''}，可直接返回应用。
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button
                className="w-full"
                onClick={continueAuthorization}
                disabled={pending === 'authorize'}
              >
                {pending === 'authorize' && (
                  <RefreshCw className="size-4 animate-spin" />
                )}
                继续并返回 {originOf(authorizationRequest.redirectUri)}
                <ArrowRight className="size-4" />
              </Button>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>账户</CardTitle>
            <CardDescription>使用邮箱和密码进行身份认证</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="signIn" className="gap-6">
              <TabsList className="w-full">
                <TabsTrigger value="signIn">登录</TabsTrigger>
                <TabsTrigger value="signUp">注册</TabsTrigger>
              </TabsList>

              <div className="grid gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="email">邮箱</Label>
                  <div className="relative">
                    <Mail className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="email"
                      type="email"
                      autoComplete="email"
                      placeholder="you@example.com"
                      className="pl-9"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                  </div>
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="password">密码</Label>
                  <div className="relative">
                    <KeyRound className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="password"
                      type="password"
                      autoComplete="current-password"
                      placeholder="••••••••"
                      className="pl-9"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              <TabsContent value="signIn">
                <Button
                  className="w-full"
                  onClick={signIn}
                  disabled={credentialsMissing || pending === 'signIn'}
                >
                  {pending === 'signIn' && (
                    <RefreshCw className="size-4 animate-spin" />
                  )}
                  登录
                </Button>
              </TabsContent>

              <TabsContent value="signUp">
                <Button
                  className="w-full"
                  onClick={signUp}
                  disabled={credentialsMissing || pending === 'signUp'}
                >
                  {pending === 'signUp' && (
                    <RefreshCw className="size-4 animate-spin" />
                  )}
                  注册
                </Button>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">会话操作</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              onClick={getUser}
              disabled={pending === 'getUser'}
            >
              <UserRound className="size-4" />
              获取用户信息
            </Button>
            <Button
              variant="outline"
              onClick={refreshSession}
              disabled={pending === 'refreshSession'}
            >
              <RefreshCw
                className={cn(
                  'size-4',
                  pending === 'refreshSession' && 'animate-spin'
                )}
              />
              获取 Session / JWT
            </Button>
            <Button
              variant="destructive"
              onClick={signOut}
              disabled={!signedIn || pending === 'signOut'}
            >
              <LogOut className="size-4" />
              退出
            </Button>
          </CardContent>
        </Card>

        {accessToken && (
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle className="text-base">Access Token</CardTitle>
              <Button variant="ghost" size="sm" onClick={copyToken}>
                {copied ? (
                  <Check className="size-4 text-emerald-500" />
                ) : (
                  <Copy className="size-4" />
                )}
                {copied ? '已复制' : '复制'}
              </Button>
            </CardHeader>
            <CardContent>
              <Textarea
                readOnly
                value={accessToken}
                className="h-28 resize-none font-mono text-xs break-all"
              />
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle className="text-base">输出</CardTitle>
            <CardDescription>最近一次操作的响应</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="max-h-96 overflow-auto rounded-md bg-muted p-4 font-mono text-xs whitespace-pre-wrap text-muted-foreground">
              {output || '暂无输出'}
            </pre>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default App
