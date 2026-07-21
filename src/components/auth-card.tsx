import { useRef, useState } from 'react'
import { Fingerprint, KeyRound, Mail, RefreshCw } from 'lucide-react'
import type { OAuthProvider, Pending } from '@/lib/types'
import { useI18n } from '@/lib/i18n'
import { GitHubIcon, GoogleIcon } from '@/components/brand-icons'
import {
  TurnstileWidget,
  type TurnstileHandle,
} from '@/components/turnstile-widget'
import { config } from '@/config'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

const TURNSTILE_SITE_KEY = config.turnstileSiteKey

interface AuthCardProps {
  email: string
  password: string
  pending: Pending
  oauthPending: OAuthProvider | null
  onEmailChange: (value: string) => void
  onPasswordChange: (value: string) => void
  onSignIn: (captchaToken?: string) => void
  onSignUp: (captchaToken?: string) => void
  onOAuth: (provider: OAuthProvider) => void
  onPasskey: () => void
}

export function AuthCard({
  email,
  password,
  pending,
  oauthPending,
  onEmailChange,
  onPasswordChange,
  onSignIn,
  onSignUp,
  onOAuth,
  onPasskey,
}: AuthCardProps) {
  const { t } = useI18n()
  const credentialsMissing = !email || !password
  const busy = pending !== null || oauthPending !== null

  // CAPTCHA is enforced only when a Turnstile site key is configured; without
  // it the widget never renders and the flow is unchanged.
  const [captchaToken, setCaptchaToken] = useState<string>()
  const turnstileRef = useRef<TurnstileHandle>(null)
  const captchaMissing = Boolean(TURNSTILE_SITE_KEY) && !captchaToken

  // Turnstile tokens are single-use, so consume the current token and arm a
  // fresh challenge on every email/password attempt.
  function submitWithCaptcha(action: (captchaToken?: string) => void) {
    action(captchaToken)
    if (TURNSTILE_SITE_KEY) {
      turnstileRef.current?.reset()
      setCaptchaToken(undefined)
    }
  }

  return (
    <Card>
      <CardContent>
        <Tabs defaultValue="signIn" className="gap-5">
          <TabsList className="w-full">
            <TabsTrigger value="signIn">{t('tabs.signIn')}</TabsTrigger>
            <TabsTrigger value="signUp">{t('tabs.signUp')}</TabsTrigger>
          </TabsList>

          <div className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="email">{t('field.email')}</Label>
              <div className="relative">
                <Mail className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  placeholder="you@example.com"
                  className="pl-9"
                  value={email}
                  onChange={(e) => onEmailChange(e.target.value)}
                />
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="password">{t('field.password')}</Label>
              <div className="relative">
                <KeyRound className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  placeholder="••••••••"
                  className="pl-9"
                  value={password}
                  onChange={(e) => onPasswordChange(e.target.value)}
                />
              </div>
            </div>
          </div>

          {TURNSTILE_SITE_KEY && (
            <TurnstileWidget
              ref={turnstileRef}
              siteKey={TURNSTILE_SITE_KEY}
              onToken={setCaptchaToken}
            />
          )}

          <TabsContent value="signIn">
            <Button
              className="w-full"
              onClick={() => submitWithCaptcha(onSignIn)}
              disabled={credentialsMissing || busy || captchaMissing}
            >
              {pending === 'signIn' && (
                <RefreshCw className="size-4 animate-spin" />
              )}
              {t('action.signIn')}
            </Button>
          </TabsContent>

          <TabsContent value="signUp">
            <Button
              className="w-full"
              onClick={() => submitWithCaptcha(onSignUp)}
              disabled={credentialsMissing || busy || captchaMissing}
            >
              {pending === 'signUp' && (
                <RefreshCw className="size-4 animate-spin" />
              )}
              {t('action.signUp')}
            </Button>
          </TabsContent>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t" />
            </div>
            <div className="relative flex justify-center text-xs">
              <span className="bg-card px-2 text-muted-foreground">
                {t('divider.or')}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <Button
              variant="outline"
              onClick={() => onOAuth('github')}
              disabled={busy}
            >
              {oauthPending === 'github' ? (
                <RefreshCw className="size-4 animate-spin" />
              ) : (
                <GitHubIcon />
              )}
              GitHub
            </Button>
            <Button
              variant="outline"
              onClick={() => onOAuth('google')}
              disabled={busy}
            >
              {oauthPending === 'google' ? (
                <RefreshCw className="size-4 animate-spin" />
              ) : (
                <GoogleIcon />
              )}
              Google
            </Button>
          </div>

          <Button
            variant="outline"
            className="w-full"
            onClick={onPasskey}
            disabled={busy}
          >
            {pending === 'passkeySignIn' ? (
              <RefreshCw className="size-4 animate-spin" />
            ) : (
              <Fingerprint className="size-4" />
            )}
            {t('action.passkey')}
          </Button>
        </Tabs>
      </CardContent>
    </Card>
  )
}
