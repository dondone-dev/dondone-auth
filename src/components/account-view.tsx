import type { Session } from '@supabase/supabase-js'
import { Fingerprint, LogOut, RefreshCw } from 'lucide-react'
import type { Pending } from '@/lib/types'
import { useI18n } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'

interface AccountViewProps {
  session: Session
  pending: Pending
  onRefreshSession: () => void
  onEnrollPasskey: () => void
  onSignOut: () => void
}

function InfoRow({
  label,
  children,
  mono = false,
}: {
  label: string
  children: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 first:pt-0 last:pb-0">
      <span className="shrink-0 text-sm text-muted-foreground">{label}</span>
      <span
        className={cn(
          'flex min-w-0 items-center gap-1 text-sm text-foreground',
          mono && 'font-mono text-xs'
        )}
      >
        {children}
      </span>
    </div>
  )
}

export function AccountView({
  session,
  pending,
  onRefreshSession,
  onEnrollPasskey,
  onSignOut,
}: AccountViewProps) {
  const { t, locale } = useI18n()
  const email = session.user.email ?? '—'
  const initial = (session.user.email ?? '?').charAt(0).toUpperCase()
  const provider = session.user.app_metadata?.provider ?? 'email'
  const expiresAt = session.expires_at
    ? new Date(session.expires_at * 1000).toLocaleString(locale)
    : '—'

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent className="flex flex-col items-center gap-2">
          <div className="flex size-12 items-center justify-center rounded-full bg-primary/10 text-lg font-semibold text-primary">
            {initial}
          </div>
          <p className="max-w-full truncate text-sm font-medium">{email}</p>
          <Badge variant="success">{t('account.signedIn')}</Badge>
        </CardContent>
        <CardContent className="divide-y border-t pt-5">
          <InfoRow label={t('account.userId')} mono>
            <span className="truncate">{session.user.id}</span>
          </InfoRow>
          <InfoRow label={t('account.provider')}>{provider}</InfoRow>
          <InfoRow label={t('account.expires')}>
            {expiresAt}
            <Button
              variant="ghost"
              size="icon-xs"
              title={t('account.refresh')}
              onClick={onRefreshSession}
              disabled={pending === 'refreshSession'}
              className="text-muted-foreground"
            >
              <RefreshCw
                className={cn(
                  'size-3',
                  pending === 'refreshSession' && 'animate-spin'
                )}
              />
            </Button>
          </InfoRow>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex min-w-0 items-center gap-3">
              <div className="flex size-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
                <Fingerprint className="size-4" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-medium">Passkey</p>
                <p className="text-sm text-muted-foreground">
                  {t('security.passkeyDesc')}
                </p>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={onEnrollPasskey}
              disabled={pending === 'enrollPasskey'}
            >
              {pending === 'enrollPasskey' && (
                <RefreshCw className="size-4 animate-spin" />
              )}
              {t('security.enrollPasskey')}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Button
        variant="outline"
        className="w-full text-muted-foreground hover:text-destructive"
        onClick={onSignOut}
        disabled={pending === 'signOut'}
      >
        <LogOut className="size-4" />
        {t('action.signOut')}
      </Button>
    </div>
  )
}
