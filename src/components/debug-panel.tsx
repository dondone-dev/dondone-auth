import { Check, Copy, RefreshCw, ShieldCheck, Trash2, UserRound } from 'lucide-react'
import type { DebugEntry, Pending } from '@/lib/types'
import { useI18n } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

interface DebugPanelProps {
  signedIn: boolean
  accessToken: string | null
  entries: DebugEntry[]
  pending: Pending
  copied: boolean
  onCopyToken: () => void
  onGetUser: () => void
  onRefreshSession: () => void
  onApiEcho: () => void
  onClearEntries: () => void
}

export function DebugPanel({
  signedIn,
  accessToken,
  entries,
  pending,
  copied,
  onCopyToken,
  onGetUser,
  onRefreshSession,
  onApiEcho,
  onClearEntries,
}: DebugPanelProps) {
  const { t } = useI18n()

  return (
    <section className="flex flex-col gap-4">
      <div className="flex items-center gap-2 border-t pt-6">
        <h2 className="text-sm font-semibold text-muted-foreground">
          {t('debug.title')}
        </h2>
        <Badge variant="outline">{t('debug.localOnly')}</Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('debug.actionsTitle')}</CardTitle>
          <CardDescription>{t('debug.actionsDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={onGetUser}
            disabled={pending === 'getUser'}
          >
            <UserRound className="size-4" />
            {t('debug.getUser')}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={onRefreshSession}
            disabled={pending === 'refreshSession'}
          >
            <RefreshCw
              className={cn(
                'size-4',
                pending === 'refreshSession' && 'animate-spin'
              )}
            />
            {t('debug.getSession')}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={onApiEcho}
            disabled={!signedIn || pending === 'apiEcho'}
          >
            {pending === 'apiEcho' ? (
              <RefreshCw className="size-4 animate-spin" />
            ) : (
              <ShieldCheck className="size-4" />
            )}
            {t('debug.apiEcho')}
          </Button>
        </CardContent>
      </Card>

      {accessToken && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Access Token</CardTitle>
            <CardAction>
              <Button variant="ghost" size="sm" onClick={onCopyToken}>
                {copied ? (
                  <Check className="size-4 text-emerald-500" />
                ) : (
                  <Copy className="size-4" />
                )}
                {copied ? t('debug.copied') : t('debug.copy')}
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <pre className="max-h-28 overflow-auto rounded-md bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap text-muted-foreground">
              {accessToken}
            </pre>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('debug.console')}</CardTitle>
          <CardDescription>
            {t('debug.consoleCount', { count: String(entries.length) })}
          </CardDescription>
          <CardAction>
            <Button
              variant="ghost"
              size="icon-sm"
              title={t('debug.clear')}
              onClick={onClearEntries}
              disabled={entries.length === 0}
            >
              <Trash2 className="size-4" />
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent>
          {entries.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              {t('debug.empty')}
            </p>
          ) : (
            <div className="flex max-h-96 flex-col gap-3 overflow-auto">
              {entries.map((entry) => (
                <div key={entry.id} className="rounded-md border bg-muted/50">
                  <div className="flex items-center justify-between gap-2 border-b px-3 py-1.5">
                    <span className="font-mono text-xs font-medium text-foreground">
                      {entry.label}
                    </span>
                    <span className="font-mono text-xs text-muted-foreground">
                      {entry.time}
                    </span>
                  </div>
                  <pre className="max-h-48 overflow-auto p-3 font-mono text-xs break-all whitespace-pre-wrap text-muted-foreground">
                    {JSON.stringify(entry.data, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </section>
  )
}
