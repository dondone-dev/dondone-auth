import { Languages, Moon, Sun, Terminal } from 'lucide-react'
import { useI18n } from '@/lib/i18n'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'

interface PageFooterProps {
  debugMode: boolean
  onToggleDebug: () => void
  theme: 'light' | 'dark'
  onToggleTheme: () => void
}

export function PageFooter({
  debugMode,
  onToggleDebug,
  theme,
  onToggleTheme,
}: PageFooterProps) {
  const { lang, setLang, t } = useI18n()

  return (
    <footer className="py-8">
      <div className="mx-auto flex items-center justify-center gap-1 px-4 text-xs text-muted-foreground">
        <Button
          variant="ghost"
          size="xs"
          onClick={() => setLang(lang === 'zh' ? 'en' : 'zh')}
          className="font-normal text-muted-foreground"
        >
          <Languages className="size-3" />
          {lang === 'zh' ? 'English' : '中文'}
        </Button>
        <Button
          variant="ghost"
          size="icon-xs"
          title={theme === 'dark' ? t('theme.toLight') : t('theme.toDark')}
          onClick={onToggleTheme}
          className="text-muted-foreground"
        >
          {theme === 'dark' ? (
            <Sun className="size-3" />
          ) : (
            <Moon className="size-3" />
          )}
        </Button>
        <Button
          variant="ghost"
          size="icon-xs"
          title={t('debug.toggle')}
          aria-pressed={debugMode}
          onClick={onToggleDebug}
          className={cn(
            'text-muted-foreground',
            debugMode &&
              'bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary'
          )}
        >
          <Terminal className="size-3" />
        </Button>
        <span className="mx-2 h-3 w-px bg-border" />
        <span>dondone · {t('brand.tagline')}</span>
      </div>
    </footer>
  )
}
