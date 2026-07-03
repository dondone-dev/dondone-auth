/* eslint-disable react-refresh/only-export-components */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

export type Lang = 'zh' | 'en'

const dictionaries = {
  zh: {
    'app.title': 'dondone · 统一身份认证',
    'brand.tagline': '统一身份认证服务',

    'auth.heading': '登录 dondone',
    'tabs.signIn': '登录',
    'tabs.signUp': '注册',
    'field.email': '邮箱',
    'field.password': '密码',
    'action.signIn': '登录',
    'action.signUp': '创建账户',
    'divider.or': '或使用以下方式',
    'action.passkey': '使用 Passkey 登录',

    'authz.willReturn': '登录后将返回 {origin}',
    'authz.invalid':
      '授权请求参数不完整或回调地址无效，已忽略。请检查 client_id、redirect_uri 与 state。',
    'authz.continueTitle': '继续登录',
    'authz.continueDescWithEmail': '你已登录为 {email}，可直接返回应用。',
    'authz.continueDesc': '你已登录，可直接返回应用。',
    'authz.continueAction': '继续并返回 {origin}',
    'authz.failed': '授权失败：{message}',
    'authz.noSession': '当前没有有效会话。',

    'signin.failed': '登录失败：{message}',
    'signup.failed': '注册失败：{message}',
    'signup.successAuto': '注册成功，已自动登录。',
    'signup.successVerify': '注册成功，请前往邮箱完成验证后再登录。',
    'passkey.signInFailed': 'Passkey 登录失败：{message}',
    'passkey.enrollSuccess': 'Passkey 绑定成功。',
    'passkey.enrollFailed': 'Passkey 绑定失败：{message}',
    'session.refreshed': '会话已刷新。',
    'session.refreshFailed': '刷新会话失败：{message}',
    'signout.done': '已退出登录。',
    'signout.failed': '退出失败：{message}',
    'apiEcho.failed': 'API Echo 失败：{message}',

    'account.signedIn': '已登录',
    'account.infoTitle': '账户信息',
    'account.email': '邮箱',
    'account.userId': '用户 ID',
    'account.provider': '登录方式',
    'account.expires': '会话到期',
    'account.refresh': '刷新会话',
    'security.title': '安全',
    'security.passkeyDesc': '使用面容、指纹或安全密钥免密码登录',
    'security.enrollPasskey': '绑定 Passkey',
    'action.signOut': '退出登录',

    'debug.title': '调试',
    'debug.localOnly': '仅本地可见',
    'debug.actionsTitle': '调试操作',
    'debug.actionsDesc': '直接调用底层接口，原始响应会输出到下方控制台',
    'debug.getUser': '获取用户信息',
    'debug.getSession': '获取 Session / JWT',
    'debug.apiEcho': 'API Echo 验证',
    'debug.copy': '复制',
    'debug.copied': '已复制',
    'debug.console': '控制台',
    'debug.consoleCount': '最近 {count} 条原始响应',
    'debug.clear': '清空控制台',
    'debug.empty': '暂无输出，执行操作后这里会显示原始响应。',
    'debug.toggle': '调试模式',
    'theme.toDark': '切换到深色',
    'theme.toLight': '切换到浅色',
  },
  en: {
    'app.title': 'dondone · Sign in',
    'brand.tagline': 'Unified identity service',

    'auth.heading': 'Sign in to dondone',
    'tabs.signIn': 'Sign in',
    'tabs.signUp': 'Sign up',
    'field.email': 'Email',
    'field.password': 'Password',
    'action.signIn': 'Sign in',
    'action.signUp': 'Create account',
    'divider.or': 'or continue with',
    'action.passkey': 'Sign in with a passkey',

    'authz.willReturn': "After signing in you'll return to {origin}",
    'authz.invalid':
      'The authorization request is incomplete or its callback URL is invalid, so it was ignored. Check client_id, redirect_uri and state.',
    'authz.continueTitle': 'Continue signing in',
    'authz.continueDescWithEmail':
      "You're signed in as {email}. You can head straight back to the app.",
    'authz.continueDesc':
      "You're signed in. You can head straight back to the app.",
    'authz.continueAction': 'Continue to {origin}',
    'authz.failed': 'Authorization failed: {message}',
    'authz.noSession': 'No active session.',

    'signin.failed': 'Sign-in failed: {message}',
    'signup.failed': 'Sign-up failed: {message}',
    'signup.successAuto': "Account created — you're signed in.",
    'signup.successVerify':
      'Account created. Verify your email before signing in.',
    'passkey.signInFailed': 'Passkey sign-in failed: {message}',
    'passkey.enrollSuccess': 'Passkey registered.',
    'passkey.enrollFailed': 'Passkey registration failed: {message}',
    'session.refreshed': 'Session refreshed.',
    'session.refreshFailed': 'Failed to refresh session: {message}',
    'signout.done': 'Signed out.',
    'signout.failed': 'Sign-out failed: {message}',
    'apiEcho.failed': 'API Echo failed: {message}',

    'account.signedIn': 'Signed in',
    'account.infoTitle': 'Account',
    'account.email': 'Email',
    'account.userId': 'User ID',
    'account.provider': 'Sign-in method',
    'account.expires': 'Session expires',
    'account.refresh': 'Refresh session',
    'security.title': 'Security',
    'security.passkeyDesc':
      'Sign in without a password using Face ID, fingerprint, or a security key',
    'security.enrollPasskey': 'Add passkey',
    'action.signOut': 'Sign out',

    'debug.title': 'Debug',
    'debug.localOnly': 'Local only',
    'debug.actionsTitle': 'Debug actions',
    'debug.actionsDesc':
      'Call the underlying APIs directly; raw responses appear in the console below',
    'debug.getUser': 'Get user',
    'debug.getSession': 'Get session / JWT',
    'debug.apiEcho': 'API Echo',
    'debug.copy': 'Copy',
    'debug.copied': 'Copied',
    'debug.console': 'Console',
    'debug.consoleCount': 'Recent raw responses ({count})',
    'debug.clear': 'Clear console',
    'debug.empty':
      'Nothing yet — raw responses will appear here after you run an action.',
    'debug.toggle': 'Debug mode',
    'theme.toDark': 'Switch to dark',
    'theme.toLight': 'Switch to light',
  },
} as const satisfies Record<Lang, Record<string, string>>

export type MessageKey = keyof (typeof dictionaries)['zh']

export type Translate = (
  key: MessageKey,
  params?: Record<string, string>
) => string

interface I18nContextValue {
  lang: Lang
  locale: string
  setLang: (lang: Lang) => void
  t: Translate
}

const STORAGE_KEY = 'dondone.lang'

function initialLang(): Lang {
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored === 'zh' || stored === 'en') return stored
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'
}

const I18nContext = createContext<I18nContextValue | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang>(initialLang)

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, lang)
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en'
    document.title = dictionaries[lang]['app.title']
  }, [lang])

  const t = useCallback<Translate>(
    (key, params) => {
      let text: string = dictionaries[lang][key]
      if (params) {
        for (const [name, value] of Object.entries(params)) {
          text = text.replace(`{${name}}`, value)
        }
      }
      return text
    },
    [lang]
  )

  const value = useMemo<I18nContextValue>(
    () => ({
      lang,
      locale: lang === 'zh' ? 'zh-CN' : 'en-US',
      setLang,
      t,
    }),
    [lang, t]
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18nContextValue {
  const context = useContext(I18nContext)
  if (!context) throw new Error('useI18n must be used within I18nProvider')
  return context
}
