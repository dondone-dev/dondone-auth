# Simple Auth

基于 Supabase 的个人身份认证服务，作为多个应用的统一登录入口，使用 React + TypeScript + Vite 构建，UI 采用 Tailwind CSS v4 + shadcn/ui。

项目部署为一个 Cloudflare Pages 应用：前端运行在 `auth.dondone.dev/*`，Pages Functions 运行在同域 `auth.dondone.dev/api/*`。登录成功后，本服务不会把 Supabase token 放进 URL，而是生成一个短期一次性授权码，业务应用再用该 code 兑换 session。

## 环境变量

前端构建环境变量：

```bash
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=your-publishable-key
```

Pages Functions 环境变量：

```bash
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_PUBLISHABLE_KEY=your-publishable-key
AUTH_APPS_JSON={"time":{"name":"Time","redirectUris":["https://time.dondone.dev/auth/callback"]}}
```

Cloudflare KV binding：

```txt
AUTH_CODES
```

`AUTH_APPS_JSON` 是业务应用注册表。`client_id` 必须存在，`redirect_uri` 必须和注册值精确匹配。

## 授权码登录流程

作为公共（SPA）客户端，业务应用必须使用 PKCE（仅支持 S256）。把用户引导到 SimpleAuth 时带上 `code_challenge`：

```txt
https://auth.dondone.dev/?client_id=time&redirect_uri=https%3A%2F%2Ftime.dondone.dev%2Fauth%2Fcallback&state=<random>&code_challenge=<challenge>&code_challenge_method=S256
```

流程：

```txt
1. time 生成随机 state 与 code_verifier，计算 code_challenge = base64url(sha256(code_verifier))
2. time 跳转到 SimpleAuth，带上 client_id、redirect_uri、state、code_challenge
3. 用户在 SimpleAuth 登录 Supabase
4. SimpleAuth 调用 /api/authorize 生成 120 秒有效的一次性 code（绑定 code_challenge）
5. SimpleAuth 跳回 https://time.dondone.dev/auth/callback?code=...&state=...
6. time callback 校验 state，带上 code_verifier 调用 https://auth.dondone.dev/api/token 兑换 session
7. time 调用 supabase.auth.setSession() 建立自己的登录态
```

业务应用发起登录示例：

```ts
function base64Url(bytes: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

const state = base64Url(crypto.getRandomValues(new Uint8Array(16)).buffer)
const codeVerifier = base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer)
const codeChallenge = base64Url(
  await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))
)

sessionStorage.setItem('simple_auth_state', state)
sessionStorage.setItem('simple_auth_verifier', codeVerifier)

const url = new URL('https://auth.dondone.dev/')
url.searchParams.set('client_id', 'time')
url.searchParams.set('redirect_uri', 'https://time.dondone.dev/auth/callback')
url.searchParams.set('state', state)
url.searchParams.set('code_challenge', codeChallenge)
url.searchParams.set('code_challenge_method', 'S256')
window.location.href = url.toString()
```

业务应用 callback 示例：

```ts
const params = new URLSearchParams(window.location.search)
const code = params.get('code')
const state = params.get('state')

if (state !== sessionStorage.getItem('simple_auth_state')) {
  throw new Error('Invalid auth state')
}

const response = await fetch('https://auth.dondone.dev/api/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    client_id: 'time',
    redirect_uri: 'https://time.dondone.dev/auth/callback',
    code,
    code_verifier: sessionStorage.getItem('simple_auth_verifier'),
  }),
})

if (!response.ok) throw new Error('Token exchange failed')

const session = await response.json()
await supabase.auth.setSession({
  access_token: session.access_token,
  refresh_token: session.refresh_token,
})
```

## API

### `POST /api/authorize`

由 SimpleAuth 前端调用。校验业务应用、回调地址和当前 Supabase access token，生成一次性 code。

```json
{
  "client_id": "time",
  "redirect_uri": "https://time.dondone.dev/auth/callback",
  "state": "random-state",
  "code_challenge": "base64url-sha256-of-verifier",
  "code_challenge_method": "S256",
  "access_token": "supabase-access-token",
  "refresh_token": "supabase-refresh-token",
  "expires_at": 1234567890,
  "token_type": "bearer"
}
```

### `POST /api/token`

由业务应用 callback 调用。校验 `code_verifier` 与发起时的 `code_challenge` 是否匹配；兑换成功后 code 会立即失效。

```json
{
  "client_id": "time",
  "redirect_uri": "https://time.dondone.dev/auth/callback",
  "code": "one-time-code",
  "code_verifier": "the-original-code-verifier"
}
```

### `GET /api/me`

读取 `Authorization: Bearer <access_token>`，用 Supabase 验证并返回最小用户信息。

## Cloudflare 部署

1. 在 Cloudflare Pages 连接本仓库。
2. Build command: `pnpm build`
3. Build output directory: `dist`
4. Custom domain: `auth.dondone.dev`
5. 在 Pages project 中配置 Functions 环境变量和 `AUTH_CODES` KV binding。

`functions/api/*.ts` 会由 Cloudflare Pages Functions 自动映射到同域 `/api/*`，不需要单独配置 Worker route。

## 本地开发

```bash
pnpm install
pnpm dev        # 仅启动 Vite 前端
pnpm pages:dev  # 构建并启动 Pages + Functions
pnpm test
pnpm build
pnpm lint
```

本地运行 Pages Functions 时，把 Functions 环境变量放到 `.dev.vars`，前端变量放到 `.env.local`。

## 技术栈

- React 19 + TypeScript
- Vite
- Supabase Auth (`@supabase/supabase-js`)
- Cloudflare Pages Functions + KV
- Tailwind CSS v4 + shadcn/ui
