# Dondone Auth

基于 Supabase 的统一身份认证服务，部署在 `auth.dondone.dev`。支持邮箱密码、OAuth（GitHub / Google）与 Passkey 登录，通过 PKCE 授权码流程为下游应用签发一次性 code。

## 技术栈

React 19 + TypeScript · Vite · Tailwind CSS v4 + shadcn/ui · Supabase Auth · Cloudflare Pages + KV

## 授权流程

```
业务应用 → 携带 PKCE 参数跳转 auth.dondone.dev
        → 用户登录
        → /api/authorize 签发 120s 一次性 code
        → 跳回业务应用 callback
        → /api/token 兑换 Supabase session
```

## API

| 端点 | 说明 |
|---|---|
| `POST /api/authorize` | 前端调用，校验 Supabase session，返回一次性 code |
| `POST /api/token` | callback 调用，校验 PKCE verifier，兑换 session |
| `GET /api/me` | 验证 Bearer token，返回用户信息 |

## 环境变量

**前端（Vite）**

```
VITE_SUPABASE_URL
VITE_SUPABASE_PUBLISHABLE_KEY
```

**Pages Functions**

```
SUPABASE_URL
SUPABASE_PUBLISHABLE_KEY
AUTH_APPS_JSON   # 注册的业务应用列表，含 client_id 与白名单 redirect_uri
```

**KV Binding**：`AUTH_CODES`

本地开发：Functions 变量写入 `.dev.vars`，前端变量写入 `.env.local`。

## 开发

```bash
pnpm install
pnpm dev          # 仅前端
pnpm pages:dev    # 前端 + Functions
pnpm test
pnpm build
```

## 部署

Cloudflare Pages 连接仓库，build command `pnpm build`，output `dist`，自定义域名 `auth.dondone.dev`，在 Dashboard 配置 Functions 环境变量与 KV binding。
