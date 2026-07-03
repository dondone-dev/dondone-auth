# Dondone Auth

[English](./README.md)

基于 Supabase 的统一身份认证服务，部署在 `auth.dondone.dev`。支持邮箱密码、OAuth（GitHub / Google）与 Passkey 登录，通过 PKCE 授权码流程为下游应用签发一次性 code，并为 `api.dondone.dev` 签发短期 Dondone API JWT。

## 技术栈

React 19 + TypeScript · Vite · Tailwind CSS v4 + shadcn/ui · Supabase Auth · Cloudflare Pages + KV

## 授权流程

```
业务应用 → 携带 PKCE 参数跳转 auth.dondone.dev
        → 用户登录
        → /api/authorize 签发 120s 一次性 code
        → 跳回业务应用 callback
        → /api/token 兑换 Supabase session + Dondone API token
        → 业务应用用 Dondone API token 调用 api.dondone.dev
```

## API

| 端点 | 说明 |
|---|---|
| `POST /api/authorize` | 前端调用，校验 Supabase session，返回一次性 code |
| `POST /api/token` | callback 调用，校验 PKCE verifier，兑换 Supabase session 与 Dondone API token |
| `POST /api/api-token` | 用 Supabase Bearer token 换取短期 Dondone API token |
| `GET /api/jwks` | 发布 Dondone API JWT 公钥 |
| `GET /api/me` | 验证 Bearer token，返回用户信息 |

## 环境变量

**前端（Vite）**

```
VITE_SUPABASE_URL
VITE_SUPABASE_PUBLISHABLE_KEY
VITE_API_BASE
```

**Pages Functions**

```
SUPABASE_URL
SUPABASE_PUBLISHABLE_KEY
AUTH_APPS_JSON   # 注册的业务应用列表，含 client_id 与白名单 redirect_uri
DONDONE_JWT_PRIVATE_JWK   # ES256 private JWK，使用 Cloudflare secret 配置
DONDONE_JWT_KID
DONDONE_JWT_ISSUER
DONDONE_API_AUDIENCE
```

**KV Binding**：`AUTH_CODES`

**SQL**：部署授权能力前，先在 Supabase SQL editor 手动执行 `docs/sql/authorization.sql`。

生成 ES256 private JWK 并写入 Cloudflare Pages secret：

```bash
node -e "crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']).then(k=>crypto.subtle.exportKey('jwk',k.privateKey)).then(jwk=>console.log(JSON.stringify(jwk)))" | pnpm wrangler pages secret put DONDONE_JWT_PRIVATE_JWK --project-name supabase-simple-auth
```

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
