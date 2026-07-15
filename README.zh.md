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
| `POST /api/authorize` | 前端调用，校验 Supabase session；必须提供已注册的 `resource` 和非空已审批 `scope`，并将其绑定到一次性 code |
| `POST /api/token` | callback 调用并校验 PKCE，签发 resource-bound `at+jwt`；若提供 resource 必须与 code 一致，scope 只能缩减且不可为空，省略时保留 code 绑定的 scope |
| `POST /api/api-token` | 用 Supabase Bearer token 换取单一 resource 的 `at+jwt`；必须显式传非空 resource 和 scope，不会默认授予全部目录 scope |
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

```sh
SUPABASE_URL
SUPABASE_PUBLISHABLE_KEY
SUPABASE_SERVICE_ROLE_KEY   # Secret；仅供 capability 管理 RPC 使用
DONDONE_JWT_PRIVATE_JWK   # ES256 private JWK，使用 Cloudflare secret 配置
DONDONE_JWT_KID
DONDONE_JWT_ISSUER
ADMIN_ALLOWED_ORIGINS   # 允许调用 /api/admin/* 的浏览器 Origin，逗号分隔
```

OAuth 客户端与 redirect URI 始终从 Dondone Console 管理的 Supabase `public.oauth_client_registry` 视图读取。注册表故障时请求会 fail-closed，不再提供静态注册表 fallback。

`SUPABASE_SERVICE_ROLE_KEY` 必须通过 Cloudflare Secret 配置，仅用于 capability 同步、审批、拒绝和审计的事务 RPC。资源 Token 热路径使用 publishable key 查询受限的 `active_resource_capabilities` 视图，不会向 anon 开放完整 `services` 表。

`/api/authorize`、`/api/token` 与 `/api/api-token` 始终要求已审批的 resource 和非空 scope，并只签发 audience-bound `at+jwt`。旧的无资源授权码和固定 audience JWT 会被拒绝。

`ADMIN_ALLOWED_ORIGINS` 至少应包含 `https://console.dondone.dev`；未列出的 Origin 不会获得管理 API 的 CORS 响应头。

**KV Binding**：`AUTH_CODES`

**SQL 迁移顺序**：

1. `docs/sql/authorization.sql`
2. `docs/sql/migrations/20260713_add_service_redirect_uris.sql`
3. `docs/sql/migrations/20260714_add_service_capability_registry.sql`
4. 发布、同步、审核并批准 API capability manifest
5. `docs/sql/migrations/20260714_migrate_seed_permissions_to_capabilities.sql`（保留现有 grant，并将 `tier:vip` 迁移为 `api:tier:vip`）

生成 ES256 private JWK 并写入 Cloudflare Pages secret：

```bash
node -e "crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']).then(k=>crypto.subtle.exportKey('jwk',k.privateKey)).then(jwk=>console.log(JSON.stringify(jwk)))" | pnpm wrangler pages secret put DONDONE_JWT_PRIVATE_JWK --project-name dondone-auth
```

如果已经有现成的 private JWK 值（例如恢复已有密钥），也可以通过管道直接写入，例如：

```bash
echo '{"kty":"EC","crv":"P-256","x":"...","y":"...","d":"..."}' | pnpm wrangler pages secret put DONDONE_JWT_PRIVATE_JWK --project-name dondone-auth
```

`d` 字段就是私钥本身，只应通过 `wrangler pages secret put` 写入，不要提交到仓库、不要打印到 CI 日志。

本地开发：Functions 变量写入 `.dev.vars`，前端变量写入 `.env.local`。

## 开发

```bash
pnpm install
pnpm dev          # 仅前端
pnpm pages:dev    # 前端 + Functions
pnpm test
pnpm test:postgres # 独立 Docker/PostgreSQL 15 迁移与 RPC 集成测试
pnpm build
```

## 部署

Cloudflare Pages 连接仓库，build command `pnpm build`，output `dist`，自定义域名 `auth.dondone.dev`，在 Dashboard 配置 Functions 环境变量与 KV binding。
