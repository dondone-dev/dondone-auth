# Simple Auth

基于 Supabase 的个人身份认证服务，使用 React + TypeScript + Vite 构建，UI 采用 Tailwind CSS v4 + shadcn/ui。

支持邮箱密码注册、登录、退出，获取用户信息与查看当前 Session / JWT。

## 环境变量

在 `.env.local` 中配置：

```bash
VITE_SUPABASE_URL=你的 Supabase 项目 URL
VITE_SUPABASE_PUBLISHABLE_KEY=你的 Supabase publishable key
```

## 本地开发

```bash
pnpm install
pnpm dev      # 启动开发服务器
pnpm build    # 类型检查 + 生产构建
pnpm lint     # 代码检查
```

## 技术栈

- React 19 + TypeScript
- Vite
- Supabase Auth (`@supabase/supabase-js`)
- Tailwind CSS v4 + shadcn/ui（组件源码位于 `src/components/ui/`）
