# United Pass Frontend

United Pass 的 Next.js 前端，覆盖统一账户、OAuth 2.0 / OpenID Connect 授权、账户安全与管理后台的初始化框架。

## 技术栈

- Next.js 16.3（App Router）
- React 19
- TypeScript（strict）
- Semi Design
- CSS Modules / CSS variables
- pnpm 10

## 本地运行

```bash
pnpm install
pnpm dev
```

打开 [http://localhost:3000](http://localhost:3000)。根路径会跳转到 `/login`。

## 当前路由

- `/login`、`/register`、`/authorize`
- `/account`、`/account/security`、`/account/sessions`
- `/admin`、`/admin/users`、`/admin/employees`、`/admin/departments`
- `/admin/applications`、`/admin/policies`、`/admin/audit`

## Mock 状态

当前数据来自 `src/lib/mock/united-pass-data-source.ts`，仅用于界面与领域模型验证。登录、授权和管理操作不会调用后端，也不会持久化。

界面支持亮色与暗色模式。首次访问默认跟随系统偏好，用户通过主题按钮选择后会在浏览器本地保存偏好。

- [Mock 数据说明](./docs/mock-data.md)
- [待接入 API 清单](./docs/api-contracts.md)
- [ADR-0001：路由、服务端边界与数据源](./docs/adr-0001.md)

## 质量检查

```bash
pnpm lint
pnpm build
```

真实 API 接入前，需要完成服务端会话、OIDC 安全校验、后端 ABAC 强制执行、重认证、错误归一化和 OpenAPI 合同生成。
