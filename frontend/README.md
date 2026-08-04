# 砾石进化统一登陆门户平台 Frontend

砾石进化统一登陆门户平台的 Next.js 前端，覆盖统一账户、OAuth 2.0 / OpenID Connect 授权、账户安全与管理后台的初始化框架。代码中的部分 `UnitedPass` 标识保留为内部技术命名，用户界面统一使用正式系统名称。

## 技术栈

- Next.js 16.3（App Router）
- React 19
- Node.js 24
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

- `/login`、`/register`、`/forgot-password`、`/authorize`、`/privacy`、`/terms`
- `/account`、`/account/security`、`/account/sessions`
- `/admin`、`/admin/users`、`/admin/employees`、`/admin/departments`
- `/admin/providers`、`/admin/applications`、`/admin/policies`、`/admin/audit`

## Mock 状态

当前数据来自 `src/lib/mock/united-pass-data-source.ts`，仅用于界面与领域模型验证。登录、注册、密码找回、授权和管理操作不会调用后端，也不会持久化。普通用户演示可使用账户名 `app.user`（或邮箱 `app.user@example.com`）和密码 `MockUser123!`；员工管理演示凭据见 Mock 数据说明。

账户中心支持显示名称、昵称、安全校验后的本地头像上传，以及经过固定验证码 `246810` 验证后的邮箱和手机号页面内修改；所有结果刷新后恢复。管理后台包含 Provider 清单，飞书接入当前仅标记为规划中。

界面支持亮色与暗色模式。首次访问默认跟随系统偏好，用户通过主题按钮选择后会在浏览器本地保存偏好。

品牌名称与 Logo 由 `src/lib/branding.ts` 和 `public/brand/gravel-evolution-logo.png` 统一维护。隐私政策与服务条款为仓库内固定静态文本，不依赖 API 或用户数据。

- [Mock 数据说明](./docs/mock-data.md)
- [待接入 API 清单](./docs/api-contracts.md)
- [ADR-0001：路由、服务端边界与数据源](./docs/adr-0001.md)
- [ADR-0002：Identity Provider 管理边界与飞书规划](./docs/adr-0002.md)
- [ADR-0003：头像上传校验与安全预览](./docs/adr-0003.md)

## 质量检查

```bash
pnpm lint
pnpm typecheck
pnpm build
```

本地运行要求 Node.js 24.x 与 pnpm 10.x；`package.json` 的 `engines` 字段是安装和 CI 的版本边界。

当前尚未引入测试运行器。Mock 流程稳定后优先覆盖登录凭据匹配、头像文件头与尺寸校验、邮箱与手机号验证、管理列表查询投影，以及 Persona / 员工状态展示；在此之前 `typecheck`、`lint` 与生产构建均为必跑检查。

真实 API 接入前，需要完成服务端会话、OIDC 安全校验、后端 ABAC 强制执行、重认证、错误归一化和 OpenAPI 合同生成。
