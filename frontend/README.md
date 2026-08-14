# 砾石进化统一登录门户平台 Frontend

这是 United Pass 的 Next.js 前端，负责统一登录、OAuth 授权交互、账户自助和管理
控制台。浏览器界面使用正式中文名称；`UnitedPass` 等标识保留为内部类型和代码命名。

项目总体状态、Phase 边界和后端启动方式见 [仓库根 README](../README.md)。

## 技术栈

- Next.js 16.3（App Router、Server Components）
- React 19.2
- TypeScript strict
- Semi Design 2.x
- CSS Modules / CSS variables
- Node.js 24.x、pnpm 10.x
- Vitest、Playwright

## 运行模式

数据访问分为两个显式层次：

- Server Components 通过 `serverQueries` 读取数据；服务端转发 HttpOnly
  `up_session`，并固定使用 `cache: no-store`。
- Client Components 通过 `browserCommands` / 专用登录命令执行写操作；请求同源
  `/api/v1`，自动携带 credentials，并在写请求附加 `X-CSRF-Token`。

`NEXT_PUBLIC_USE_MOCK` 是唯一的数据源总开关：

| 值 | 行为 |
| --- | --- |
| `true` | 所有 seam 使用固定 Mock，适合组件开发、单元测试和 fixture 演示 |
| 未设置或非 `true` | 已迁移 seam 调用真实后端；未迁移 seam 继续显式使用 Mock |

这个开关会进入浏览器 bundle，只能保存布尔配置，绝不能放入秘密。Next.js 服务端
使用 `API_BASE_URL` 直连 Go API，默认值为 `http://localhost:8080/api/v1`；浏览器
始终使用同源 `/api/v1`。

## 当前真实 API 范围

非 Mock 模式已经接入：

- 密码登录、TOTP MFA、飞书登录入口、退出；
- 当前用户、权限、OAuth 授权/Consent、已授权应用和撤销；
- 密码修改、TOTP、Passkey、重认证、当前用户会话及撤销；
- 用户、员工、部门的查询和管理操作；
- Provider 列表/详情、目录同步、冲突处理与显式身份关联；
- 策略草稿/模拟/发布、审计筛选与异步导出；
- 个人数据导出、账户删除/取消，以及受控发布的隐私政策和服务条款。

以下前端 seam 仍是 Mock 或产品原型，刷新后不代表真实持久化：

- 注册、密码找回/重置、邮箱验证；
- 个人资料、头像、邮箱和手机号变更；
- 管理端仪表盘摘要；
- OAuth Application / Client 的前端查询与增删改、Secret 轮换；
- Recovery Codes（后端架构性 Deferred）。

后端已经具有部分对应管理 API，并不意味着前端 seam 已迁移。以
`src/lib/api/server/server-queries.ts` 和
`src/lib/api/browser/browser-commands.ts` 的实际分支为准。

## 登录态行为

- Session Cookie 名为 `up_session`，HttpOnly；CSRF Cookie 名为 `up_csrf`。
- 已登录用户访问 `/login` 时，Server Component 会调用后端 `/me` 校验会话；有效
  会话自动跳转 `/account`。
- `/login?requestId=...` 遇到有效会话会继续
  `/authorize?requestId=...`，不会丢失 OAuth 事务。
- 只有后端明确返回 401 才把已有 Cookie 当作过期/撤销并显示登录页；网络、解析和
  其他后端失败不会被静默伪装成匿名状态。
- `/admin/*` 在 React 渲染前调用 `/me/permissions`；未登录跳转 `/login`，无管理
  capability 跳转 `/account`，上游或响应异常返回 503。每个管理 API 仍由后端独立
  强制授权。

默认会话绝对 TTL 为 12 小时，“记住登录状态”为 30 天，空闲 TTL 为 2 小时；这些
值由后端配置决定。两种会话当前都是带 Max-Age 的 Cookie，不应描述为“关闭浏览器
立即失效”。

## 路由

### 公开与认证

- `/login`、`/logout`
- `/register`、`/forgot-password`、`/reset-password`、`/verify-email`
- `/authorize`
- `/privacy`、`/terms`

### 账户中心

- `/account`
- `/account/security`
- `/account/sessions`
- `/account/applications`
- `/account/data-export`
- `/account/delete`

### 管理控制台

- `/admin`
- `/admin/users`、`/admin/users/[userId]`
- `/admin/employees`、`/admin/employees/[userId]`、`/admin/employees/link`
- `/admin/departments`、`/admin/departments/[departmentId]`
- `/admin/providers`、`/admin/providers/[providerId]`
- `/admin/applications`、`/admin/applications/new`
- `/admin/applications/[applicationId]`
- `/admin/applications/[applicationId]/clients/[clientId]`
- `/admin/policies`、`/admin/policies/new`、`/admin/policies/[policyId]`
- `/admin/audit`

## 本地运行

```bash
fnm use 24.17.0
pnpm install --frozen-lockfile
cp .env.example .env.local
pnpm dev
```

打开 [http://localhost:3000](http://localhost:3000)，根路径会跳转 `/login`。
已有 `.env.local` 时不要用示例文件覆盖它。

Mock 配置：

```dotenv
NEXT_PUBLIC_USE_MOCK=true
API_BASE_URL=http://localhost:8080/api/v1
```

Mock 登录 fixture（只用于开发，不是秘密，也不得复用为真实密码）：

| Persona | 账户 | 密码 | 目标页 |
| --- | --- | --- | --- |
| 外部用户 | `app.user` | `MockUser123!` | `/account` |
| 管理员 | `zhixing.lin` | `MockAdmin123!` | `/admin` |

受保护页面仍执行服务端 Cookie/权限门禁；Mock fixture 不能替代真实同源 Session 和
权限验收。

## 完整联调与部署拓扑

浏览器 API 固定为 `/api/v1`，`next.config.ts` 不提供开发 rewrite。完整流程必须经
同源反向代理运行：

| Public path | Owner |
| --- | --- |
| `/api/v1/*`、`/_interaction/*` | Go backend |
| `/oauth/v2/*`、`/oidc/v1/*`、`/.well-known/openid-configuration` | ZITADEL |
| 其余路径 | Next.js |

生产必须使用 HTTPS 和 Secure Cookie。OAuth path ownership、公开 issuer、旧 Client
backfill 以及切流顺序见
[backend topology runbook](../backend/docs/topology-runbook.md)。

## 质量检查

本地要求 Node.js 24.x 和 pnpm 10.x。前端有修改时执行完整门禁：

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

可选的 Mock 浏览器套件：

```bash
pnpm test:e2e
```

Vitest 使用 Node 环境，测试覆盖 API 错误归一化、响应运行时收窄、CSRF、登录/MFA、
OAuth 决策、安全因子、WebAuthn 序列化、组织管理、Provider、策略、审计、隐私、
账户删除和权限门禁。GitHub Actions 因组织额度耗尽当前不作为门禁；本地结果为准。

## 代码边界

- `src/app/`：路由、布局和 Server Component 组合
- `src/features/`：按业务域组织的 UI、类型和流程
- `src/lib/api/server/`：服务端查询、Session Cookie 转发和运行时校验
- `src/lib/api/browser/`：同源浏览器命令、CSRF 和错误归一化
- `src/lib/mock/`：显式 fixture 数据源，不得被真实 seam 静默 fallback
- `src/proxy.ts`：管理路由 pre-render 权限门禁
- `docs/`：前端 ADR、冻结合同和 Mock 说明

任何用户专属 Server fetch 必须 `cache: no-store`；任何写请求必须经共享浏览器客户端
携带 CSRF；重认证 token 只允许通过受约束参数进入专用 header，不能暴露通用 header
逃生口。

## 文档

- [前端冻结清单](docs/frontend-freeze-v1.md)
- [API 合同](docs/api-contracts.md)
- [Mock 数据说明](docs/mock-data.md)
- [ADR-0004：API 客户端、会话与错误边界](docs/adr-0004.md)
- [ADR-0007：Phase 5 身份与员工管理真实 seam](docs/adr-0007.md)
- [ADR-0008：Phase 6 Feishu Provider](docs/adr-0008.md)
- [ADR-0009：Phase 7 策略与审计](docs/adr-0009.md)
- [Backend README](../backend/README.md)
