# United Pass 前端冻结清单 v1 — 后端交接

- 状态：Frozen
- 日期：2026-08-05
- 适用提交：`35d948b` 及之前的全部前端变更
- 后端语言：Go
- 前端栈：Next.js 16 · React 19 · TypeScript · Semi Design · CSS Modules

本文是前端正式转交后端开发的冻结点。后端可以按照本文和 `docs/api-contracts.md` 的合同逐模块实现，不会再出现"后端写到一半前端换数据模型"的情况。

## 1. 已完成的前端能力

### 1.1 认证流程

| 路由 | 状态 | 说明 |
| --- | --- | --- |
| `/login` | Mock 完成 | 密码登录、MFA 挑战（TOTP / Passkey / 恢复码）、限速、challenge 过期 |
| `/register` | Mock 完成 | 外部用户注册，不预建员工档案 |
| `/forgot-password` | Mock 完成 | 发送重置说明，始终返回通用结果 |
| `/reset-password` | Mock 完成 | 一次性令牌密码重置落地页 |
| `/verify-email` | Mock 完成 | 一次性令牌邮箱验证落地页 |
| `/logout` | Mock 完成 | 撤销当前会话 |
| `/authorize` | Mock 完成 | OAuth 授权同意页，支持未登录跳转登录后恢复事务 |

### 1.2 账户中心

| 路由 | 状态 | 说明 |
| --- | --- | --- |
| `/account` | Mock 完成 | 个人资料编辑、头像上传 |
| `/account/security` | Mock 完成 | 修改密码、TOTP 绑定/删除、Passkey 列表、恢复代码、撤销其他会话 |
| `/account/sessions` | Mock 完成 | 会话列表、撤销单个会话 |
| `/account/applications` | Mock 完成 | 已授权应用列表、撤销授权 |
| `/account/data-export` | P8 真实 API | 重认证、异步生成、owner-bound 15 分钟 JSON 下载 |
| `/account/delete` | P8 真实 API | 重认证、30 天可取消冷静期、durable 删除状态 |

### 1.3 管理端

| 路由 | 状态 | 说明 |
| --- | --- | --- |
| `/admin` | Mock 完成 | 仪表盘、指标、最近事件 |
| `/admin/users` | Mock 完成 | 游标分页列表、搜索 |
| `/admin/users/[userId]` | Mock 完成 | 统一资料、Persona、外部身份关联、活跃会话、授权应用、审计、启用/停用、撤销会话 |
| `/admin/employees` | Mock 完成 | 游标分页列表 |
| `/admin/employees/[userId]` | Mock 完成 | 员工档案、部门、主管、入职/离职确认 |
| `/admin/employees/link` | Mock 完成 | 搜索已有用户、为同一 userId 建立员工档案 |
| `/admin/departments` | Mock 完成 | 部门列表 |
| `/admin/departments/[departmentId]` | Mock 完成 | 树形结构、成员、负责人 |
| `/admin/applications` | Mock 完成 | 游标分页列表 |
| `/admin/applications/new` | Mock 完成 | 原子创建 Application + 初始 Client |
| `/admin/applications/[applicationId]` | Mock 完成 | 应用详情、Client 列表、编辑 |
| `/admin/applications/[applicationId]/clients/[clientId]` | Mock 完成 | 独立 Client 详情、Secret 轮换 |
| `/admin/providers` | P6 real seam | Provider 列表 |
| `/admin/providers/[providerId]` | P6 real seam | 飞书 Provider 详情、异步目录同步、显式冲突处理 |
| `/admin/policies` | P7 真实 API | 策略列表 |
| `/admin/policies/new` | P7 真实 API | ABAC 策略编辑器、乐观锁草稿 |
| `/admin/policies/[policyId]` | P7 真实 API | 策略详情、版本历史、模拟、重认证发布 |
| `/admin/audit` | P7 真实 API | 审计事件服务端筛选、详情、重认证异步导出 |

### 1.4 法律文件

| 路由 | 状态 | 说明 |
| --- | --- | --- |
| `/privacy` | P8 受控发布 | 仅 version + SHA-256 匹配后端审批记录时显示生效日期 |
| `/terms` | P8 受控发布 | 仅 version + SHA-256 匹配后端审批记录时显示生效日期 |

## 2. 架构决策记录（ADR）

| ADR | 标题 | 状态 |
| --- | --- | --- |
| ADR-0001 | 前端路由与页面架构 | Accepted |
| ADR-0002 | Semi Design 设计系统采用 | Accepted |
| ADR-0003 | 暗色模式实现 | Accepted |
| ADR-0004 | API 客户端分层（Server/Browser） | Accepted |
| ADR-0005 | Application 与 OAuth Client 分离 | Accepted |
| ADR-0006 | 前端、API、OAuth endpoints 与 Cookie 部署拓扑 | Accepted |

> **P4.5 Frozen Amendment（2026-08-09；acceptance `194b6d2`）**：Passkey 的真实 browser
> ceremony、多凭据 summary、action/target-bound reauthentication 与 abandoned
> enrollment settlement 由 `backend/docs/adr-0008.md` 统一定义并实现；真实
> ZITADEL 浏览器仪式仍须据实验收。P4.5 不顺带开启密码/TOTP/Session mutation
> 的 P4.7 迁移。

> **P4.7 Frozen Amendment（2026-08-09；implementation `e0dcc47`）**：password、
> TOTP、current-user Session 与 logout 已迁移为 real HTTP seam；runtime parser、
> action-bound reauth、secret lifecycle、authoritative refresh、TOTP abandonment
> settlement 与 admin/current-user 权限隔离按 ADR-0009 冻结。Recovery/profile/
> admin mutation 仍在原边界内；真实 ZITADEL A15 留 P4.9。

## 3. 后端必须实现的 API 合同

完整且唯一的 API 路径清单见 `docs/api-contracts.md`（状态：Frozen v1 — Accepted for backend implementation）。本文不再重复定义全部路径，以避免两份文档漂移。

合同优先级：

1. **`backend/openapi/openapi.yaml`** — 机器可读的唯一合同（建立后以本为准）
2. **`docs/api-contracts.md`** — 人类可读的详细合同（当前规范）
3. **本文（`frontend-freeze-v1.md`）** — 前端交接摘要，不再独立定义 API 路径

以下为各模块的简要说明，详细路径、请求体、响应体和权限标识请查阅 `api-contracts.md`。

| 模块 | 说明 |
| --- | --- |
| 认证与注册 | 密码登录、MFA 挑战、注册、密码重置、邮箱验证、退出登录 |
| 当前账户 | `GET/PATCH /api/v1/me`、头像上传、安全因子、会话管理、已授权应用 |
| OAuth 授权同意 | `GET /api/v1/authorization/requests/{requestId}`、`POST .../decision` |
| OAuth Application / Client | Application 与 Client 分离管理（ADR-0005） |
| 用户与员工 | 员工档案挂在 `userId` 下，不强制使用 `/employees/{userId}` API 路径 |
| 部门 | 树形/分页部门管理 |
| Identity Provider | P6 real seam：飞书登录、Provider 状态、durable sync/history、显式冲突链接；见 ADR-0008 |
| ABAC 策略 | 草稿、发布、模拟、版本历史 |
| 审计 | 事件筛选与异步导出 |

## 4. 关键类型合同

### 4.1 游标分页

```ts
type PageQuery = {
  cursor?: string;
  limit?: number;
  query?: string;
  sort?: string;
  status?: string;
};

type CursorPage<T> = {
  items: T[];
  page: { nextCursor: string | null; hasMore: boolean };
};
```

### 4.2 审计查询

```ts
type AuditQuery = PageQuery & {
  eventType?: string;
  result?: string;
  actorName?: string;
  requestId?: string;
  from?: string;
  to?: string;
};
```

### 4.3 权限能力

```ts
type PermissionCapabilities = {
  userRead: boolean;
  userDisable: boolean;
  employeeManage: boolean;
  employeeOffboard: boolean;
  departmentManage: boolean;
  applicationRead: boolean;
  applicationManage: boolean;
  applicationSecretRotate: boolean;
  policyRead: boolean;
  policyManage: boolean;
  policyPublish: boolean;
  auditRead: boolean;
  auditExport: boolean;
  providerRead: boolean;
  providerManage: boolean;
};
```

### 4.4 错误格式

```json
{
  "error": {
    "code": "session.reauthentication_required",
    "message": "请重新验证身份后继续。",
    "requestId": "req_01...",
    "fieldErrors": [
      { "field": "redirectUris[0]", "message": "该重定向地址未登记。" }
    ]
  }
}
```

`fieldErrors` 使用数组格式。前端 `ApiError` 支持 `network`、`unauthorized`、`forbidden`、`not_found`、`conflict`、`validation`、`rate_limited`、`reauthentication_required`、`server_error`。

### 4.5 Cookie 与 CSRF

```ts
const SESSION_COOKIE_NAME = "up_session";
const CSRF_COOKIE_NAME = "up_csrf";
const CSRF_HEADER_NAME = "X-CSRF-Token";
```

详见 ADR-0006。

## 5. 数据源切换机制

前端使用 `UnitedPassQueries` 和 `UnitedPassCommands` 接口隔离 Mock 与真实 HTTP 实现。

### 当前架构

```text
Server Components
  └── serverQueries (src/lib/api/server/server-queries.ts)
        └── mockUnitedPassDataSource (当前)

Client Components
  └── browserCommands (src/lib/api/browser/browser-commands.ts)
        └── mockUnitedPassDataSource (当前)
```

### 切换到真实后端

在 `server-queries.ts` 中：

```ts
export const serverQueries =
  process.env.USE_MOCK === "true"
    ? mockQueries
    : httpServerQueries;
```

在 `browser-commands.ts` 中同理。

后端每完成一个接口，在前端对应方法中替换 Mock 调用为 HTTP 调用即可逐个切换，不必全量切换。

### HTTP 客户端

- 浏览器端：`browser-http-client.ts`（JSON、FormData、CSRF、AbortSignal、ApiError 归一化）
- 服务端：`server-http-client.ts`（Session Cookie 转发、`cache: no-store`、Request ID 转发、ApiError 归一化）

## 6. 安全约束

前端已强制执行以下安全约束，后端必须独立验证：

1. **不存储令牌**：前端不持久化 Access Token、Refresh Token 或 ID Token
2. **CSRF 防护**：所有写操作必须携带 CSRF Token
3. **重认证**：密钥轮换、策略发布、应用删除、员工离职和会话批量撤销需要重认证
4. **OAuth 安全**：不存储 Client Secret 到前端代码、不禁用 state/nonce/PKCE、不接受任意 Redirect URI
5. **身份关联**：不允许仅凭邮箱静默合并账户
6. **敏感数据**：Client Secret 仅在创建时显示一次，之后不可获取
7. **权限分离**：前端权限检查仅用于 UX，后端必须独立执行 ABAC

## 7. 留到后端阶段实现的内容

以下内容前端已固定页面状态和请求合同，后端实现后即可联调：

- 真实密码校验与哈希
- 真实 TOTP 和 WebAuthn Ceremony
- 真实 OAuth Token 交换
- 通用 Provider 创建/编辑、SCIM/LDAP/SAML/CAS（P6 仅固定飞书 Provider）
- 数据库存储
- CSRF 服务端验证
- ABAC 实际决策引擎
- OpenAPI 生成代码
- 邮件和短信发送
- 头像对象存储
- 审计导出文件生成

## 8. 验证命令

```bash
pnpm lint        # ESLint
pnpm typecheck   # TypeScript 严格模式
pnpm test        # Vitest 单元测试 + Mock 生命周期
pnpm build       # Next.js 生产构建
```

当前状态：全部通过，99 个测试，35 个页面路由。

## 9. 仍需后续跟进的项目

| 项目 | 说明 |
| --- | --- |
| Playwright E2E 测试 | 覆盖登录、授权恢复、应用创建、Client Secret 轮换、权限不足、员工升级等关键链路 |
| ReauthenticationModal | 统一重认证组件（密码/TOTP/Passkey），供密钥轮换、策略发布等复用 |
| 真实 API 逐个切换 | 后端完成一个接口，前端对应方法从 Mock 切换为 HTTP |
| OpenAPI 生成类型 | 后端合同稳定后，使用 OpenAPI 生成 TypeScript 类型和客户端 |
| CI/CD | GitHub Actions 需要 `workflow` scope 权限推送 `.github/workflows/` |

## 10. P4.9 live-closure amendment — 2026-08-09

Frontend real-mode live acceptance is Passed against pinned ZITADEL v2.71.18.
The browser WebAuthn adapter now strictly accepts the provider's single
`{publicKey: ...}` envelope, submits a valid non-empty passkey name, completes
registration/provider readback, and performs passkey step-up target-bound
removal. Password/TOTP/session/logout and `prompt=none` live matrices also
passed. Historical future-work descriptions above are freeze-v1 context, not
the current Phase 4 status.

## 11. P5 identity/workforce amendment — 2026-08-11

The user, employee and department surfaces are now real HTTP seams in
non-Mock mode. Every response is runtime-narrowed before it reaches a page.
User and employee directories use URL-driven server search and signed cursor
pagination; no full directory is loaded for browser filtering. Department
search is server-side and bounded to 100 rows.

The UI implements explicit existing-user employee linking, employee profile
updates, user enable/disable, targeted and bulk session revocation,
offboarding, and department create/update/delete. High-risk operations reuse
the password/TOTP/passkey reauthentication flow with single-use grants bound
to `user.disable`, `user.sessions.revoke`, or `employee.offboard` and the exact
target `userId`. Frontend capability checks remain UX-only; backend checks are
authoritative. The old “Mock 完成” table above is historical freeze context for
these P5 routes.

## 12. P7 policy/audit amendment — 2026-08-11

Policy list/detail/draft/simulation/publication and audit search/export are now
real backend seams in non-Mock mode. Server Component reads stay uncached and
every response is runtime-narrowed. Draft PATCHes carry `expectedVersion`;
publication persists the exact form version and then uses the shared
password/TOTP/passkey reauthentication UI bound to `policy.publish + policyId`.

Audit export uses a grant bound to `audit.export + audit`, receives a durable
202 job, polls boundedly and shows pending/processing/failed/completed states.
Only a completed result exposes the backend same-origin, 15-minute CSV URL.
Frontend capability checks remain UX-only; backend Cerbos and ownership checks
are authoritative.
