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
| `/login` | 真实 API | 密码登录、TOTP / Passkey MFA、同源保护、限速、challenge 过期；Recovery Codes Deferred |
| `/register` | 真实 API | Provider 创建外部用户、稳定本地 `userId`、邮箱验证前保持 pending |
| `/forgot-password` | 真实 API | 抗账户枚举的通用 202 与 Provider 重置通知 |
| `/reset-password` | 真实 API | 加密生命周期令牌 + Provider code；成功后旧安全 epoch 会话失效 |
| `/verify-email` | 真实 API | Provider code 验证与 pending 账户原子激活 |
| `/logout` | 真实 API | 撤销当前会话并清理 Cookie |
| `/authorize` | 真实 API | OAuth 授权同意页，支持未登录跳转登录后恢复事务 |

### 1.2 账户中心

| 路由 | 状态 | 说明 |
| --- | --- | --- |
| `/account` | 真实 API | 个人资料、服务端净化头像、Provider 验证邮箱/手机号 |
| `/account/security` | 真实 API | 修改密码、TOTP、Passkey、撤销其他会话；Recovery Codes 明确 Deferred |
| `/account/sessions` | 真实 API | 会话列表、撤销单个会话 |
| `/account/applications` | 真实 API | 已授权应用列表、撤销授权 |
| `/account/data-export` | P8 真实 API | 重认证、异步生成、owner-bound 15 分钟 JSON 下载 |
| `/account/delete` | P8 真实 API | 重认证、30 天可取消冷静期、durable 删除状态 |

### 1.3 管理端

| 路由 | 状态 | 说明 |
| --- | --- | --- |
| `/admin` | 真实 API | 按 `user.read` / `application.read` / `audit.read` 独立裁剪指标与最近事件 |
| `/admin/users` | 真实 API | 服务端游标分页与搜索 |
| `/admin/users/[userId]` | 真实 API | 统一资料、Persona、外部身份、会话、授权、审计与生命周期操作 |
| `/admin/employees` | 真实 API | 服务端游标分页 |
| `/admin/employees/[userId]` | 真实 API | 员工档案、部门、主管、入职/离职确认 |
| `/admin/employees/link` | 真实 API | 搜索已有用户、为同一 `userId` 建立员工档案 |
| `/admin/departments` | 真实 API | 部门列表与变更 |
| `/admin/departments/[departmentId]` | 真实 API | 树形结构、成员、负责人 |
| `/admin/applications` | 真实 API | 服务端游标分页列表 |
| `/admin/applications/new` | 真实 API | 原子创建 Application + 初始 Client |
| `/admin/applications/[applicationId]` | 真实 API | 应用详情、Client 列表、编辑与状态变更 |
| `/admin/applications/[applicationId]/clients/[clientId]` | 真实 API | Client 详情、更新、状态、删除与 Secret 轮换 |
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

前端使用 `UnitedPassQueries` 和 `UnitedPassCommands` 接口隔离显式开发 fixture 与真实
HTTP 实现。生产默认值为 real；不存在“接口尚未迁移时静默回落 Mock”的分支。

### 当前架构

```text
Server Components
  └── serverQueries (src/lib/api/server/server-queries.ts)
        ├── NEXT_PUBLIC_USE_MOCK=true → mockUnitedPassDataSource（显式 fixture）
        └── otherwise                → same-origin real HTTP

Client Components
  └── browserCommands (src/lib/api/browser/browser-commands.ts)
        ├── NEXT_PUBLIC_USE_MOCK=true → mockUnitedPassDataSource（显式 fixture）
        └── otherwise                → same-origin real HTTP + CSRF
```

### 认证边界

密码登录、注册、邮箱验证和密码恢复始终调用真实认证 API，不受 fixture 开关影响。
这避免演示凭据跳转到受保护页面却没有服务器 `up_session` 的伪登录状态。fixture
只用于非安全产品数据的界面开发和单元测试。

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

## 7. 后端联调状态

最初冻结时预留给后端的密码校验、TOTP/WebAuthn Ceremony、飞书服务端换码、
PostgreSQL 持久化、CSRF、fail-closed capability 判定、Provider 验证消息、净化头像
存储与审计导出均已有真实实现。生产模式不会在这些 seam 上回落 fixture。

仍属后续范围的是通用 Provider 创建/编辑与 SCIM/LDAP/SAML/CAS、由 OpenAPI
自动生成 TypeScript 客户端，以及将净化后的头像从 PostgreSQL 迁往对象存储；这些
不影响当前已冻结接口的真实持久化和安全边界。

## 8. 验证命令

```bash
pnpm lint        # ESLint
pnpm typecheck   # TypeScript 严格模式
pnpm test        # Vitest 单元测试（真实 transport 合同 + 显式 fixture）
pnpm build       # Next.js 生产构建
```

当前状态（2026-08-16 本次实现定向验证）：231 个 Vitest 测试通过；完整门禁结果以
对应提交报告为准。

## 9. 仍需后续跟进的项目

| 项目 | 说明 |
| --- | --- |
| Playwright E2E 测试 | 覆盖登录、授权恢复、应用创建、Client Secret 轮换、权限不足、员工升级等关键链路 |
| OpenAPI 生成类型 | 后端合同稳定后，使用 OpenAPI 生成 TypeScript 类型和客户端 |
| 真实外部系统验收 | 飞书租户、Cerbos、法律批准、生产 HTTPS/Secret Manager 与备份恢复 |
| Recovery Codes | Provider 提供可审计 lifecycle API 后另行设计；当前不伪造生成/轮换 |
| CI/CD | GitHub Actions 组织分钟额度恢复后重新启用远程门禁 |

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
authoritative. The status table above incorporates the later real-seam amendments.

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

## 13. Production seam completion amendment — 2026-08-16

All production query and command seams now have real HTTP implementations.
Public registration, email verification and password recovery use ZITADEL-owned
credentials plus encrypted, short-lived local lifecycle capabilities. Password
reset advances the security epoch and invalidates older sessions. Logged-out
credential endpoints require JSON and an exact same-origin `Origin`; rate-limit
keys use the authoritative transport peer rather than caller-controlled XFF.

Profile edits, sanitized avatar storage, verified email/phone changes, OAuth
Application/Client management and the administration dashboard are real. The
dashboard independently scopes each aggregate to `user.read`,
`application.read` or `audit.read`; an unrelated admin capability cannot reveal
those counts. `NEXT_PUBLIC_USE_MOCK=true` remains an explicit fixture mode only,
and production never falls back to it. Recovery Codes remain provider-deferred
and are not represented by fake codes or success states.
