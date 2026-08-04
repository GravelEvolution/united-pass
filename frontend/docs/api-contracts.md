# United Pass 前端 API 接入清单

- 状态：Draft，等待前后端评审
- 日期：2026-08-05
- 基础路径建议：同源 `/api/v1`
- 协议边界：OAuth 2.0、OpenID Connect

本文记录当前页面替换 mock 所需的后端能力。它不是最终 OpenAPI 定义；字段名、状态码和权限标识需要以后端合同为准。正式接入优先使用 OpenAPI 生成的类型或客户端。

## 通用约定

### 认证与传输

- 浏览器使用 Secure、HttpOnly、SameSite 会话 Cookie；前端不持久化 Access Token、Refresh Token 或 ID Token。
- 所有写操作需要 CSRF 防护；高风险操作应支持后端发起的重认证挑战。
- API 仅返回界面必要字段，员工内部字段由后端权限过滤。
- 所有时间为 ISO 8601 UTC 字符串，前端展示时明确本地时区。
- 列表使用服务端分页，不允许生产环境一次加载完整用户或审计集合。

### 列表查询

```text
?page[cursor]=opaque_cursor&page[limit]=20&filter[query]=lin&sort=-updatedAt
```

建议响应：

```json
{
  "items": [],
  "page": {
    "nextCursor": "opaque_cursor_or_null",
    "hasMore": false
  }
}
```

### 错误响应

```json
{
  "error": {
    "code": "session.reauthentication_required",
    "message": "请重新验证身份后继续。",
    "requestId": "req_01...",
    "fieldErrors": {
      "redirectUri": "该重定向地址未登记。"
    }
  }
}
```

前端可安全展示 `message` 和字段错误；不得显示堆栈、SQL、内部主机名、令牌或原始异常。建议至少统一处理 `400`、`401`、`403`、`404`、`409`、`422`、`429` 和 `5xx`。

## 认证、注册与 OIDC

| 页面/流程 | 方法与路径 | 用途 | 关键要求 |
| --- | --- | --- | --- |
| `/login` | `POST /api/v1/auth/sessions` | 使用凭据建立浏览器会话 | 限速；返回通用凭据错误；支持 MFA challenge，不记录密码 |
| 全局退出 | `DELETE /api/v1/auth/session` | 撤销当前浏览器会话 | 清除服务端会话与 Cookie |
| `/register` | `POST /api/v1/registrations` | 创建普通用户账户 | 邮箱验证；稳定 `userId`；不得预建独立员工账户 |
| 邮箱验证 | `POST /api/v1/registrations/email-verifications` | 验证注册邮箱 | 一次性、限时、限速 |
| `/authorize` | `GET /oauth/authorize` | 发起 OAuth/OIDC 授权请求 | 后端校验 client、redirect URI、state、nonce、PKCE；不得把校验责任交给页面 |
| `/authorize` | `GET /api/v1/authorization/requests/{requestId}` | 获取已校验的应用、当前身份和请求 Scope | 不接受前端自行拼装应用名称或任意回跳地址 |
| `/authorize` | `POST /api/v1/authorization/requests/{requestId}/decision` | 提交 allow/deny | body: `{ "decision": "allow" | "deny" }`；后端生成安全重定向 |

登录请求使用统一标识字段，允许用户输入账户名或邮箱：

```json
{
  "identifier": "zhixing.lin",
  "password": "user-entered-password"
}
```

注册请求至少包含账户名、邮箱和密码：

```json
{
  "username": "zhixing.lin",
  "email": "zhixing.lin@example.com",
  "password": "user-entered-password"
}
```

`confirmPassword` 仅用于浏览器即时校验，不应进入传输合同或日志。后端必须独立验证账户名格式与唯一性、邮箱格式、密码强度和凭据泄露风险，并返回字段级错误；登录失败不得泄露账户名或邮箱是否存在。

授权请求响应至少包含：`requestId`、应用显示名/说明/负责人、已验证 `redirectHost`、当前用户最小身份信息及逐项 Scope 描述。授权完成响应建议返回后端验证过的 `redirectUrl` 或直接通过受控 303 重定向完成流程。

## 当前账户

| 页面 | 方法与路径 | 数据/操作 | 权限 |
| --- | --- | --- | --- |
| `/account` | `GET /api/v1/me` | `userId`、姓名、邮箱、脱敏手机、personas、可选员工档案 | 当前会话用户 |
| `/account` | `PATCH /api/v1/me` | 修改允许自助维护的公开资料 | 当前会话用户 |
| `/account` | `POST /api/v1/me/email-change-requests` | 为新邮箱创建验证请求并发送验证码 | 当前会话用户；限速；可要求重认证 |
| `/account` | `POST /api/v1/me/email-change-requests/{requestId}/verify` | 校验验证码并原子更新邮箱 | 当前会话用户；一次性、限时验证码 |
| `/account` | `POST /api/v1/me/phone-change-requests` | 为新手机号创建验证请求并发送验证码 | 当前会话用户；限速；可要求重认证 |
| `/account` | `POST /api/v1/me/phone-change-requests/{requestId}/verify` | 校验验证码并原子更新手机号 | 当前会话用户；一次性、限时验证码 |
| `/account/security` | `GET /api/v1/me/security/factors` | 密码、TOTP、Passkey 状态 | 当前会话用户 |
| `/account/security` | `POST /api/v1/me/security/totp/enrollments` | 开始 TOTP 绑定 | 重认证；密钥只在绑定阶段返回 |
| `/account/security` | `POST /api/v1/me/security/passkeys/options` | 获取 WebAuthn 注册选项 | 重认证；服务端 challenge |
| `/account/security` | `POST /api/v1/me/security/passkeys` | 完成 Passkey 注册 | 服务端验证 origin、RP ID、challenge |
| `/account/sessions` | `GET /api/v1/me/sessions` | 设备、客户端、脱敏 IP、大致位置、最近活动和当前会话标记 | 当前会话用户 |
| `/account/sessions` | `DELETE /api/v1/me/sessions/{sessionId}` | 撤销指定会话 | 明确确认；不能误撤当前事务 |
| `/account/security` | `POST /api/v1/me/sessions/revoke-others` | 撤销除当前会话外的全部会话 | 重认证与明确确认 |

`GET /me` 必须以稳定 `userId` 作为身份主键。`employeeProfile` 可为空；外部用户关联员工档案后仍使用原 `userId`，且保留普通用户能力。

`PATCH /me` 当前页面需要支持以下公开资料字段，未提供的字段保持不变：

```json
{
  "displayName": "林知行",
  "nickname": "知行",
  "avatarUrl": "https://cdn.example.com/avatars/usr_01JUP8M8B4Q7R4T6PK1D.png"
}
```

后端必须限制字段长度、验证 `avatarUrl` 协议与允许的图片来源，并返回更新后的完整账户资料。邮箱、手机号等安全联系方式不得混入此通用资料接口，应使用带验证挑战的独立流程。

联系方式修改的申请请求建议仅传新值：

```json
{
  "email": "new-address@example.com"
}
```

或：

```json
{
  "phone": "+8613800138000"
}
```

申请响应返回不含验证码的 `requestId`、脱敏目标值和 `expiresAt`。验证请求使用 `{ "code": "user-entered-code" }`；后端必须校验请求归属、过期时间和尝试次数，并在成功后原子更新联系方式、使请求失效、按安全策略撤销相关会话或通知原联系方式。验证码和完整联系方式不得写入 URL、客户端日志或审计事件。

## 管理工作台与权限

| 页面 | 方法与路径 | 权限标识建议 |
| --- | --- | --- |
| `/admin` | `GET /api/v1/admin/dashboard` | `admin.dashboard.read` |
| 管理导航/操作能力 | `GET /api/v1/me/permissions` | 后端返回显式 permission capabilities |

前端权限仅用于导航和控件可用性。以下每个请求仍须由后端执行 ABAC 决策，不能依赖角色名称或前端传入的权限结论。

## 用户与员工

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/users` | `GET /api/v1/admin/users` | 分页搜索统一用户 | `user.read` |
| 用户详情 | `GET /api/v1/admin/users/{userId}` | 获取授权范围内的用户资料 | `user.read` |
| 用户详情 | `POST /api/v1/admin/users/{userId}/disable` | 停用用户并声明是否撤销会话 | `user.disable`；重认证；审计 |
| 用户详情 | `POST /api/v1/admin/users/{userId}/enable` | 恢复已停用用户 | `user.enable`；审计 |
| `/admin/employees` | `GET /api/v1/admin/employees` | 分页搜索员工档案 | `employee.read` |
| 员工详情 | `PUT /api/v1/admin/users/{userId}/employee-profile` | 为既有用户关联/更新员工档案 | `employee.manage`；不得创建第二身份 |
| 员工详情 | `POST /api/v1/admin/users/{userId}/offboarding` | 启动离职并声明访问撤销范围 | `employee.offboard`；重认证；审计 |

## 部门

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/departments` | `GET /api/v1/admin/departments` | 获取分页或树形部门数据 | `department.read` |
| 部门详情 | `POST /api/v1/admin/departments` | 创建部门 | `department.manage` |
| 部门详情 | `PATCH /api/v1/admin/departments/{departmentId}` | 修改名称、负责人或上级 | `department.manage`；防止循环层级 |

## OAuth 应用

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/applications` | `GET /api/v1/admin/applications` | 分页搜索 OAuth 应用 | `application.read` |
| 应用详情 | `POST /api/v1/admin/applications` | 注册 public/confidential client | `application.manage` |
| 应用详情 | `GET /api/v1/admin/applications/{applicationId}` | 获取元数据和登记的 redirect URIs | `application.read` |
| 应用详情 | `PATCH /api/v1/admin/applications/{applicationId}` | 修改允许字段 | `application.manage` |
| 应用详情 | `POST /api/v1/admin/applications/{applicationId}/client-secret-rotations` | 轮换机密客户端 secret | `application.secret.rotate`；重认证；新 secret 只显示一次 |
| 应用详情 | `POST /api/v1/admin/applications/{applicationId}/disable` | 停用应用并说明影响 | `application.manage`；审计 |

重定向 URI 必须由后端按精确安全语义校验；前端不得静默归一化。公共客户端必须使用 PKCE，浏览器代码不得持有 client secret。

## 授权策略

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/policies` | `GET /api/v1/admin/policies` | 分页搜索策略 | `policy.read` |
| 策略详情 | `GET /api/v1/admin/policies/{policyId}` | 读取策略及版本 | `policy.read` |
| 策略详情 | `POST /api/v1/admin/policies` | 创建草稿 | `policy.manage` |
| 策略详情 | `PATCH /api/v1/admin/policies/{policyId}` | 更新草稿 | `policy.manage`；乐观锁版本号 |
| 策略详情 | `POST /api/v1/admin/policies/{policyId}/publish` | 发布策略版本 | `policy.publish`；重认证；审计 |

## 审计

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/audit` | `GET /api/v1/admin/audit-events` | 分页筛选安全与管理事件 | `audit.read` |
| `/admin/audit` | `POST /api/v1/admin/audit-exports` | 创建异步导出任务 | `audit.export`；重认证；字段脱敏；审计 |
| 导出任务 | `GET /api/v1/admin/audit-exports/{exportId}` | 查询导出状态并获取短期下载地址 | `audit.export` |

审计事件建议包含 `eventId`、`eventType`、受控的 actor/target 摘要、`occurredAt`、`result` 和 `requestId`。不得把令牌、密码、授权码、完整私密策略或敏感员工字段写入事件展示载荷。

## Mock 到 API 的映射

| 当前数据源方法 | 目标接口 |
| --- | --- |
| `getCurrentUser` | `GET /api/v1/me` |
| `getAdminCurrentUser` | `GET /api/v1/me`（Mock 中用于固定管理身份；真实实现仍由当前服务端会话决定） |
| `getSecurityFactors` | `GET /api/v1/me/security/factors` |
| `getSessions` | `GET /api/v1/me/sessions` |
| `getConsentRequest` | `GET /api/v1/authorization/requests/{requestId}` |
| `getAdminDashboard` | `GET /api/v1/admin/dashboard` |
| `getUsers` | `GET /api/v1/admin/users` |
| `getEmployees` | `GET /api/v1/admin/employees` |
| `getDepartments` | `GET /api/v1/admin/departments` |
| `getApplications` | `GET /api/v1/admin/applications` |
| `getPolicies` | `GET /api/v1/admin/policies` |
| `getAuditEvents` | `GET /api/v1/admin/audit-events` |
