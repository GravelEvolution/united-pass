# United Pass 前端 API 接入清单

- 状态：Frozen v1 + P4.5/P4.7/P4.9 Frozen Amendments（live A14/A15 Passed）
- 日期：2026-08-09（P4.7 Account Security real-seam 接入修订）
- 基础路径建议：同源 `/api/v1`
- 协议边界：OAuth 2.0、OpenID Connect

本文是后端实现的详细人类可读合同。当 `backend/openapi/openapi.yaml` 建立后，OpenAPI 规范是机器可读的唯一合同，本文是其详细说明。两者必须保持同步，不得 knowingly 矛盾。在 OpenAPI 未覆盖到的细节上，以本文为准。

## 通用约定

### 认证与传输

- 浏览器使用 Secure、HttpOnly、SameSite 会话 Cookie；前端不持久化 Access Token、Refresh Token 或 ID Token。
- 所有写操作需要 CSRF 防护；高风险操作应支持后端发起的重认证挑战。
- API 仅返回界面必要字段，员工内部字段由后端权限过滤。
- 所有时间为 ISO 8601 UTC 字符串，前端展示时明确本地时区。
- 列表使用服务端游标分页，不允许生产环境一次加载完整用户或审计集合。

### 游标分页

请求参数：

```text
?cursor=opaque_cursor&limit=20&query=lin&sort=-updatedAt&status=active
```

响应体：

```json
{
  "items": [],
  "page": {
    "nextCursor": "opaque_cursor_or_null",
    "hasMore": false
  }
}
```

前端类型：

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
  page: {
    nextCursor: string | null;
    hasMore: boolean;
  };
};
```

### 错误响应

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

`fieldErrors` 使用数组格式，支持同一字段返回多个错误。前端 `ApiError` 类型：

```ts
type FieldError = { field: string; message: string };

type ApiError = {
  kind: "network" | "unauthorized" | "forbidden" | "not_found"
      | "conflict" | "validation" | "rate_limited"
      | "reauthentication_required" | "server_error";
  message: string;
  requestId?: string;
  fieldErrors?: FieldError[];
  retryAfter?: number;
  challenge?: {
    methods: ReadonlyArray<"password" | "totp" | "passkey">;
    requestId: string;
  };
};
```

前端可安全展示 `message` 和 `fieldErrors`；不得显示堆栈、SQL、内部主机名、令牌或原始异常。建议至少统一处理 `400`、`401`、`403`、`404`、`409`、`422`、`429` 和 `5xx`。

### 权限能力

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

前端按能力过滤导航和控件可用性，不依赖角色名称。每个请求仍须由后端执行 ABAC 决策。

## 认证、注册与 OIDC

| 页面/流程 | 方法与路径 | 用途 | 关键要求 |
| --- | --- | --- | --- |
| `/login` | `POST /api/v1/auth/sessions` | 使用凭据建立浏览器会话 | 限速；返回通用凭据错误；支持 MFA challenge，不记录密码 |
| MFA 挑战 | `POST /api/v1/auth/sessions/mfa` | 提交 TOTP / Passkey / 恢复码 | challenge 限时；限速；过多尝试锁定 |
| 高危操作重认证 | `POST /api/v1/auth/reauthentication` | 为删除应用/删除 Client/轮换 Secret 等高危操作重新验证密码 | 需要会话 + CSRF；返回授权（200）或 MFA 挑战（202）；限速；授权令牌一次性 |
| 重认证 MFA 完成 | `POST /api/v1/auth/reauthentication/mfa` | 以 TOTP / Passkey 完成重认证挑战 | 与登录 MFA 相同的原子消费语义；成功后签发一次性授权令牌 |
| `/forgot-password` | `POST /api/v1/password-reset-requests` | 请求向已验证联系方式发送重置说明 | 限速；始终返回通用结果，不能泄露账户是否存在 |
| 密码重置落地页 | `POST /api/v1/password-resets` | 使用一次性令牌设置新密码 | 令牌限时、一次性、不可写入日志；成功后按策略撤销会话 |
| 邮箱验证落地页 | `POST /api/v1/email-verifications` | 使用一次性令牌验证邮箱 | 令牌限时、一次性、限速 |
| 全局退出 | `DELETE /api/v1/auth/session` | 撤销当前浏览器会话 | 清除服务端会话与 Cookie |
| `/register` | `POST /api/v1/registrations` | 创建普通用户账户 | 邮箱验证；稳定 `userId`；不得预建独立员工账户 |

登录请求使用统一标识字段：

```json
{
  "identifier": "zhixing.lin",
  "password": "user-entered-password"
}
```

MFA 挑战请求：

```json
{
  "mfaToken": "opaque_mfa_token",
  "method": "totp",
  "code": "user-entered-code"
}
```

高危操作重认证请求。既有 Application/Client action 与 Account Security
action 共用同一端点，但绑定字段不同：

```json
{
  "action": "client.secret.rotate",
  "applicationId": "app_x",
  "clientId": "clt_x",
  "target": "",
  "password": "user-entered-password"
}
```

P4 Account Security action：

```text
account.password.change
account.totp.enroll
account.totp.remove
account.passkey.enroll
account.passkey.remove
```

Account action 的 `applicationId` / `clientId` 必须为空；只有
`account.passkey.remove` 要求 `target=passkeyId`，其他 Account action 禁止
`target`。前端不得填写假的 Application/Client ID。

重认证响应：密码验证通过但需要第二因子时返回 `202`
`{"status":"mfa_required","reauthToken":"...","availableMethods":["totp","passkey"],"passkeyRequestOptions":{},"expiresAt":"..."}`；
完成后的最终授权返回 `200`
`{"status":"granted","reauthToken":"...","expiresAt":"..."}`。最终
`reauthToken` 一次性消费，随高危请求以 `X-Reauthentication-Token` 请求头
提交；复用或未携带时后端返回错误码
`session.reauthentication_required`。授权与声明的 action 及目标资源绑定，
不能跨操作重放。`passkeyRequestOptions` 仅在 provider 提供 Passkey challenge
时出现。

注册请求至少包含账户名、邮箱和密码：

```json
{
  "username": "zhixing.lin",
  "email": "zhixing.lin@example.com",
  "password": "user-entered-password"
}
```

`confirmPassword` 仅用于浏览器即时校验，不应进入传输合同或日志。后端必须独立验证账户名格式与唯一性、邮箱格式、密码强度和凭据泄露风险，并返回字段级错误；登录失败不得泄露账户名或邮箱是否存在。

## OAuth 授权与同意

| 页面/流程 | 方法与路径 | 用途 | 关键要求 |
| --- | --- | --- | --- |
| `/authorize` | `GET /oauth/authorize` | 发起 OAuth/OIDC 授权请求 | 后端校验 client、redirect URI、state、nonce、PKCE；不得把校验责任交给页面 |
| `/authorize` | `GET /api/v1/authorization/requests/{requestId}` | 获取已校验的应用、当前身份和请求 Scope | 不接受前端自行拼装应用名称或任意回跳地址 |
| `/authorize` | `POST /api/v1/authorization/requests/{requestId}/decision` | 提交 allow/deny | body: `{ "decision": "allow" \| "deny" }`；后端生成安全重定向 |

授权请求响应至少包含：`requestId`、应用显示名/说明/负责人、已验证 `redirectHost`、当前用户最小身份信息及逐项 Scope 描述。

授权完成响应返回后端验证过的 `redirectUrl`，前端使用 `window.location.assign` 在当前窗口跳转。拒绝也应返回已验证的 Client Redirect URI 并携带 OAuth 错误参数（`error=access_denied`），而不是默认进入 `/account`。

## 当前账户

| 页面 | 方法与路径 | 数据/操作 | 权限 |
| --- | --- | --- | --- |
| `/account` | `GET /api/v1/me` | `userId`、姓名、邮箱、脱敏手机、personas、可选员工档案 | 当前会话用户 |
| `/account` | `PATCH /api/v1/me` | 修改允许自助维护的公开资料 | 当前会话用户 |
| `/account` | `POST /api/v1/me/avatar` | multipart 上传头像并返回受控媒体地址 | 当前会话用户；CSRF 防护；文件解码与重编码 |
| `/account` | `POST /api/v1/me/email-change-requests` | 为新邮箱创建验证请求并发送验证码 | 当前会话用户；限速；可要求重认证 |
| `/account` | `POST /api/v1/me/email-change-requests/{requestId}/verify` | 校验验证码并原子更新邮箱 | 当前会话用户；一次性、限时验证码 |
| `/account` | `POST /api/v1/me/phone-change-requests` | 为新手机号创建验证请求并发送验证码 | 当前会话用户；限速；可要求重认证 |
| `/account` | `POST /api/v1/me/phone-change-requests/{requestId}/verify` | 校验验证码并原子更新手机号 | 当前会话用户；一次性、限时验证码 |
| `/account/security` | `GET /api/v1/me/security` | 密码、TOTP、Passkey 列表与 Recovery Codes capability | 当前会话用户；provider readback |
| `/account/security` | `POST /api/v1/me/security/totp/enrollment` | 开始 TOTP 绑定 | `account.totp.enroll` 重认证；密钥只在绑定阶段返回 |
| `/account/security` | `POST /api/v1/me/security/totp/enrollment/confirm` | 确认 TOTP 绑定 | enrollmentToken + 首次 TOTP 码 |
| `/account/security` | `DELETE /api/v1/me/security/totp` | 删除 TOTP 因子 | 重认证；审计 |
| `/account/security` | `POST /api/v1/me/security/passkeys/enrollment` | 开始 WebAuthn 注册并返回 creation options | `account.passkey.enroll` 重认证；no-store |
| `/account/security` | `POST /api/v1/me/security/passkeys/enrollment/confirm` | 完成 Passkey 注册 | enrollmentToken + 浏览器 credential JSON |
| `/account/security` | `POST /api/v1/me/security/passkeys/enrollment/cancel` | 取消/结算已放弃的 pending registration | enrollmentToken capability；Session + CSRF；ADR-0008 |
| `/account/security` | `DELETE /api/v1/me/security/passkeys/{passkeyId}` | 删除指定 Passkey | `account.passkey.remove` 重认证且 target 必须匹配；审计 |
| `/account/sessions` | `GET /api/v1/me/sessions` | 设备、客户端、脱敏 IP、大致位置、最近活动和当前会话标记 | 当前会话用户 |
| `/account/sessions` | `DELETE /api/v1/me/sessions/{sessionId}` | 撤销指定会话 | 明确确认；不能误撤当前事务 |
| `/account/security` | `DELETE /api/v1/me/sessions` | 撤销除当前会话外的全部会话 | 明确确认；当前会话保留 |
| `/account/applications` | `GET /api/v1/me/authorized-applications` | 已授权应用列表 | 当前会话用户 |
| `/account/applications` | `DELETE /api/v1/me/authorized-applications/{grantId}` | 撤销指定应用授权 | 当前会话用户 |

`GET /me` 必须以稳定 `userId` 作为身份主键。`employeeProfile` 可为空；外部用户关联员工档案后仍使用原 `userId`，且保留普通用户能力。

### P4.5 Security Summary 与 Passkey browser ceremony

真实 Security Summary 的固定形状：

```json
{
  "password": { "set": true },
  "totp": { "enabled": true },
  "passkeys": [
    { "passkeyId": "pk_opaque", "createdAt": null, "state": "active" }
  ],
  "recoveryCodes": {
    "available": false,
    "deferredReason": "provider_unsupported"
  }
}
```

`passkeys` 可以有零个、一个或多个元素；前端逐凭据显示并以
`passkeyId` 作为删除 target。禁止退化回 Mock 时代“一种 factor 一行”的
`SecurityFactor[]`。`createdAt:null` 表示 provider 未提供时间，前端不得用
本机当前时间伪造。

Passkey begin 响应：

```json
{
  "enrollmentToken": "opaque",
  "passkeyId": "provider-passkey-id",
  "publicKeyCredentialCreationOptions": {
    "challenge": "base64url",
    "rp": {},
    "user": { "id": "base64url" },
    "pubKeyCredParams": []
  }
}
```

`publicKeyCredentialCreationOptions` 是 JSON wire shape，不可直接 type-cast
为 DOM `PublicKeyCredentialCreationOptions`。浏览器适配层必须把 challenge、
`user.id` 与 credential descriptor IDs 从 base64url 转为 ArrayBuffer，调用
`navigator.credentials.create()`，再把 attestation 二进制字段编码回无 padding
base64url JSON。WebAuthn credential 只在函数栈中存在并立即提交：

```json
{
  "enrollmentToken": "opaque",
  "publicKeyCredential": {
    "id": "credential-id",
    "rawId": "base64url",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64url",
      "attestationObject": "base64url"
    }
  },
  "passkeyName": "当前设备"
}
```

ZITADEL v2.71.18 的 creation/request options 以单层
`{"publicKey": {...}}` envelope 返回；浏览器适配层严格解包该 envelope，且拒绝
同时存在 envelope 与顶层 option 字段。`passkeyName` trim 后必须为 1–200 个
Unicode 字符，后端在 claim enrollment capability 前校验。

成功响应为
`{"status":"confirmed","passkeyId":"provider-passkey-id"}`。前端随后
`router.refresh()` 并以 provider-derived summary 为权威；不得在请求完成前
乐观插入 passkey。

如果 begin 之后浏览器取消、WebAuthn 失败或本地转换失败，前端使用 body 中
的 enrollmentToken 调用 P4.5 cancel seam。页面/进程直接消失时，由
ADR-0008 定义的 claim-aware expiry cleanup 结算 provider pending state；worker
在删除前必须做 provider readback，active credential 永不删除。

Recovery Codes 在当前 provider baseline 下为架构性 Deferred：真实模式隐藏，
不存在 generate/rotate API；Mock mode 可继续展示原型。

`PATCH /me` 当前页面需要支持以下公开资料字段，未提供的字段保持不变：

```json
{
  "displayName": "林知行",
  "nickname": "知行"
}
```

头像使用独立的 `POST /api/v1/me/avatar` multipart 上传接口，不接受用户提交的外部图片 URL。后端必须重新验证文件大小、真实媒体类型、文件头、解码尺寸和总像素，拒绝 SVG 等主动内容，重新编码并剥离元数据后存储，再返回同源或受控媒体域的头像地址。前端校验只用于即时反馈，不能替代服务端安全处理。邮箱、手机号等安全联系方式不得混入通用资料接口，应使用带验证挑战的独立流程。

## 管理工作台与权限

| 页面 | 方法与路径 | 权限标识建议 |
| --- | --- | --- |
| `/admin` | `GET /api/v1/admin/dashboard` | `admin.dashboard.read` |
| 管理导航/操作能力 | `GET /api/v1/me/permissions` | 后端返回显式 `PermissionCapabilities` |

前端权限仅用于导航和控件可用性。以下每个请求仍须由后端执行 ABAC 决策，不能依赖角色名称或前端传入的权限结论。

P5 用户、员工和部门目录已接入真实 API。搜索词、游标、页容量、排序和筛选随对应 `GET /api/v1/admin/*` 请求发送，由服务端在权限过滤和字段裁剪后返回当前页；浏览器不接收完整用户或员工集合再做本地过滤。尚未迁移的管理目录仍可在 Mock mode 保留显式字段的本地原型搜索。

## OAuth Application 与 Client

Application 和 OAuth Client 是分离的实体。一个 Application 可以有多个 Client。

### Application

| 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- |
| `POST /api/v1/admin/applications/with-initial-client` | 原子创建应用和初始 Client | `application.manage` |
| `GET /api/v1/admin/applications` | 分页搜索 OAuth 应用 | `application.read` |
| `GET /api/v1/admin/applications/{applicationId}` | 获取应用元数据和 Client 列表 | `application.read` |
| `PATCH /api/v1/admin/applications/{applicationId}` | 修改应用名称、说明、受众、负责人 | `application.manage` |
| `POST /api/v1/admin/applications/{applicationId}/enable` | 启用应用 | `application.manage`；审计 |
| `POST /api/v1/admin/applications/{applicationId}/disable` | 停用应用并说明影响 | `application.manage`；审计 |
| `DELETE /api/v1/admin/applications/{applicationId}` | 删除应用及其所有 Client | `application.manage`；重认证；审计 |

### OAuth Client

| 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- |
| `POST /api/v1/admin/applications/{applicationId}/clients` | 为应用添加新 Client | `application.manage` |
| `GET /api/v1/admin/applications/{applicationId}/clients/{clientId}` | 获取 Client 详情 | `application.read` |
| `PATCH /api/v1/admin/applications/{applicationId}/clients/{clientId}` | 修改 Client 名称、Redirect URI、Scope、Consent Mode | `application.manage` |
| `POST /api/v1/admin/applications/{applicationId}/clients/{clientId}/enable` | 启用 Client | `application.manage` |
| `POST /api/v1/admin/applications/{applicationId}/clients/{clientId}/disable` | 停用 Client | `application.manage` |
| `DELETE /api/v1/admin/applications/{applicationId}/clients/{clientId}` | 删除 Client | `application.manage`；重认证 |
| `POST /api/v1/admin/applications/{applicationId}/clients/{clientId}/secret-rotations` | 轮换机密客户端 Secret | `application.secret.rotate`；重认证；新 Secret 只显示一次 |

Client Profile（`web_server`、`spa_mobile`、`server_to_server`）决定 Grant Types、Token Endpoint Auth Method、是否需要 Redirect URI、是否允许 `openid` Scope。MVP 中 `openid` 对所有交互式 Profile 为可选，管理员按需勾选。`trusted_first_party` 同意模式暂不支持，待后端实现信任策略后加入。

重定向 URI 必须由后端按精确安全语义校验；前端不得静默归一化。公共客户端必须使用 PKCE，浏览器代码不得持有 Client Secret。

## 用户与员工

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/users` | `GET /api/v1/admin/users` | 分页搜索统一用户 | `user.read` |
| 用户详情 | `GET /api/v1/admin/users/{userId}` | 获取授权范围内的用户资料、Persona、外部身份关联、活跃会话、授权应用 | `user.read` |
| 用户详情 | `POST /api/v1/admin/users/{userId}/disable` | 停用用户并声明是否撤销会话 | `user.disable`；重认证；审计 |
| 用户详情 | `POST /api/v1/admin/users/{userId}/enable` | 恢复已停用用户 | `user.enable`；审计 |
| 用户详情 | `DELETE /api/v1/admin/users/{userId}/sessions` | 撤销用户所有会话 | `user.disable`；重认证 |
| 用户详情 | `DELETE /api/v1/admin/users/{userId}/sessions/{sessionId}` | 撤销属于该用户的单个会话 | `user.disable`；所有权校验；审计 |
| `/admin/employees` | `GET /api/v1/admin/employees` | 分页搜索员工档案 | `user.read` |
| 员工详情 | `GET /api/v1/admin/users/{userId}/employee-profile` | 获取员工档案 | `user.read` |
| 员工详情 | `PUT /api/v1/admin/users/{userId}/employee-profile` | 为既有用户关联/更新员工档案 | `employee.manage`；不得创建第二身份 |
| `/admin/employees/link` | `POST /api/v1/admin/employees/link` | 搜索已有普通用户并为其建立员工档案 | `employee.manage` |
| 员工详情 | `POST /api/v1/admin/users/{userId}/offboarding` | 启动离职并声明访问撤销范围 | `employee.offboard`；重认证；审计 |

用户与员工共用同一 `userId`。外部用户关联员工档案后保留 Consumer Persona。不得仅凭邮箱、手机号、域名或显示名合并账户。

`user.disable`、`user.sessions.revoke` 与 `employee.offboard` 必须使用绑定到当前 actor session、动作和精确目标 `userId` 的单次重认证 grant。离职提交后，`offboarding` 是立即生效的管理权限 deny；消费者 Persona 与 OAuth grant 保留。Redis/ZITADEL 会话撤销可由持久化作业继续收敛，`202` 不得描述为所有外部会话已经完成撤销。

## 部门

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/departments` | `GET /api/v1/admin/departments` | 获取树形或分页部门数据 | `user.read` |
| 部门详情 | `GET /api/v1/admin/departments/{departmentId}` | 获取部门信息、负责人和成员 | `user.read` |
| 部门详情 | `POST /api/v1/admin/departments` | 创建部门 | `department.manage` |
| 部门详情 | `PATCH /api/v1/admin/departments/{departmentId}` | 修改名称、负责人或上级 | `department.manage`；防止循环层级 |
| 部门详情 | `DELETE /api/v1/admin/departments/{departmentId}` | 删除空部门 | `department.manage`；审计 |

## Identity Provider 管理

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/providers` | `GET /api/v1/admin/identity-providers` | 分页读取 Provider 状态与非敏感元数据 | `identity_provider.read` |
| Provider 详情 | `POST /api/v1/admin/identity-providers` | 创建 Provider 草稿 | `identity_provider.manage`；重认证；审计 |
| Provider 详情 | `GET /api/v1/admin/identity-providers/{providerId}` | 获取 Provider 配置（不含密钥明文） | `identity_provider.read` |
| Provider 详情 | `PATCH /api/v1/admin/identity-providers/{providerId}` | 更新允许的非密钥配置 | `identity_provider.manage`；重认证；审计 |
| Provider 详情 | `POST /api/v1/admin/identity-providers/{providerId}/enable` | 完成后端校验后启用登录 | `identity_provider.enable`；重认证；审计 |
| Provider 详情 | `POST /api/v1/admin/identity-providers/{providerId}/disable` | 停止新的 Provider 登录并说明已有账户影响 | `identity_provider.enable`；重认证；审计 |

飞书是首个计划支持的厂商 Provider，但当前前端只展示规划记录。正式接入前需以后端确认飞书开放平台协议、回调和字段合同；客户端密钥只能保存在服务端密钥系统中。授权回调必须由后端校验请求关联、防重放参数、精确回调地址和供应商响应，不得由前端直接交换凭据。外部身份必须显式关联到既有稳定 `userId`，不得仅凭邮箱或手机号自动合并，也不得根据飞书组织信息直接授予员工或管理权限。

## 授权策略 (ABAC)

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/policies` | `GET /api/v1/admin/policies` | 分页搜索策略 | `policy.read` |
| 策略详情 | `GET /api/v1/admin/policies/{policyId}` | 读取策略及版本 | `policy.read` |
| 策略详情 | `POST /api/v1/admin/policies` | 创建草稿 | `policy.manage` |
| 策略详情 | `PATCH /api/v1/admin/policies/{policyId}` | 更新草稿 | `policy.manage`；乐观锁版本号 |
| 策略详情 | `POST /api/v1/admin/policies/{policyId}/publish` | 发布策略版本 | `policy.publish`；重认证；审计 |
| 策略模拟 | `POST /api/v1/admin/policies/{policyId}/simulate` | 模拟 Allow/Deny | `policy.read` |
| 策略版本 | `GET /api/v1/admin/policies/{policyId}/versions` | 发布后的版本历史 | `policy.read` |

## 审计

| 页面 | 方法与路径 | 用途 | 权限标识建议 |
| --- | --- | --- | --- |
| `/admin/audit` | `GET /api/v1/admin/audit-events` | 分页筛选安全与管理事件 | `audit.read` |
| `/admin/audit` | `POST /api/v1/admin/audit-exports` | 创建异步导出任务 | `audit.export`；重认证；字段脱敏；审计 |
| 导出任务 | `GET /api/v1/admin/audit-exports/{exportId}` | 查询导出状态并获取短期下载地址 | `audit.export` |

审计事件建议包含 `eventId`、`eventType`、受控的 actor/target 摘要、`occurredAt`、`result` 和 `requestId`。不得把令牌、密码、授权码、完整私密策略或敏感员工字段写入事件展示载荷。

## 数据源方法到 API 映射

### Queries（只读）

| 数据源方法 | 目标接口 | 返回类型 |
| --- | --- | --- |
| `getCurrentUser()` | `GET /api/v1/me` | `CurrentUser` |
| `getCurrentPermissions()` | `GET /api/v1/me/permissions` | `PermissionCapabilities` |
| `getSecuritySummary()` | `GET /api/v1/me/security` | `SecuritySummary` |
| `getSessions()` | `GET /api/v1/me/sessions` | `UserSession[]` |
| `getAuthorizedApplications()` | `GET /api/v1/me/authorized-applications` | `AuthorizedApplication[]` |
| `getConsentResolution(requestId)` | `GET /api/v1/authorization/requests/{requestId}` | `ConsentResolution` |
| `getAdminDashboard()` | `GET /api/v1/admin/dashboard` | `AdminDashboard` |
| `getUsers(query)` | `GET /api/v1/admin/users` | `CursorPage<ManagedUser>` |
| `getEmployees(query)` | `GET /api/v1/admin/employees` | `CursorPage<EmployeeRecord>` |
| `getDepartments(query)` | `GET /api/v1/admin/departments` | `DepartmentRecord[]`（服务端搜索，最多 100 条） |
| `getIdentityProviders(query)` | `GET /api/v1/admin/identity-providers` | `CursorPage<IdentityProviderRecord>` |
| `getApplications(query)` | `GET /api/v1/admin/applications` | `CursorPage<OAuthApplication>` |
| `getApplicationDetail(applicationId)` | `GET /api/v1/admin/applications/{applicationId}` | `OAuthApplicationDetail \| null` |
| `getClientDetail(applicationId, clientId)` | `GET /api/v1/admin/applications/{applicationId}/clients/{clientId}` | `OAuthClient \| null` |
| `getAvailableScopes()` | `GET /api/v1/admin/scopes` | `AllowedScope[]` |
| `getPolicies(query)` | `GET /api/v1/admin/policies` | `CursorPage<AuthorizationPolicy>` |
| `getAuditEvents(query)` | `GET /api/v1/admin/audit-events` | `CursorPage<AuditEvent>` |

### Commands（写操作）

| 数据源方法 | 目标接口 |
| --- | --- |
| `createApplicationWithInitialClient(input)` | `POST /api/v1/admin/applications/with-initial-client` |
| `createOAuthClient(input)` | `POST /api/v1/admin/applications/{applicationId}/clients` |
| `updateApplication(applicationId, input)` | `PATCH /api/v1/admin/applications/{applicationId}` |
| `updateApplicationStatus(applicationId, status)` | `POST /api/v1/admin/applications/{applicationId}/enable\|disable` |
| `deleteApplication(applicationId)` | `DELETE /api/v1/admin/applications/{applicationId}` |
| `rotateClientSecret(applicationId, clientId)` | `POST /api/v1/admin/applications/{applicationId}/clients/{clientId}/secret-rotations` |
| `decideConsent(requestId, decision)` | `POST /api/v1/authorization/requests/{requestId}/decision` |
| `revokeGrant(grantId)` | `DELETE /api/v1/me/authorized-applications/{grantId}` |
| `requestReauthentication(input)` | `POST /api/v1/auth/reauthentication` |
| `completeReauthenticationMfa(input)` | `POST /api/v1/auth/reauthentication/mfa` |
| `startPasskeyEnrollment(reauthToken)` | `POST /api/v1/me/security/passkeys/enrollment` + `X-Reauthentication-Token` |
| `completePasskeyEnrollment(input)` | `POST /api/v1/me/security/passkeys/enrollment/confirm` |
| `cancelPasskeyEnrollment(enrollmentToken)` | `POST /api/v1/me/security/passkeys/enrollment/cancel` |
| `removePasskey(passkeyId, reauthToken)` | `DELETE /api/v1/me/security/passkeys/{passkeyId}` + target-bound reauth header |
| `changePassword(newPassword, reauthToken)` | `POST /api/v1/me/security/password`；body 仅 `{newPassword}` |
| `beginTotpEnrollment(reauthToken)` | `POST /api/v1/me/security/totp/enrollment` |
| `confirmTotpEnrollment(input)` | `POST /api/v1/me/security/totp/enrollment/confirm`；enrollmentToken + code |
| `cancelTotpEnrollment(enrollmentToken)` | `POST /api/v1/me/security/totp/enrollment/cancel`；清理 provider pending registration |
| `removeTotp(reauthToken)` | `DELETE /api/v1/me/security/totp` |
| `revokeOwnSession(sessionId)` | `DELETE /api/v1/me/sessions/{sessionId}` |
| `revokeOtherSessions()` | `DELETE /api/v1/me/sessions`；返回 `{revoked}` |
| `logout()` | `DELETE /api/v1/auth/session`；成功后再跳转登录页 |
| `updateUserStatus(userId, status, reauthToken?)` | `POST /api/v1/admin/users/{userId}/enable\|disable`；disable 需要 target-bound grant |
| `revokeUserSession(userId, sessionId)` | `DELETE /api/v1/admin/users/{userId}/sessions/{sessionId}` |
| `revokeUserSessions(userId, reauthToken)` | `DELETE /api/v1/admin/users/{userId}/sessions` + target-bound grant |
| `linkEmployeeProfile(input)` | `POST /api/v1/admin/employees/link`；body 使用显式稳定 `userId` |
| `updateEmployeeProfile(userId, input)` | `PUT /api/v1/admin/users/{userId}/employee-profile` |
| `offboardEmployee(userId, reauthToken)` | `POST /api/v1/admin/users/{userId}/offboarding` + target-bound grant |
| `createDepartment(input)` | `POST /api/v1/admin/departments` |
| `updateDepartment(departmentId, input)` | `PATCH /api/v1/admin/departments/{departmentId}` |
| `deleteDepartment(departmentId)` | `DELETE /api/v1/admin/departments/{departmentId}` |

### 已移除的 Mock 专用接口

| 旧 Mock 方法 | 替代方案 |
| --- | --- |
| `getAdminCurrentUser()` | `getCurrentUser()`；管理员能力由 `getCurrentPermissions()` 返回的 `PermissionCapabilities` 决定 |
| `getConsentRequest()` | `getConsentResolution(requestId)`；统一为解析已校验的授权请求 |
