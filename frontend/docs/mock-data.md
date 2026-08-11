# Mock 数据说明

当前初始化阶段使用集中式 mock 数据，用于验证页面结构、响应式布局和领域模型，不构成认证、授权或后端功能实现。

## 使用边界

- 数据源接口位于 `src/lib/api/united-pass-data-source.ts`。
- mock 实现位于 `src/lib/mock/united-pass-data-source.ts`。
- 公开演示凭据及浏览器端校验位于 `src/lib/mock/mock-auth.ts`。
- 页面只调用数据源接口暴露的方法，不直接维护硬编码记录。
- 搜索仅在浏览器内过滤当前 mock 列表，并且每种资源只声明允许搜索的展示字段；真实大数据集必须改为服务端权限过滤、字段裁剪、分页和搜索。
- 登录只在浏览器中校验下方公开的演示凭据并跳转，不会创建 Cookie 或真实会话。注册必须勾选服务条款；密码找回仅显示防账户枚举的通用 Mock 结果。注册、密码找回、授权、撤销会话和管理变更均不持久化。
- `/account` 的显示名称、昵称与头像可在当前页面内修改。头像只接受本地 PNG、JPEG、WebP，经过文件头、尺寸与解码校验并重新编码后预览；不会上传原文件或接受外部 URL。刷新页面后恢复初始 mock。
- `/account` 的邮箱和手机号使用“发送 Mock 验证码 → 校验 → 更新”的独立流程。固定验证码为 `246810`，不会真的发送邮件或短信，更新结果同样只保留到刷新前。
- 普通用户仅包含 `consumer` 人格；员工演示用户同时包含 `consumer` 和 `employee` 人格及 `employeeProfile`。稳定 `userId` 不因员工档案关联而变化。
- `/admin/providers` 展示 Provider 管理清单。飞书记录状态为“规划中”、登录未启用，不代表已经实现飞书认证或账户关联。

## 演示凭据

这些凭据公开用于本地界面演示，不是秘密，也不得复用于真实环境。

| 身份 | 账户名 | 邮箱 | 密码 | 登录后页面 |
| --- | --- | --- | --- | --- |
| 普通外部应用用户 | `app.user` | `app.user@example.com` | `MockUser123!` | `/account` |
| 员工管理用户 | `zhixing.lin` | `zhixing.lin@example.com` | `MockAdmin123!` | `/admin` |

登录标识可填写对应的账户名或邮箱。凭据错误时只显示通用错误，避免根据提示判断账户是否存在。

## 替换流程

替换按 seam 逐步推进，由单一环境标志 `NEXT_PUBLIC_USE_MOCK` 控制（唯一读取点在 `src/lib/api/data-source-mode.ts`）：`"true"` 时所有 seam 走 mock；未设置时已迁移的 seam 调用真实后端 HTTP API，未迁移的 seam 仍走 mock。标志必须带 `NEXT_PUBLIC_` 前缀，因为浏览器端命令同样读取它（与 frontend-freeze-v1.md §5 伪代码中的 `USE_MOCK` 命名差异源于 Next.js 只会向客户端内联 `NEXT_PUBLIC_*` 变量）。示例配置见 `.env.example`；e2e 的 Playwright webServer 固定注入 `NEXT_PUBLIC_USE_MOCK=true`，保证 e2e 始终演练冻结的 mock 数据源。

已迁移到真实 HTTP 的 seam（P3–P5）：

| Seam | 方向 | 后端路径 |
| --- | --- | --- |
| `getCurrentUser` | Query（服务端） | `GET /api/v1/me` |
| `getConsentResolution` | Query（服务端） | `GET /api/v1/authorization/requests/{requestId}` |
| `getAuthorizedApplications` | Query（服务端） | `GET /api/v1/me/authorized-applications` |
| `decideConsent` | Command（浏览器） | `POST /api/v1/authorization/requests/{requestId}/decision` |
| `revokeGrant` | Command（浏览器） | `DELETE /api/v1/me/authorized-applications/{grantId}` |
| account security/session queries and commands | Query / Command | `/api/v1/me/security`、`/api/v1/me/sessions`、`/api/v1/auth/reauthentication*` 等 P4 冻结路径 |
| `getCurrentPermissions` | Query（服务端） | `GET /api/v1/me/permissions` |
| user list/detail and lifecycle/session commands | Query / Command | `/api/v1/admin/users*` |
| employee list/detail/link/update/offboard | Query / Command | `/api/v1/admin/employees*`、`/api/v1/admin/users/{userId}/employee-profile`、`/offboarding` |
| department list/detail/create/update/delete | Query / Command | `/api/v1/admin/departments*` |

未迁移的 seam（账户资料/联系方式编辑、OAuth 应用后台、Provider、策略、审计等）在标志关闭时仍走 mock，后续阶段逐个替换。P5 用户、员工和部门 seam 在真实模式下不得回退到 mock。

迁移每个 seam 的步骤：

1. 根据 `docs/api-contracts.md` 与后端确认 OpenAPI 合同。
2. 在 `src/lib/api` 的对应 seam 层接线真实 HTTP 调用，统一处理基础 URL、凭据、取消请求、错误和运行时校验；响应体必须经过 `src/lib/api/response-validators.ts` 收窄校验后才能进入冻结的领域类型。
3. 在服务端组合层选择真实数据源；不要把访问令牌或私密环境变量传入 Client Component。
4. 移除页面中的 Mock 文案和预览动作，并补齐 pending、失败、unauthorized 与重试状态。
5. 保留 mock 作为测试 fixture 时，应移入测试专用目录，防止生产环境误用。
