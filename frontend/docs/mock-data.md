# Mock 数据说明

当前初始化阶段使用集中式 mock 数据，用于验证页面结构、响应式布局和领域模型，不构成认证、授权或后端功能实现。

## 使用边界

- 数据源接口位于 `src/lib/api/united-pass-data-source.ts`。
- mock 实现位于 `src/lib/mock/united-pass-data-source.ts`。
- 公开演示凭据及浏览器端校验位于 `src/lib/mock/mock-auth.ts`。
- 页面只调用数据源接口暴露的方法，不直接维护硬编码记录。
- 搜索仅在浏览器内过滤当前 mock 列表；真实大数据集必须改为服务端分页和搜索。
- 登录只在浏览器中校验下方公开的演示凭据并跳转，不会创建 Cookie 或真实会话。注册、授权、撤销会话和管理变更均不持久化。
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

1. 根据 `docs/api-contracts.md` 与后端确认 OpenAPI 合同。
2. 在 `src/lib/api` 中实现真实 HTTP 数据源并统一处理基础 URL、凭据、取消请求、错误和运行时校验。
3. 在服务端组合层选择真实数据源；不要把访问令牌或私密环境变量传入 Client Component。
4. 移除页面中的 Mock 文案和预览动作，并补齐 pending、失败、unauthorized 与重试状态。
5. 保留 mock 作为测试 fixture 时，应移入测试专用目录，防止生产环境误用。
