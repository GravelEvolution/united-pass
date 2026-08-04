# Mock 数据说明

当前初始化阶段使用集中式 mock 数据，用于验证页面结构、响应式布局和领域模型，不构成认证、授权或后端功能实现。

## 使用边界

- 数据源接口位于 `src/lib/api/united-pass-data-source.ts`。
- mock 实现位于 `src/lib/mock/united-pass-data-source.ts`。
- 页面只调用数据源接口暴露的方法，不直接维护硬编码记录。
- 搜索仅在浏览器内过滤当前 mock 列表；真实大数据集必须改为服务端分页和搜索。
- 登录、注册、授权、撤销会话和管理变更均不持久化。界面会明确显示 Mock 提示。
- mock 账户同时包含 `consumer` 人格和可选 `employeeProfile`，稳定 `userId` 不因员工档案关联而变化。

## 替换流程

1. 根据 `docs/api-contracts.md` 与后端确认 OpenAPI 合同。
2. 在 `src/lib/api` 中实现真实 HTTP 数据源并统一处理基础 URL、凭据、取消请求、错误和运行时校验。
3. 在服务端组合层选择真实数据源；不要把访问令牌或私密环境变量传入 Client Component。
4. 移除页面中的 Mock 文案和预览动作，并补齐 pending、失败、unauthorized 与重试状态。
5. 保留 mock 作为测试 fixture 时，应移入测试专用目录，防止生产环境误用。
