# 显式开发 Fixture 说明

`src/lib/mock/united-pass-data-source.ts` 保留一套与生产合同同形的固定数据，只用于
组件开发、单元测试和可重复的界面演示。它不是认证、授权或持久化实现。

## 使用边界

- `src/lib/api/data-source-mode.ts` 是读取 `NEXT_PUBLIC_USE_MOCK` 的唯一位置。
- 只有精确值 `true` 才让 `UnitedPassQueries` / `UnitedPassCommands` 选择 fixture；
  未设置、`false` 或其他值都让每个 seam 调用真实 HTTP API。
- 密码登录、注册、邮箱验证和密码恢复不受 fixture 开关影响，始终调用真实后端。
  仓库不再提供浏览器端 Mock 登录凭据或只跳转、不建立 `up_session` 的伪登录。
- 受保护页面始终执行服务端 Session / capability 门禁；fixture 不能授予权限。
- 页面只依赖数据源接口，不得直接导入 fixture 或在组件内维护硬编码业务记录。
- fixture 的搜索/分页仅用于小型演示集合；生产由后端执行权限过滤、字段裁剪、
  稳定排序、游标分页和搜索。
- Recovery Codes 因 Provider 能力保持 Deferred，任何模式都不生成可能被误认为真实
  凭据的代码或成功态。

## 当前生产覆盖

生产 HTTP 层覆盖全部数据源 seam，包括：

- 当前用户、权限、资料、头像、验证邮箱/手机号、安全因子与会话；
- OAuth 授权、Grant、Application / Client 全生命周期和 Secret 轮换；
- 用户、员工、部门、飞书 Provider、目录同步与显式身份冲突；
- 策略、审计、管理仪表盘、个人数据导出与延迟注销；
- 公开注册、邮箱验证和抗账户枚举的密码找回/重置。

每个真实响应都在 `src/lib/api/response-validators.ts` 收窄后才进入领域类型；生产
分支不存在失败后回写 fixture 或静默成功的逻辑。

## 本地选择

真实联调（默认）：

```dotenv
NEXT_PUBLIC_USE_MOCK=false
API_BASE_URL=http://localhost:8080/api/v1
```

非认证页面 fixture：

```dotenv
NEXT_PUBLIC_USE_MOCK=true
API_BASE_URL=http://localhost:8080/api/v1
```

浏览器请求仍固定走同源 `/api/v1`。fixture 开关是公开构建配置，不能承载任何秘密。
