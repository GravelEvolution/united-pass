# P2.8 真实 Provider 验收记录

- 日期：2026-08-06
- 范围：Phase 2 任务书 P2.8 —— Apple container machine；ZITADEL v2.71；Provider Provisioning；Rotation；Delete；Compensation；环境清理；验收记录。
- 结论：**全部验收项通过**。验收环境已拆除，`.env` 已恢复 fake provider 默认。

## 1. 验收环境

| 项目 | 值 |
| --- | --- |
| 执行环境 | Apple `container` machine `up-zitadel`（Ubuntu 24.04 arm64，Docker 29.7.1 + Compose v5.4.0 + go1.26.5），宿主工作区同路径挂载 |
| ZITADEL | v2.71.0，`docker-compose.zitadel.yml`，machine 内 `http://localhost:8080` |
| 初始化 | `scripts/zitadel-init.sh`（幂等通过）：测试 human 用户（密码 + TOTP）、后端 Service Account + JSON key、SA 授权为组织 ORG_OWNER |
| 项目 | ZITADEL 项目 "United Pass"（SA 通过 Management API find-or-create） |
| 后端 | `UP_AUTH_PROVIDER=zitadel`，监听 `127.0.0.1:8090`，迁移至 schema 版本 2；开发权限 override 仅对验收操作者生效 |
| 数据库访问 | machine 内 `127.0.0.1:15432` 隧道 → 远端 dev PostgreSQL |

## 2. 验收结果

自动化验收脚本在 machine 内驱动真实 HTTP API + ZITADEL Management API + SQL 断言，共三部分。

### Part 1：Provisioning / Rotation / Delete（15 PASS）

| 场景 | 断言 | 结果 |
| --- | --- | --- |
| 登录 | 密码登录返回 202 `mfa_required`（仅暴露 `totp`）；真实 TOTP 完成后 204 + 会话 Cookie + CSRF Cookie | ✅ |
| 身份映射 | `/me` 返回本地 userId（ZITADEL subject → 本地 identity link） | ✅ |
| 创建应用 + 初始 client | `with-initial-client` 返回 `app_*`/`clt_*` + 64 字符一次性 Secret | ✅ |
| Provider Provisioning | ZITADEL 项目内恰好出现对应 app；本地 `provider_application_id` 与 ZITADEL 一致、`provisioning_status=provisioned`；列表中无半完成态泄漏 | ✅ |
| 第二个 confidential client | 创建成功并返回一次性 Secret | ✅ |
| Reauthentication | 轮转前强制 password + TOTP 二次认证，签发单次 grant | ✅ |
| Secret 轮转 | 返回新 `sec_*` + 一次性 Secret；响应头 `Cache-Control: no-store` + `Pragma: no-cache`；reauth token 复用被拒（单次消费）；DB 记录 2 条（旧记录标记已轮转）；审计事件 `oauth_client.secret_rotated` | ✅ |
| Client 删除 | 全新 reauth（`client.delete`）后删除返回 204；ZITADEL 侧 app 同步移除 | ✅ |

### Part 2：Compensation（真实 Provider 失败）+ 应用删除（14 PASS）

| 场景 | 断言 | 结果 |
| --- | --- | --- |
| 撤销 SA 项目成员后删除 client | 返回 502 `provider.unavailable`；`provider_reconciliation_required=true`；`provider_reconciliation_jobs` 落 1 行；审计事件 `oauth_client.provider_reconciliation_required` | ✅ |
| 恢复成员后重试删除 | delete_failed 状态可重试（`MarkClientDeletingRetry`），返回 204 | ✅ |
| 应用删除 | reauth（`application.delete`）后返回 204；ZITADEL 侧 app 全部移除 | ✅ |

### Part 3：软删除语义 + 轮转 fail-closed（10 PASS）

| 场景 | 断言 | 结果 |
| --- | --- | --- |
| 软删除 | 已删应用/客户端 `deleted_at` 置位、列表与详情不可见（404）；删除审计事件齐备 | ✅ |
| 轮转补偿（真实失败） | 将 `provider_application_id` 指向不存在的 provider app 后轮转：返回 409 `state.conflict`（fail closed）；审计 `oauth_client.secret_rotation_failed`；原活动 Secret 记录不变 | ✅ |
| 补偿 fixture 清理 | 恢复 provider id 后经 API 删除 fixture 应用，204，ZITADEL 项目清空 | ✅ |

## 3. 发现的问题与结论

1. **RemoveApp 需要项目级成员身份（环境要求，非代码缺陷）**：SA 仅为组织 ORG_OWNER 时，AddOIDCApp / 轮转 Secret 均可成功，但 `RemoveApp` 返回 403 `AUTH-5mWD2 No matching permissions found`。将 SA 加入该项目并授予 `PROJECT_OWNER` 后恢复正常。**部署要求：provisioning 项目的 SA 必须同时拥有该项目 PROJECT_OWNER 成员身份。**
2. **删除失败后客户端隐藏但可重试**：`delete_failed` 客户端对普通查询不可见，但删除状态机允许重试（`ListLiveClientsByApplication` 含 deleting/delete_failed 行），符合 ADR-0004 §6 设计。
3. **Provider 失败一律 fail closed**：轮转在 provider 调用失败时不推进本地状态、不吊销旧 Secret，并留下审计记录，与验收预期一致。
4. **TOTP 窗口**：同一 30s 窗口内的多次 reauth MFA 完成在 ZITADEL v2.71 上可通过；脚本仍以“等待新窗口”作为稳妥策略。
5. **`client_credentials` 限制（ADR-0004 Follow-up 补验，如实记录不冒充）**：以 provisioner 相同的参数形态（WEB + BASIC + authorization_code grant）创建 confidential app 后，用其 clientId/clientSecret 请求 `grant_type=client_credentials`，token 端点返回 `400 invalid_client: client not found`。结论：ZITADEL v2.71 仅对 machine/service user 提供 client_credentials；`server_to_server` profile 可正常 provision/轮转/删除，但无法经项目 app 获取 client_credentials token。限制已在 ADR-0004 Follow-up 与本记录中披露。

## 4. 环境清理确认

- 验收 fixture 应用与客户端已删除（ZITADEL 项目内 app 列表为空）；
- API 进程已停止，`docker compose down` 完成，无残留容器；
- `.env` 中 `UP_AUTH_PROVIDER*` / `UP_HTTP_ADDR` / `UP_PERMISSION_DEV_OVERRIDE*` 已注释，恢复 fake provider 默认，并在注释中记录 PROJECT_OWNER 部署要求；
- 全部临时验收脚本（`.tmp-*`）已删除，未入库；
- `docs/HANDOFF_260806.md` 保持未跟踪，未提交。

## 5. 复现要点（供下一轮验收参考）

1. `docker compose -f docker-compose.zitadel.yml up -d` → `./scripts/zitadel-init.sh`；
2. SA 以 JWT profile（scope 含 `urn:zitadel:iam:org:project:id:zitadel:aud`）find-or-create 项目，并把 SA 加为项目 `PROJECT_OWNER` 成员；
3. `.env` 启用 zitadel provider（注意 machine 内 ZITADEL 占用 8080 时 API 需换端口）；
4. 迁移到最新版本后启动 API，依次验收：登录+TOTP → Provisioning → Rotation（reauth/一次性 Secret/no-store/token 单次）→ Delete → Compensation（撤销项目成员或删除 provider app 制造真实失败）。
