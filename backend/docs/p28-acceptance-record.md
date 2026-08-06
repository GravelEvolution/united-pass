# P2.8 真实 Provider 验收记录

- 日期：2026-08-06
- 范围：Phase 2 任务书 P2.8 —— Apple container machine；ZITADEL v2.71；Provider Provisioning；Rotation；Delete；Compensation；环境清理；验收记录。
- 结论（如实记录，不写满）：
  - **confidential-client real-provider acceptance: passed**（Part 1–3，2026-08-06 首轮）；
  - **public-client real-provider acceptance: passed**（Part 4，2026-08-06 安全复核整改期补验，44/44 PASS）。
- 验收环境已拆除，`.env` 已恢复 fake provider 默认。

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

1. **RemoveApp 需要项目级成员身份（环境要求，非代码缺陷）**：SA 仅为组织 ORG_OWNER 时，AddOIDCApp / 轮转 Secret 均可成功，但 `RemoveApp` 返回 403 `AUTH-5mWD2 No matching permissions found`。将 SA 加入该项目并授予 `PROJECT_OWNER` 后恢复正常。**部署要求：provisioning 项目的 SA 必须同时拥有该项目 PROJECT_OWNER 成员身份。** 补验轮（Part 4）复测发现该成员身份在环境封存期间已丢失，由验收脚本重新授予后通过 —— 说明该授权不受 compose 生命周期之外的事件保护，部署检查必须包含它（见后续 readiness 整改项）。
2. **删除失败后客户端隐藏但可重试**：`delete_failed` 客户端对普通查询不可见，但删除状态机允许重试（`ListLiveClientsByApplication` 含 deleting/delete_failed 行），符合 ADR-0004 §6 设计。
3. **Provider 失败一律 fail closed**：轮转在 provider 调用失败时不推进本地状态、不吊销旧 Secret，并留下审计记录，与验收预期一致。
4. **TOTP 窗口**：同一 30s 窗口内的多次 reauth MFA 完成在 ZITADEL v2.71 上可通过；脚本仍以“等待新窗口”作为稳妥策略。
5. **`client_credentials` 限制（ADR-0004 Follow-up 补验，如实记录不冒充）**：以 provisioner 相同的参数形态（WEB + BASIC + authorization_code grant）创建 confidential app 后，用其 clientId/clientSecret 请求 `grant_type=client_credentials`，token 端点返回 `400 invalid_client: client not found`。结论：ZITADEL v2.71 仅对 machine/service user 提供 client_credentials。整改后 `server_to_server` Profile 在域校验层即被拒绝（422 provider capability），provisioner 同步 fail closed，不再产生“看似有效却无法使用”的凭据。
6. **登录标识符必须是 preferredLoginName（Part 4 补验发现）**：用户名携带外域后缀（`zhixing.lin@zitadel.localhost`）时，ZITADEL 将 preferredLoginName 派生为已验证邮箱（`zhixing.lin@example.com`）；Session API 的 loginName 检查只认前者。验收脚本已改用真实 loginName。
7. **v2.71 GetAppByID 不返回 `codeChallengeMethod` 字段（Part 4 补验发现）**：PKCE S256 由 `OIDC_APP_TYPE_USER_AGENT` 类型强制（该类型只允许 S256），断言以 app type + 授权码流程覆盖。

## 4. Part 4：Public Client（spa_mobile）补验（2026-08-06，44 PASS）

安全复核指出首轮验收未覆盖真实 public client，本轮在同一环境（machine 内 ZITADEL v2.71 + 隧道数据库）以自动化脚本补验，覆盖复核要求的五个验收点。

| 场景 | 断言 | 结果 |
| --- | --- | --- |
| 登录 | 密码登录 202 `mfa_required` → 真实 TOTP → 204 + 会话/CSRF Cookie；`/me` 返回本地 userId | ✅ |
| 创建 spa_mobile | `with-initial-client` 返回 201；**响应无 `clientSecret`**；详情 `clientType=public`、`tokenEndpointAuthMethod=none`、`clientSecrets=[]`、grantTypes=[authorization_code, refresh_token] | ✅ |
| Provider 断言 | ZITADEL app 存在且 `provider_application_id` 与本地一致；`appType=OIDC_APP_TYPE_USER_AGENT`；`authMethodType=OIDC_AUTH_METHOD_TYPE_NONE`；`responseTypes=[CODE]`；PKCE S256（USER_AGENT 强制）；redirectUris 同步（2 条）；`provisioning_status=provisioned` | ✅ |
| 全局唯一标识 | Provider 显示名为 `Public Acceptance App · SPA Public · {shortClientId}`，编入本地 clientId 尾段（Fix 3 幂等恢复标识） | ✅ |
| 禁用/启用 | disable → ZITADEL `APP_STATE_INACTIVE`；enable → `APP_STATE_ACTIVE` | ✅ |
| 轮转拒绝 | public client 的 secret-rotations 请求经 reauth 后返回 422（public client 无 Secret 可轮转） | ✅ |
| 删除 | 全新 reauth（`client.delete`）→ 204；ZITADEL 侧 app 同步移除；fixture 应用删除 204 | ✅ |
| 残留检查 | ZITADEL 项目内无验收残留 app | ✅ |

## 5. 环境清理确认

- 验收 fixture 应用与客户端已删除（ZITADEL 项目内 app 列表为空，两轮验收均已确认）；
- API 进程已停止，`docker compose down` 完成，无残留容器；
- `.env` 中 `UP_AUTH_PROVIDER*` / `UP_HTTP_ADDR` / `UP_PERMISSION_DEV_OVERRIDE*` 已注释，恢复 fake provider 默认，注释中保留真实项目 ID（384994263844257795）与 PROJECT_OWNER 部署要求供复现；
- 全部临时验收脚本（`.tmp-*`）已删除，未入库；
- `docs/HANDOFF_260806.md` 保持未跟踪，未提交。

## 6. 复现要点（供下一轮验收参考）

1. `docker compose -f docker-compose.zitadel.yml up -d` → `./scripts/zitadel-init.sh`；
2. SA 以 JWT profile（scope 含 `urn:zitadel:iam:org:project:id:zitadel:aud`）find-or-create 项目，并把 SA 加为项目 `PROJECT_OWNER` 成员（该授权可能在环境封存后丢失，脚本应幂等补授）；
3. `.env` 启用 zitadel provider（注意 machine 内 ZITADEL 占用 8080 时 API 需换端口）；machine 内无 psql 时可用本地 `postgres:16-alpine` 镜像经 `--network host` 执行 SQL 断言；
4. 迁移到最新版本后启动 API，依次验收：登录+TOTP（**登录标识符须使用 preferredLoginName，即派生邮箱**）→ Provisioning（confidential 与 public 两类）→ Rotation（reauth/一次性 Secret/no-store/token 单次）→ Delete → Compensation（撤销项目成员或删除 provider app 制造真实失败）。
