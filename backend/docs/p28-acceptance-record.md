# P2.8 真实 Provider 验收记录

- 日期：2026-08-06
- 范围：Phase 2 任务书 P2.8 —— Apple container machine；ZITADEL v2.71；Provider Provisioning；Rotation；Delete；Compensation；环境清理；验收记录。
- 结论（如实记录，不写满）：
  - **confidential-client real-provider acceptance: passed**（Part 1–3，2026-08-06 首轮）；
  - **public-client real-provider acceptance: passed**（Part 4，2026-08-06 安全复核整改期补验，44/44 PASS）；
  - **security-remediation real-provider re-acceptance (P2.8b): passed**（Part 5，2026-08-07 第二轮安全复核整改后补验，70/70 PASS，schema 版本 4）。
- **P2 最终冻结状态（2026-08-07）**：
  - Phase 2 implementation: complete
  - Phase 2 local real-provider acceptance: passed
  - Phase 2 local code review: passed
  - GitHub Actions verification: pending quota recovery
  - Production operational sign-off: pending
- 验收环境已拆除，`.env` 已恢复 fake provider 默认。

## 1. 验收环境

| 项目 | 值 |
| --- | --- |
| 执行环境 | Apple `container` machine `up-zitadel`（Ubuntu 24.04 arm64，Docker 29.7.1 + Compose v5.4.0 + go1.26.5），宿主工作区同路径挂载 |
| ZITADEL | v2.71.0，`docker-compose.zitadel.yml`，machine 内 `http://localhost:8080` |
| 初始化 | `scripts/zitadel-init.sh`（幂等通过）：测试 human 用户（密码 + TOTP）、后端 Service Account + JSON key、SA 授权为组织 ORG_OWNER |
| 项目 | ZITADEL 项目 "United Pass"（SA 通过 Management API find-or-create） |
| 后端 | `UP_AUTH_PROVIDER=zitadel`，监听 `127.0.0.1:8090`（首轮）/ `127.0.0.1:8081`（Part 5）；首轮迁移至 schema 版本 2，Part 5 补验时 migrations 已演进至 **版本 4**（00001–00004）并迁移到位；开发权限 override 仅对验收操作者生效 |
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

## 5. Part 5：P2.8b 第二轮安全复核整改后补验（2026-08-07，70 PASS）

首轮/Part 4 验收发生在第二批安全整改（Application 部分状态回滚、Reauth 放弃清理）之前，且验收时 schema 为版本 2；本轮在同一环境对整改后的实现补验，覆盖复核要求的七个验收点，schema 已迁移至版本 4。

| 场景 | 断言 | 结果 |
| --- | --- | --- |
| schema v4 migration | `cmd/migrate` 将测试 schema 从 v2 迁移至 v4（00003 持久化 Secret Rotation 状态 + 00004 Reconciliation 期望状态）无错误 | ✅ |
| confidential create | `with-initial-client`（audience=external，profile=web_server）201；一次性 Secret 64 字符；provider app ACTIVE 且 id 回写；第二个 confidential client 同样成功 | ✅ |
| durable rotation single-winner | 两个并发 reauth grant 同时轮转：恰好一个 200 一个 409；rotation gate 释放回 idle；secret 记录恰 2 条；`secret_rotated` 审计恰 1 条；无 reconciliation_required | ✅ |
| outcome_unknown | 轮转进行中 docker kill ZITADEL：返回 409 且错误说明结果未知；`secret_rotation_status=outcome_unknown`；`provider_reconciliation_required=true`；job reason=`provider_outcome_unknown`；审计 `secret_rotation_failed`（payload failure_class）+ `provider_reconciliation_required`；人工对账（确认 provider 侧未变更）后状态回 idle | ✅ |
| application partial enable rollback | A 启用成功、B 失败（provider app 指向不存在 id，409 provider_conflict）：应用本地保持 disabled；**A 被 best-effort 回滚为 INACTIVE（kill switch 未被绕过）**；回滚成功不产生 drift job；恢复后 enable 成功 | ✅ |
| application partial disable drift | disable 中途失败：应用本地保持 active（不假装成功）；已切换的 A 保持 INACTIVE（fail-safe 方向）；drift job reason=`disable_partial:provider_conflict` 且 **desired_status=disabled**（migration 00004）；审计 `provider_reconciliation_required` 新增 1 条 | ✅ |
| reauth abandoned challenge cleanup | reauth step1 202 后放弃：cleanup-index 存在含 providerSessionId 的 member；challenge key 存活；TTL（45s）过期后 worker 撤销日志出现且 index 清空（ZCARD=0）；过期 challenge 完成 MFA 被拒 401；ZITADEL 侧 session 确认终态；Phase 自身无新增 `revoke_failed` 审计 | ✅ |
| transactional audit | 全场景审计表落库 ≥ 10 行；成功审计 outcome 均为 success/denied 枚举；`secret_rotated` 审计与 secret 记录同事务并存 | ✅ |
| fixture 清理 | reauth（client.delete/application.delete）后全部 204；app 软删除；ZITADEL 项目内无残留 app（APP_COUNT: 0） | ✅ |

### Part 5 如实记录的问题与语义说明

1. **enable/disable 中途失败返回 409 而非 502**：注入方式为将 `provider_application_id` 指向不存在的 provider app，错误被分类为 `provider_conflict`（409），非 `provider.unavailable`（502）。回滚/drift 逻辑与错误分类无关，两种分类下行为一致。
2. **client 本地 status 不随应用 kill switch 联动（既定模型）**：应用 disable/enable 只切换 provider 侧 Client 状态，不修改 client 本地 `status`；enable 时会跳过被单独禁用的 client（保持禁用）。这与 ADR-0004 的 kill switch 语义一致，验收未将其断言为缺陷。
3. **Phase 4 期间存在 1 条 `provider_session.revoke_failed` 审计（预期行为）**：ZITADEL down 期间 client.delete 后的 best-effort provider session 撤销失败，按设计落 denied 审计（failure_class=internal）。Part 5 断言采用增量方式，确认 cleanup 路径自身不产生新的 revoke 失败。
4. **SA PROJECT_OWNER 授权再次需要幂等补授**：与 Part 4 相同，环境封存后 SA 的项目成员身份丢失，验收脚本重新授予后通过；部署要求不变（见第 3 节问题 1）。
5. **reauth 限流默认偏紧**：补验脚本需显式提高 `UP_REAUTH_RATE_LIMIT`（默认额度不足以支撑连续多场景 reauth）；生产默认值保持不变（fail closed 方向）。

## 6. 环境清理确认

- 验收 fixture 应用与客户端已删除（ZITADEL 项目内 app 列表为空，两轮验收均已确认）；
- API 进程已停止，`docker compose down` 完成，无残留容器；
- `.env` 中 `UP_AUTH_PROVIDER*` / `UP_HTTP_ADDR` / `UP_PERMISSION_DEV_OVERRIDE*` 已注释，恢复 fake provider 默认，注释中保留真实项目 ID（384994263844257795）与 PROJECT_OWNER 部署要求供复现；
- 全部临时验收脚本（`.tmp-*`）已删除，未入库；
- `docs/HANDOFF_260806.md` 保持未跟踪，未提交。

## 7. 复现要点（供下一轮验收参考）

1. `docker compose -f docker-compose.zitadel.yml up -d` → `./scripts/zitadel-init.sh`；
2. SA 以 JWT profile（scope 含 `urn:zitadel:iam:org:project:id:zitadel:aud`）find-or-create 项目，并把 SA 加为项目 `PROJECT_OWNER` 成员（该授权可能在环境封存后丢失，脚本应幂等补授）；
3. `.env` 启用 zitadel provider（注意 machine 内 ZITADEL 占用 8080 时 API 需换端口）；machine 内无 psql 时可用本地 `postgres:16-alpine` 镜像经 `--network host` 执行 SQL 断言；
4. 迁移到最新版本后启动 API，依次验收：登录+TOTP（**登录标识符须使用 preferredLoginName，即派生邮箱**）→ Provisioning（confidential 与 public 两类）→ Rotation（reauth/一次性 Secret/no-store/token 单次）→ Delete → Compensation（撤销项目成员或删除 provider app 制造真实失败）。
