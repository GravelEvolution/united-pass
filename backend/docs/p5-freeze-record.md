# Phase 5 身份与员工管理最终冻结记录

- 日期：2026-08-11
- 状态：**PASSED / FROZEN**（本 final freeze commit 生效）
- 基线：Phase 4 final freeze `7e5be5a`
- 验收对象：pinned ZITADEL `v2.71.18`、United Pass schema migration `v8`

> Phase 5 将用户、员工档案和部门管理从冻结的前端 seam 接入真实后端。
> 员工始终是稳定 `userId` 上的可选档案，不创建第二账户；离职不删除
> consumer persona 或 OAuth grant。

## 1. 冻结范围

本轮冻结以下权威能力：

- 用户、员工和部门的真实服务端查询、搜索和分页；
- 显式以既有稳定 `userId` 关联员工档案；
- 部门树创建、更新、循环检测和非空删除保护；
- 用户启用/禁用、员工离职和单个/全部用户会话撤销；
- high-risk 操作的 actor-session/action/target 单次 reauth binding；
- PostgreSQL 权威状态、审计和 access-revocation job 的事务提交；
- Redis 本地会话收敛与 ZITADEL provider session 的审计型 best effort；
- frontend runtime response validation、真实 API commands 和受保护布局会话门禁。

恢复/返聘、SCIM/LDAP/SAML/CAS、自动按邮箱或域名关联、员工邀请、离职时
撤销 consumer OAuth grants 均不在 Phase 5 范围内。

## 2. 真实环境校准

- ZITADEL 使用 `ghcr.io/zitadel/zitadel:v2.71.18`，不是浮动 tag。
- 开发数据库通过正式 `cmd/migrate up` 从 `v7` 升至 `v8`；没有手工改 schema。
- backend、frontend 和同源 acceptance proxy 均使用本轮真实代码；frontend
  browser matrix 使用 Node `v24.17.0` 的 `next build` + `next start`，Mock 关闭。
- 浏览器登录使用真实 ZITADEL password + TOTP，United Pass `up_session` 由真实
  登录流程建立；没有向浏览器注入伪造 session。
- PostgreSQL/Redis integration 通过既有 SSH tunnel 与 `backend/.env` 的
  `UP_TEST_*` 配置执行。外部 tunnel 本轮已存在且保持不变。

## 3. W1–W14 acceptance matrix

| ID | 结果 | 证据 |
| --- | --- | --- |
| W1 | ✅ PASS | PostgreSQL integration 与 live user detail 均证明关联后保持同一 `userId`、`consumer + employee` personas；consumer account/OAuth grants 未删除 |
| W2 | ✅ PASS | 两个并发 `LinkEmployee` 只有一个成功，另一个 conflict/serialization loser；数据库仅有一个 profile/employee number |
| W3 | ✅ PASS | mutation input 只接受稳定 `userId`；service regression test 拒绝以 contact fact 选择身份；live 稳定 ID 搜索精确命中 1 条 |
| W4 | ✅ PASS | sibling name unique index、serializable hierarchy mutation 和 recursive ancestor check；integration 与 live cycle update 均返回拒绝（live 409） |
| W5 | ✅ PASS | 有子部门或员工的部门删除在 integration 和 live 均失败且无部分变更（live 409） |
| W6 | ✅ PASS | 所有 16 个 workforce handler 在读取/变更前独立调用 capability authorize；denial unit test 断言 403、零 mutation、denied audit |
| W7 | ✅ PASS | handler/unit + live：grant 精确绑定 session/action/target；错误 target 返回 403 且 grant 已消费，随后 replay 仍为 403 |
| W8 | ✅ PASS | integration 在一次 transaction 中观察到 offboarding profile、success audit、cleanup job；失败不会形成半提交 |
| W9 | ✅ PASS | workforce guard 在 base allow 前检查 durable offboarding deny；unit fail-closed；live 离职后目标仍为 active consumer account 但员工状态为 offboarding |
| W10 | ✅ PASS | cleanup ledger 只保存 stable error class/attempt count；无 token、provider handle、password 或 raw error；Redis cleanup 可重试且幂等 |
| W11 | ✅ PASS | user/employee query 使用 1–100 page limit 和 HMAC opaque cursor；cursor 绑定完整 query，篡改/换查询返回 400；stable ID search 返回 1 条 |
| W12 | ✅ PASS | frontend runtime parsers 覆盖 capabilities、cursor pages、user detail、employee profile、department detail；malformed fixtures fail closed |
| W13 | ✅ PASS | 最终 backend static/unit/race/build 与 PostgreSQL/Redis integration+Race 全部通过 |
| W14 | ✅ PASS | configured ZITADEL-backed runtime 完成真实登录、目录查询、关联、部门约束、禁用/启用、session revoke、offboarding 与 browser readback |

## 4. 真实 HTTP 与浏览器矩阵

验收 actor 为真实 ZITADEL 用户；开发环境仅为该 actor 配置冻结 capability
override。业务授权仍由每个 backend route 强制执行。

| 场景 | 结果 |
| --- | --- |
| 当前用户与权限 | `/me` 200；`/me/permissions` 200；actor 具备验收所需 capability |
| 用户分页 | `limit=200` 按合同裁剪并返回 opaque cursor；带旧 cursor 更换 query 返回 400 |
| 稳定 ID 搜索 | API 与 `/admin/users?q=<userId>` 均精确返回 1 条；浏览器显示 `外部用户 · 员工` |
| 部门创建 | root 与 child 均 201；browser 列表显示 2 条和正确 parent/member count |
| 部门安全 | root 指向 child 的 cycle update 409；非空 root delete 409 |
| 员工关联 | 两个既有 consumer 账户均 201；employee number 由服务器生成；详情保留稳定 `userId` |
| 禁用/启用 | target-bound reauth 后 disable 204、enable 204；禁用事务清空其 owner/supervisor assignment |
| 错 target/replay | grant 用于错误 target 返回 403；同一 grant 再用于正确 target 仍返回 403 |
| 管理员 bulk revoke | 新鲜 target-bound grant 后 204；durable job 与本地 session convergence seam 生效 |
| 离职 | 202；profile 为 `offboarding`；consumer account 仍 `active`，personas 仍为 `consumer + employee` |
| 离职关系清理 | target 的 department owner 与 subordinate supervisor references 在同一事务内归零 |
| actor 隔离 | target lifecycle 后 actor `/me/permissions` 仍为 200 且 `user.read=true` |
| browser 员工目录 | 真实页面显示 2 条：一条 active、一条 `离职处理中` |
| browser 部门详情 | child 显示 parent、2 名成员及各自稳定用户链接；离职 owner 不再显示 |
| 未登录保护 | 退出后直达 `/admin/employees` 服务端回到 `/login`，不再落入通用错误页 |

真实验收数据保留在开发实例作为冻结证据。Phase 5 没有恢复/删除 employee
profile 的产品 seam，因此没有用 direct SQL 绕过产品合同清除这些记录。

## 5. 事务与失效语义

- linking 把 employee profile、employee persona 和 success audit 一次提交；
- disable/offboarding 把权威状态、owner/supervisor 清理、audit 和需要时的 durable
  cleanup job 一次提交；
- offboarding durable deny 不等待 Redis 或 provider；
- background reconciler 只负责可安全重试的 United Pass/Redis 收敛；
- provider revoke 仅在 encrypted reference 仍存在时 best effort。若 local record 已
  删除而 provider revoke 失败，记录稳定 degraded class 并依赖 provider expiry，
  不持久化 credential 以伪造分布式事务。

## 6. 门禁记录

| 类别 | 结果 | 记录 |
| --- | --- | --- |
| 本地静态检查 | Passed | backend `gofmt`、`git diff --check`、`go mod tidy` clean、两套 `go vet`、两套 `go build`；OpenAPI 512 个 local refs 全解析；frontend frozen install、lint、typecheck、build |
| 本地单元测试 | Passed | backend `go test ./...`；frontend 15 files / 207 tests |
| 本地 Race | Passed | backend `go test -race ./...` |
| 本地集成测试 | Passed | PostgreSQL `-tags integration -race` 509.811s；Redis 首轮 73.252s，最终同代码命中 Go test cache |
| 真实 ZITADEL 验收 | Passed | password + TOTP login、target-bound reauth、真实 admin HTTP/browser matrix 全部通过 |
| GitHub Actions | 因额度耗尽暂未验证 | 根 `AGENTS.md`：远程 CI 当前不作为门禁 |

### 6.1 集成超时整改

首轮完整 integration+Race 没有业务断言失败，但新增的 6 个 P5 测试各自重复
drop/migrate，PostgreSQL package 在默认 10 分钟处进入最后场景 setup 时超时。
最终实现把 P5 场景改为一次真实建库、顺序唯一 ID 子场景共享连接；没有放宽
timeout，也没有删除 W1–W11 关键断言。定向耗时从 57.578s 降至 26.088s，随后
原命令完整通过（509.811s）。

## 7. Phase 5 最终状态

| 项 | 状态 |
| --- | --- |
| Identity/workforce ADR | ACCEPTED / FROZEN |
| Schema migration | `v8` APPLIED |
| W1–W14 | PASSED |
| Blocking defects | 0 |
| Scope leakage | 0 |
| Phase 5 | **COMPLETE / FROZEN** |
