# Phase 6 飞书 Provider 实现冻结记录

- 日期：2026-08-11
- 状态：**IMPLEMENTATION PASSED / FROZEN；LIVE FEISHU PENDING**
- 基线：Phase 5 freeze `e96bc8a`
- 验收对象：United Pass schema migration `v9`、Feishu OAuth v2 / Contact v3 adapter

> Phase 6 已完成飞书登录、目录 staging、durable sync/history、冲突处理和
> 显式 identity linking 的产品代码与本地真实基础设施验证。当前工作区未配置
> `UP_FEISHU_APP_ID` / `APP_SECRET` / `TENANT_ID` / `REDIRECT_URL`，因此不能把
> 真实飞书租户登录或通讯录验收标记为 Passed。

## 1. 冻结范围

- 服务端 Feishu OAuth authorize、v2 code exchange 和 user-info lookup；
- Redis hash-keyed、TTL、SET-NX、GET-and-delete 单次 OAuth state；
- 仅通过精确 Provider/tenant/subject identity link 建立本地会话；
- server-only App Secret、内存 tenant token cache、回调后丢弃 user token；
- durable single-active sync job、stale claim、三次 bounded retry 和 history；
- 外部 department/user staging，与 United Pass workforce authority 完全隔离；
- 完整 snapshot checksum 幂等、partial snapshot 不下线未观察记录；
- email/name 候选提示、显式 stable `userId` resolution、target-bound reauth；
- Provider read/manage capability、CSRF、拒绝/成功 audit；
- P6 frontend real queries/commands、202 job UX、登录入口和 runtime parser；
- ADR-0012、frontend ADR-0008、OpenAPI 0.6.0 与人类可读合同同步。

通用 Provider 创建/编辑、浏览器 Secret 录入、SCIM/LDAP/SAML/CAS、按邮箱/姓名
自动合并、从飞书自动授予员工/Persona/权限、飞书 remote logout、Cerbos 和审计
导出均不在 P6 范围内。

## 2. P6-1–P6-13 验收矩阵

| ID | 结果 | 证据 |
| --- | --- | --- |
| P6-1 | ✅ PASS | config unit tests：partial credential 与错误 callback path fail closed；完整配置通过 |
| P6-2 | ✅ PASS | Redis real integration：state collision 拒绝、首次原子消费、replay not found |
| P6-3 | ✅ PASS | local Feishu protocol server：v2 token + user-info；授权 URL 不含 App Secret；token 不持久化 |
| P6-4 | ✅ PASS | service/unit + PostgreSQL integration：tenant mismatch 拒绝；只有 exact link 返回 active user |
| P6-5 | ✅ PASS | directory/OAuth unlinked identity 只写 pending suggestion；identity_links 保持 0 直到管理员 resolve |
| P6-6 | ✅ PASS | PostgreSQL real integration：重复 enqueue 返回同一 active `syncId`；durable claim/attempt 生效 |
| P6-7 | ✅ PASS | real integration：checksum upsert；partial snapshot 未把缺失 staging user 标为 inactive |
| P6-8 | ✅ PASS | real integration：同步后 `employee_profiles` 仍为 0；staging 表与 authority 表无写路径 |
| P6-9 | ✅ PASS | real integration：选定 stable `userId`、identity link、resolved conflict 和 audit 原子提交 |
| P6-10 | ✅ PASS | partial unique index + real integration：同 tenant 第二个 Feishu subject 关联同一 user 返回 conflict |
| P6-11 | ✅ PASS | frontend 16 files / 212 tests；Provider list/detail/job/conflict parsers 与 browser commands fail closed |
| P6-12 | ✅ PASS | 最终 static/unit/race/build、PostgreSQL/Redis integration+Race 全部通过 |
| P6-13 | ⏳ PENDING | 工作区没有真实飞书租户凭据，未执行真实飞书网页登录/通讯录 readback |

## 3. 安全与失效语义

- App Secret 只存在于 typed runtime config；数据库和 API 只有
  `secretConfigured` 布尔值；
- authorization code 与 user access token 只活在回调调用栈，tenant token 只在
  进程内缓存到提前过期；
- callback 先单次消费 state，再换码；任意 return URL 不进入协议；
- wrong tenant、unlinked subject、disabled Provider/user 均不能建会话；
- Provider directory 数据只是 observation，不创建本地用户/员工/部门成员/权限；
- partial failure 不下线未见 staging row；terminal failure 仅存 stable class；
- enable 先做实时 credential validation，再事务更新状态；
- resolve 使用 `provider.identity.link + conflictId` 的单次 reauth，并在同事务写 link/conflict/audit；
- 不宣称 PostgreSQL、Redis 与飞书存在分布式事务。

## 4. 门禁记录

| 类别 | 结果 | 记录 |
| --- | --- | --- |
| 本地静态检查 | Passed | backend `gofmt`、`git diff --check`、`go mod tidy` clean、两套 `go vet`、两套 `go build`；OpenAPI YAML 可解析、595 refs 全解析；frontend frozen install/lint/typecheck/build |
| 本地单元测试 | Passed | backend `go test ./...`；frontend 16 files / 212 tests |
| 本地 Race | Passed | backend `go test -race ./...` |
| 本地集成测试 | Passed | exact gate `go test -tags integration -race ./internal/adapters/postgres/... ./internal/adapters/redis/...`：PostgreSQL 558.140s、Redis 122.425s |
| 真实 ZITADEL 验收 | Pending | P6 本轮未重复执行真实 ZITADEL browser regression；既有 P5 freeze 证据不改写为本轮结果 |
| 真实飞书租户验收 | Pending | 未配置真实飞书 App/tenant credentials；没有冒充登录或通讯录通过 |
| GitHub Actions | 因额度耗尽暂未验证 | 根 `AGENTS.md`：远程 CI 当前不作为门禁 |

## 5. 集成超时整改

首轮 exact business suite 无 P6/既有断言失败，Redis Passed，但 PostgreSQL 因
每个场景通过 SSH 重复执行 9 个 head migrations，在既有 Consent 场景触发 Go
默认 10 分钟 package timeout。没有放宽 timeout。

最终 harness 保持测试串行并为每个场景 `TRUNCATE ... RESTART IDENTITY` 得到空
业务数据集，同时复用已迁移的专用 schema；migration-path 测试仍独立 drop 并从
00001/00005 验证 fresh/upgrade/fail-closed 路径。`TestMain` 在成功 package 结束时
删除专用 schema 内所有对象，异常终止后的下轮 setup 也会自动恢复到 head。

整改后全量非 Race PostgreSQL 为 483.790s；最终 exact integration+Race 为
558.140s，未改变默认 10 分钟 timeout，且 Redis 同轮 122.425s Passed。

## 6. 最终状态

| 项 | 状态 |
| --- | --- |
| Backend ADR-0012 | ACCEPTED / IMPLEMENTATION FROZEN |
| Frontend ADR-0008 | ACCEPTED |
| OpenAPI | 0.6.0 / 595 local refs resolved |
| Schema migration | `v9` integration-applied |
| P6-1–P6-12 | PASSED |
| P6-13 live Feishu | PENDING credentials |
| Blocking code defects | 0 |
| Phase 6 code implementation | **COMPLETE** |
