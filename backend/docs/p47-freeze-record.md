# Phase 4.7 冻结记录 — Remaining Account Security Real-Seam Migration

- 日期：2026-08-09
- 状态：**PASSED / FROZEN**（本 docs-only freeze commit 生效；真实 ZITADEL 端到端验收纳入 P4.9）
- 架构：ADR-0009
- 实现验收 head：`e0dcc47`（`feat(account): migrate remaining security seams`）

## 1. 谱系与范围

| Gate | Commit | 结论 |
| --- | --- | --- |
| P4.5 frozen baseline | `60dc6a7` | Passkey ceremony 已冻结；A14 live pending 继续携带 |
| P4.7 architecture | `86070b0` | password/TOTP/own-session/logout real-seam 与验收矩阵冻结 |
| P4.7 implementation + closure | `e0dcc47` | 20 files，full local gates + focused E2E 通过 |
| P4.7 official frozen head | 本 docs commit | docs-only 封箱，不改业务语义 |

本阶段只迁移已有后端真实契约：password change、TOTP lifecycle、当前用户
session inventory/revoke 与 current-session logout。Recovery Codes 继续
DEFERRED BY ARCHITECTURE；profile/avatar/contact/admin mutation 继续隔离在
Mock seam，未借机扩张。

## 2. 复审发现与关闭

### 2.1 Admin/current-user session 权限隔离

复审发现旧前端 `revokeSession` 同时被账户页与管理员用户详情页复用。若直接
迁移会把管理端按钮错误导向 `/me/sessions/{id}`。实现拆为：

- `revokeOwnSession(sessionId)`：P4.7 real seam；
- `revokeUserSession(userId, sessionId)`：管理端仍为独立 Mock seam。

因此管理端操作不会借 current-user route 越权或误撤调用者自己的会话。

### 2.2 P4.2 TOTP pending reachability reopen

provider-compatible factor fake 证明：invalid TOTP verification 后 provider
pending registration 仍存在，而冻结 handler 消耗本地 enrollmentToken；新的
begin 随后只会得到 `already set`。该证据满足 P4.2 reopen criterion。

`e0dcc47` 关闭方式：

- 错码先在 detached + bounded context 清理 provider pending，再消费 token；
- cleanup failure 释放 claim，并返回 provider failure，保留显式重试能力；
- 新增 capability-bound `POST /me/security/totp/enrollment/cancel`，关闭 setup
  modal 前结算 pending registration；无第二次 reauth grant；
- handler、route、OpenAPI、browser command 与 terminal/retry tests 同步。

这只修正冻结生命周期的可达性，不改变 provider authority、action binding 或
factor 状态来源。

### 2.3 Modal-close late-mutation race

统一 AbortController 覆盖 reauth request → optional WebAuthn/MFA → 单次 grant
consumer。关闭 modal 会 abort 整条链；晚到的 reauth 响应不能在 UI 关闭后继续
触发 password/TOTP/passkey mutation。

## 3. ADR-0009 acceptance

| ID | 结论 | 证据 |
| --- | --- | --- |
| A1 real mode 无对应 Mock seam | ✅ PASS | server/browser datasource 对所有 P4.7 seam 以 `USE_MOCK_DATA_SOURCE` 分流；real 分支均走 HTTP |
| A2 action/target 精确 | ✅ PASS | account action union 完整；password/TOTP target/application/client 均空；request contract tests |
| A3 password secret separation | ✅ PASS | reauth body 仅 current password；mutation body 断言严格等于 `{newPassword}` + constrained grant header |
| A4 password authoritative refresh | ✅ PASS | 204 后 `router.refresh()`；401/settlement re-login 分支清空本地新密码并跳登录；失败重新 reauth |
| A5 TOTP secret lifecycle | ✅ PASS | strict parser；secret/otpauth/token 仅 modal state；无 storage/log/URL state；close 先 cancel settlement |
| A6 TOTP terminal/retry | ✅ PASS | confirm body token+code；invalid-code provider cleanup 后 consume；cleanup failure release；handler tests |
| A7 TOTP removal readback | ✅ PASS | correct grant header；`SecuritySummary` parser 验证返回；成功后 server refresh |
| A8 complete session parser | ✅ PASS | nullable location、createdAt、auth methods、current flag 与 unknown fallbacks 均覆盖 |
| A9 targeted revoke | ✅ PASS | current row 无按钮；204 / stable 404 refresh；其他失败不改变 real rendered props |
| A10 bulk revoke | ✅ PASS | `{revoked}` non-negative integer validator；无 reauth header；current session backend invariant 保留 |
| A11 logout | ✅ PASS | real DELETE 完成后 redirect；401 视为已结束；其他失败显示 retry；Mock 仍独立 |
| A12 CSRF/header discipline | ✅ PASS | browser client 自动 CSRF；command tests 证明 grant header 只在 grant consumers |
| A13 scope isolation | ✅ PASS | Recovery UI 仅 Mock；profile/admin seams 未迁移；admin targeted session seam 已拆分 |
| A14 tests | ✅ PASS | validators、exact HTTP requests、immediate/MFA parser branches、TOTP settlement failures、Mock account E2E 8/8 |
| A15 live proof | ⏳ Pending | P4.9：真实 password settlement、TOTP、两会话 revoke/logout、secret sweep |

## 4. 门禁证据

| 类别 | 结论 | 记录 |
| --- | --- | --- |
| 本地静态检查 | Passed | `gofmt -w .`、`git diff --check`、`go mod tidy` + module clean、双 tag `go vet`、frontend lint/typecheck |
| 本地单元测试 | Passed | `go test ./...`；frontend Vitest 14 files / 196 tests |
| 本地 Race | Passed | `go test -race ./...` |
| 本地集成测试 | Passed | `.env` + SSH tunnel；PostgreSQL/Redis `-tags integration -race` 均通过（cached） |
| 本地 build | Passed | Go 普通/`integration` 双 build；Next.js 16.3.0 production build（Node 24.14.0 / pnpm 10.33.0） |
| focused browser E2E | Passed | `UP_E2E_PORT=3112 ... e2e/account.spec.ts --workers=1`：8/8 |
| 敏感信息扫描 | Passed | changed scope 无私钥/token key pattern；secret/password/token 无 console/storage/analytics sink |
| 真实 ZITADEL 验收 | Pending | A15；与 P4.5 live browser A14 一并在 P4.9 实演 |
| GitHub Actions | 因额度耗尽暂未验证 | 远程 CI 不作为当前门禁 |

`tunnel.sh start` 报告两个本地端口 ready；integration tests 完成后 `stop`
报告 `tunnel is not running`（未发现可停止 PID）。测试结果按实际记录，不把该
提示改写为 tunnel stop 成功。

## 5. P4.8 / P4.9 handoff

P4.8 只处理跨冻结阶段 settlement/observability hardening：

- provider 已终结后 enrollment Redis `ConsumeEnrollment` 失败的 detached、可观测
  收敛语义（P4.2 debt；同时覆盖 TOTP cancel 与 Passkey lifecycle）；
- partial bulk session revoke 的 durable failure forensic coverage。

P4.8 不改写 P4.1/P4.2/P4.3/P4.5/P4.7 的业务结果。

P4.9 必须以 pinned ZITADEL v2.71.18 完成 A15、P4.5 A14 与跨不变量 live matrix，
并保留真实证据；未实演前不得标记 Phase 4 complete。

## P4.9 closure amendment — 2026-08-09

A15 and the carried P4.5 A14 are Passed. Password/TOTP/session/logout,
`prompt=none`, browser passkey registration, provider active readback and
target-bound removal all passed. Historical Pending rows above remain as the
P4.7 freeze-time record and are superseded by this amendment.
