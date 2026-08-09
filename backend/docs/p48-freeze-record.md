# Phase 4.8 冻结记录 — Settlement and Partial-Revoke Hardening

- 日期：2026-08-09
- 状态：**PASSED / FROZEN**（本 docs-only freeze commit 生效；真实 ZITADEL 跨不变量验收纳入 P4.9）
- 架构：ADR-0010
- 实现验收 head：`b0ef98b`（`fix(security): harden settlement and revoke forensics`）

## 1. 谱系与范围

| Gate | Commit | 结论 |
| --- | --- | --- |
| P4.7 frozen baseline | `0b6aa6e` | password/TOTP/session/logout real seam 已冻结，live A15 继续携带至 P4.9 |
| P4.8 architecture | `353df32` | ADR-0010 冻结 settlement 与 partial-revoke forensic 语义 |
| P4.8 implementation | `b0ef98b` | detached bounded retry、partial durable audit 与回归证据完成 |
| P4.8 official frozen head | 本 docs commit | docs-only 封箱，不改业务语义 |

P4.8 仅关闭两个已登记技术债：provider outcome 已确定后的 enrollment
finalization 收敛，以及 Redis bulk revoke 部分成功时的 durable forensic gap。
没有新增端点、数据库迁移、Redis scan、provider mutation retry 或用户可见功能。

## 2. 冻结实现

### 2.1 Enrollment finalization

TOTP/passkey confirm、cancel 以及 claim 后的 binding/security-gate rejection
统一进入三模式 helper：`consume`、`abandon`、`release`。helper 使用
`context.WithoutCancel(requestContext)` + 2 秒 hard timeout，最多尝试三次，
退避 25ms/50ms；`ErrEnrollmentNotHeld` 视为幂等完成。

重试耗尽只发出一次 `security.enrollment_finalization_degraded`，字段固定为
`userId`、`factorKind`、`finalizationMode`、`outcome=degraded`、`errorClass`。
HTTP 始终保持 provider outcome；日志不含 enrollment token/hash、claim ID、
TOTP secret/code、credential 或 provider error detail。

### 2.2 Partial bulk revoke forensics

`Store.RevokeAllOtherSessions` 返回 `victims + count + err` 时，service 先对每个
已删除 victim 尝试 provider cleanup，再在 `count > 0` 时记录一条 durable
`session.revoked_others`：

- `result=denied`，表示完整请求契约未成功；
- target 仍为 current session ID；
- `failure_class` 是 store failure 的稳定分类；
- `revoked_count` 是已本地删除的精确数量；
- `provider_failure_class` 独立携带首个 provider cleanup failure（若有）。

零 victim 的 infrastructure failure 仍只写 structured log；完整成功仍为
`success`，新增 `revoked_count`，provider degradation 继续留在既有
`failure_class`，不改历史含义。

### 2.3 Audit attempt boundary

session revocation 的 durable audit 在本地 mutation 后以 detached、2 秒 bounded
context 尝试。客户端取消不能抹掉取证尝试；PostgreSQL 故障仍是 best-effort，
只产出既有安全 warning，不反写已经完成的 session outcome。本阶段不引入 outbox，
也不宣称数据库故障期间 guaranteed delivery。

## 3. ADR-0010 acceptance

| ID | 结论 | 证据 |
| --- | --- | --- |
| H1 | ✅ PASS | canceled request 下 TOTP terminal consume 的每次 store context 均未取消 |
| H2 | ✅ PASS | consume/release/abandon 均注入两次 transient failure，第三次收敛；HTTP provider-success 保持 200 |
| H3 | ✅ PASS | 重试耗尽精确一条 degraded event；token/code/secret 泄漏断言为否 |
| H4 | ✅ PASS | `ErrEnrollmentNotHeld` 单次完成且无 degraded event |
| H5 | ✅ PASS | TOTP confirm/cancel、passkey confirm/cancel 和 claim 后拒绝路径均调用 shared helper |
| H6 | ✅ PASS | zero-victim failure = 0 durable rows；partial failure = exactly 1 denied row |
| H7 | ✅ PASS | partial event 精确断言 count=2、store class=internal、provider class=internal |
| H8 | ✅ PASS | successful bulk 保持 success 且 count=1；targeted audit 不增加 bulk-only 字段 |
| H9 | ✅ PASS | canceled caller 下 auditor 收到有效 detached context；recorder error 不掩盖 revoke |
| H10 | ✅ PASS | full backend gates、PostgreSQL/Redis integration race、sensitive diff scan 全绿 |

## 4. 门禁证据

| 类别 | 结论 | 记录 |
| --- | --- | --- |
| 本地静态检查 | Passed | `gofmt -w .`、`git diff --check`、`go mod tidy` + module clean、`go vet ./...`、`go vet -tags integration ./...` |
| 本地单元测试 | Passed | `go test ./...` |
| 本地 Race | Passed | `go test -race ./...` |
| 本地集成测试 | Passed | `.env` + SSH tunnel；`go test -tags integration -race ./internal/adapters/postgres/... ./internal/adapters/redis/...`：PostgreSQL 379.765s，Redis Passed（cached） |
| 本地 build | Passed | `go build ./...`、`go build -tags integration ./...` |
| 敏感信息扫描 | Passed | staged scope 无 private-key/access-token pattern，且未出现 `.env` 中长度 ≥12 的值 |
| 真实 ZITADEL 验收 | Pending | P4.9：password settlement、TOTP、双会话 revoke/logout、passkey browser ceremony 与 secret sweep |
| GitHub Actions | 因额度耗尽暂未验证 | 远程 CI 不作为当前门禁 |

`tunnel.sh start` 报告 PostgreSQL/Redis 两个本地端口 ready；集成测试结束后
`stop` 报告 `tunnel is not running`，按实际保留，不改写为 stop success。

## 5. Debt closure 与剩余边界

- P4.2 的「provider-success 后 enrollment Redis consume 仅 Warn」debt 已由
  shared detached bounded retry、幂等完成与安全 degraded event 关闭；
- P4.1 的 partial bulk revoke durable forensic gap 已由 denied + exact side-effect
  payload 关闭，未改变 frozen HTTP result；
- 连续 Redis outage 最终仍由 capability TTL/provider-authoritative readback 收敛；
- audit-store outage 仍无 guaranteed delivery，这是 ADR-0010 明确接受的非目标；
- Recovery Codes、profile/admin mutations 与 OAuth/consent 均未重开。

## 6. 正式状态与下一阶段

| 项 | 状态 |
| --- | --- |
| P4.8 Settlement / Observability Hardening | PASSED / FROZEN |
| Blocking defects | 0 |
| Scope leakage | 0 |
| 下一阶段 | P4.9 pinned ZITADEL v2.71.18 live acceptance；完成前 Phase 4 不得标记 complete |

## P4.9 closure amendment — 2026-08-09

The live cross-invariant matrix is Passed. Enrollment settlement converged for
real TOTP and browser passkey flows; active-preservation held until explicit
target-bound removal; targeted/bulk revoke, logout and provider readbacks all
matched the frozen contracts. Phase 4 is complete/frozen, with P4.6 Recovery
Codes still architecture-deferred and non-blocking.
