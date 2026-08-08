# Phase 4.1 冻结记录 — Session Inventory & Lifecycle

- 日期：2026-08-08
- 范围：P4.1 —— Session domain（fail-closed SessionID、展示元数据、EffectiveExpiry、remember 跨 MFA 修复）、Redis SessionStore inventory（ZSET + locator + Lua 原子操作）、Service 层撤销生命周期（provider 撤销 + 安全事件）、HTTP `/me/sessions` 契约。
- 状态：**PASSED / FROZEN**

## 1. 冻结谱系

| 项 | 值 |
| --- | --- |
| P4.0 frozen head | `f28e29edeccc396a14c60c8284b2f2495deb1bf5`（`docs(adr): verify passkey registration capability`） |
| Implementation acceptance head | `c9d2af2`（`feat(session): session inventory and lifecycle management (P4.1)`，13 files，+2107/-125） |
| Test-only follow-up | `c1672da`（`test(redis): relax reauth cleanup timing for tunnel latency`，+4/-4；预存在 flake，frozen head 上独立复现，非产品行为变化） |
| Official P4.1 frozen head | 本 freeze commit（docs-only，append-only 追加于 `c1672da` 之后） |
| Blocking defects | 0 |
| P4.2+ scope leakage | 0 |

## 2. 复审通过的核心不变量

| 不变量 | 实现 |
| --- | --- |
| 多键会话变更原子性 | Create / Delete / Touch / Rotate 各为独立 Lua 脚本（`redis.NewScript`）；Delete 在同一脚本内解析 record → DEL record → DEL locator → ZREM inventory，无中间态窗口。禁 pipeline |
| EffectiveExpiry 单一定义 | `EffectiveExpiry(idleTTL) = idleTTL<=0 ? ExpiresAt : min(ExpiresAt, LastSeenAt+idleTTL)`；所有 ZSET score 由此派生（UnixMilli）；与 `IsExpired` 同源，杜绝 List 显示 active 而 RequireSession 判 expired 的分叉 |
| Inventory ZSET 模型 | `user_sessions:{userId}`（member=SessionID，score=effectiveExpiryUnixMilli）→ `session_locator:{sessionId}` → `session:{tokenHash}`；禁 KEYS / SCAN |
| Stale 自愈 | locator/record 缺失或过期的 ZSET 成员：DEL locator + ZREM member，永不作为 active 返回 |
| RevokeAllOthers | 仅 `ZRANGE` 当前用户自己的 ZSET，成员级排除 current SessionID；不跨用户、不扫全库、不误杀当前会话 |
| SessionID fail-closed | `crypto/rand` 失败即失败，无 timestamp/counter fallback |
| remember 跨 MFA | `MFAChallengeData.Remember` 携带登录时选择 → CompleteMFA → 正确 TTL（remember=true → rememberTTL；false → shortTTL），含回归测试 |
| 非枚举契约 | unknown / foreign / expired / vanished → 404 `session.not_found`；current → 409 `session.current` |
| Provider 撤销语义 | 本地撤销先行，provider 撤销 best-effort（失败只 Warn + 安全事件），不耦合本地撤销成败 |

## 3. HTTP 契约（ADR-0006 §2/§3）

| 端点 | 行为 |
| --- | --- |
| `GET /api/v1/me/sessions` | 200 JSON 数组（空为 `[]`）；GET 豁免 CSRF |
| `DELETE /api/v1/me/sessions/{sessionId}` | 204 / 404 `session.not_found` / 409 `session.current` |
| `DELETE /api/v1/me/sessions` | 200 `{"revoked":N}`（撤销除当前外全部） |

Wire shape：`sessionId / deviceName / clientName / approximateLocation(恒 null) / ipAddressMasked / lastActiveAt / createdAt / authenticationMethods / isCurrent`。

## 4. 门禁证据

| 检查 | 结果 |
| --- | --- |
| gofmt / go vet（含 `-tags integration`） | ✅ clean |
| go build（含 integration tag） | ✅ |
| go test ./...（含 -race） | ✅ 全部通过 |
| Redis 集成测试（SSH 隧道实连，-race，DB 1 + test prefix） | ✅ 全绿 |
| 实机冒烟（:8081，zitadel provider 装配） | ✅ 三端点未认证 401、`/readyz` 健康 |
| 已认证 happy path | 留用户浏览器实跑（凭据不在仓库） |

## 5. Known non-blocking debt

- P3 debt「remember flag is not preserved through MFA completion」已在本阶段修复并回归锁定；
- Frontend session list / revoke seam 按约定保留至 P4.7；
- reauth cleanup 集成测试时序按隧道延迟加固（`c1672da`），断言语义不变。

## 6. Reopen criteria

> 仅当后续出现证明冻结的 session inventory / lifecycle 不变量存在缺陷的证据时才可重开 P4.1。

## 7. 正式状态

| 项 | 状态 |
| --- | --- |
| P4.0 Architecture & Contract Freeze | PASSED / FROZEN（`f28e29e`） |
| P4.1 Session Inventory & Lifecycle | PASSED / FROZEN |
| Implementation head | `c9d2af2` |
| 下一阶段 | P4.2 Security Factors Backend（TOTP / Passkey lifecycle；Recovery Codes deferred） |

---

# 更正记录（append-only，2026-08-09）

> 本更正依据后续复审证据追加，原始记录正文保持不动；历史提交不改写。

## C1. 原 freeze 结论被复审证据否定

本记录第 1–7 节（`2ddaea8`，docs-only）将 P4.1 记为 PASSED / FROZEN、Blocking defects = 0，该结论**无效**：复审在 `8b13bd8899de3a0a437f7c37609bb3b5987883a6`（P4.2 lifecycle head）上确认 R1–R4 四个 blocking defect 仍然存在。`2ddaea8` 不是有效的 P4.1 frozen head。

## C2. 复审确认的 blocking defects（R1–R4 + Rotate）

| Finding | 缺陷 | 修复（`e73a60f` fix(session): close phase 4.1 review findings） |
| --- | --- | --- |
| R1 Redis revoke false-success | `resolve()` 把 record `Get()` 的基础设施错误压成 `ErrSessionNotFound`；bulk revoke 对 resolve 错误 continue → Redis 故障下漏撤销仍返回成功 | `resolve()` 仅对逻辑 miss（无 locator / 无 record / 损坏 / foreign owner）返回 `ErrSessionNotFound`，基础设施错误包装后传播；`RevokeAllOtherSessions` 遇非 NotFound 错误即 abort 并返回 err（fail closed）。回归：`TestRevokeSessionPropagatesInfrastructureFailure`、`TestRevokeAllOtherSessionsPropagatesInfrastructureFailure` |
| R2 bulk revoke 忽略 idle expiry | `DeleteBySessionID` / `RevokeAllOtherSessions` 用 `IsExpired(time.Now(), 0)` 重放，关闭了冻结的 idle-expiry 语义 | 两个方法签名显式携带 `now time.Time, idleTTL time.Duration`，与 `GetBySessionID` / `ListUserSessions` / `EffectiveExpiry` 同源重放；idle-expired 目标只清理不计入撤销。回归：`TestBulkRevokeHonoursIdleExpiry` + Redis 集成（DeleteBySessionID / RevokeAllOtherSessions idle 用例） |
| R3 持久化 untrusted XFF | session 创建用 `clientIP(r)`（优先信任 X-Forwarded-For）写入 `IPAddressMasked`，违反 P4.0「不新增 proxy-header trust」 | 新增 `peerIP(r)`（仅 RemoteAddr）用于持久化；`clientIP` 保留但限定 rate limiting only。回归：`TestLoginPersistsPeerIPNotForwardedHeader`、`TestPeerIPIgnoresProxyHeaders` |
| R4 durable audit 缺失 | targeted/bulk revoke 仅 `slog.Info/Warn`，无 durable audit recorder（ADR-0004 §8：log-based audit is not a substitute） | session 包新增 `SecurityAuditor` 接缝（`RecordSessionEvent`）与事件常量 `session.revoked` / `session.revoked_others`；bootstrap 以 `sessionSecurityAuditor` 适配到既有 `postgres.SecurityEventStore`（空 app/client 列）。audit best-effort：recorder 失败仅 Warn，不掩盖已成功的撤销。回归：`TestRevokeRecordsDurableSecurityAudit`、`TestRevokeSucceedsWhenAuditRecorderFails` |
| Rotate 复活缺陷（复审顺手项） | old record 不存在时 Rotate 仍会重写出新 record，被撤销的 session 可被在途 rotation 复活 | Rotate Lua 脚本先 `EXISTS KEYS[1]`，不存在即 return 0 → Go 侧 `session.ErrSessionNotFound`。回归：`TestIntegration_SessionStoreRotate`（vanished rotation 用例）+ `store_test.go` fake 同语义 |

## C3. 更正后的门禁证据（本机实跑）

| 检查 | 结果 |
| --- | --- |
| gofmt / go vet / go build | ✅ clean |
| go test ./... -race -count=1 | ✅ 全部通过 |
| Redis 集成测试（-tags integration，SSH 隧道实连，-race） | ✅ 全绿（65.8s，含 R2 / Rotate 新用例） |

## C4. 更正后的正式状态

| 项 | 状态 |
| --- | --- |
| `2ddaea8` freeze record | **INVALIDATED BY REVIEW EVIDENCE**（仅保留作历史记录） |
| P4.1 Session Inventory & Lifecycle | 修复 head = `e73a60f`（fix(session): close phase 4.1 review findings），待复审重新判 gate |
| R1–R4 / Rotate | 已在 `e73a60f` 关闭并回归锁定 |

