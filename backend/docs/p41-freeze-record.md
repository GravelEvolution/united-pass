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
