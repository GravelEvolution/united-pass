# Phase 3 冻结记录 — OAuth Authorization / Consent / Grants

- 日期：2026-08-08
- 范围：Phase 3（P3.0 – P3.9）全量 —— OAuth Authorization Request 处理、登录/恢复、Consent 展示与决策、Grant 视图与撤销、OAuth Endpoint Topology、Final Live Acceptance。
- 状态：**PASSED / FROZEN**

## 1. 冻结谱系

| 项 | 值 |
| --- | --- |
| Implementation acceptance head | `bdde1abd6c15120909a3fbeda2a28b613334f3ac`（`fix(auth): gate MFA lock/expired mock copy and offer only TOTP in real mode`） |
| P3.9 prerequisite（真实 /login continuation） | `f6c0c2f`（PASSED） |
| P3.8 frozen head | `2b0bc95` |
| Official Phase 3 frozen head | 本 freeze commit（docs-only，append-only 追加于 `bdde1ab` 之后） |
| Blocking defects | 0 |
| Non-blocking debt | 已记录（§5） |

## 2. 验收环境（Final Live Acceptance）

| 项目 | 值 |
| --- | --- |
| 执行环境 | 宿主 macOS（darwin arm64）；colima VM + docker（ZITADEL v2.71.0 + PostgreSQL 16-alpine） |
| public origin | `http://localhost:8443`（本地验收 reverse proxy：`/oauth/*`、`/oidc/*`、`/.well-known/openid-configuration` → ZITADEL 127.0.0.1:18080；`/_interaction/*`、`/api/*` → Go 后端 127.0.0.1:8090；其余 → Next.js 生产构建 127.0.0.1:3000） |
| 后端 | 真实模式（ZITADEL provider + PostgreSQL + Redis，`/readyz` 200） |
| 前端 | 生产构建（`NEXT_PUBLIC_USE_MOCK=false`，服务端 `API_BASE_URL` 指向 8090） |
| RP | 经后端 admin API provision 的 confidential client（ZITADEL `client_id=385324853013577731`）+ 本地 RP stub（redirect 记录） |
| 测试用户 | human 用户，password + TOTP（MFA 全链真实执行） |

## 3. Live acceptance 矩阵（全部本机实跑）

| 验收项 | 判定 | 关键证据 |
| --- | --- | --- |
| ZITADEL / backend / frontend / RP topology | PASS | discovery issuer == public origin；`topology-probe.sh` 全绿；authorize 302 → `/_interaction/login?authRequest=V2_…`，prefix preserved |
| fresh logged-out → password → TOTP | PASS | logged-out 状态确认（/me 401）→ POST /auth/sessions 202 `mfa_required` → POST /auth/sessions/mfa 204 + Set-Cookie |
| real Session cookie 建立 | PASS | `up_session` / `up_csrf` 建立，/me 200 |
| /authorize real Resolution + /me | PASS | 真实 Resolution consent 页：真实应用名、真实身份、真实 scopes |
| interactive allow → RP callback | PASS | allow → RP callback 收到 `code` + `state`；token exchange 200（access_token + id_token，iss == public origin）；userinfo/introspect 通过；code 一次性（复用 400） |
| reusable grant → already_authorized 自动完成 | PASS | 第二次 authorize 无 consent UI 直达 callback |
| revoke → fresh consent required | PASS | DELETE grant 204 → 列表空 → re-authorize consent UI 重新出现 |
| revoke 后 allow → 同 grant row reactivation | PASS | 同一 `grant_id` 重新激活（status=active），未产生新行 |
| prompt=none + reusable grant | PASS | silent success：静默 302 callback 带 code，全程无 UI |
| prompt=none + no grant | PASS | error callback `error=consent_required` |
| prompt=none + no session | PASS | logout（DELETE /auth/session 204）后 error callback `error=login_required` |

五种状态（interactive、silent、revocation、reuse、无 session / 无 grant）共同闭环。

## 4. 一致性检查（全部本机实跑）

| 检查项 | 判定 | 证据 |
| --- | --- | --- |
| single-winner DB invariant | PASS | 只读 DB 快照：7 个 auth request 各恰 1 行 decision operation，全部终态 `succeeded`；`in_flight = 0`；无 session 的 login_required 行不绑定 user |
| current-run reconciliation backlog | PASS | P3.9 acceptance run 产生 0 条未解决 reconciliation job |
| LoginVersion backfill idempotency | PASS | `cmd/oauth-topology-backfill` 连跑两次，均 `verified=1 repaired=0 skipped=0 failed=0`，第二次零写入 |
| credential/callback log leakage sweep | PASS | RP callback 记录仅 code/state/error；backend / frontend / proxy / RP stub 运行日志对密码、TOTP、clientSecret、session cookie 全零命中；access log 仅 method/path/status/duration，无请求体；decision operation 表不持久化 provider callback URL / payload（schema 保证） |

## 5. Known non-blocking debt

> 3 unresolved pre-P3.9 reconciliation jobs exist for app_5a667d…, reason provider_unavailable, created 2026-08-06. No unresolved reconciliation jobs were created by the P3.9 acceptance run. Historical rows require separate operational cleanup/investigation.

其余：

- remember flag is not preserved through MFA completion（既有 P1 session semantics 缺口，单独追踪，不属于 Phase 3 授权正确性）；
- passkey login frontend seam not migrated；
- live concurrent same-request race not load-tested（唯一约束 + single-winner domain tests + 本次 DB 快照已支撑冻结；真实并发压测作为后续 resilience test）；
- provider-side token expiry/revocation not part of this acceptance。冻结的撤销契约为：United Pass revoke → revoke local consent → block future silent reuse ≠ immediately revoke provider-issued Access/Refresh Tokens。

## 6. Reopen criteria

> Only reopen Phase 3 if later evidence shows a defect in a frozen authorization/consent/grant invariant. Operational cleanup or unrelated P1 session behavior does not reopen Phase 3 automatically.

## 7. 正式状态

| 项 | 状态 |
| --- | --- |
| P3.0 – P3.8 | PASSED / FROZEN |
| P3.9 Final Live Acceptance | PASSED |
| Phase 3 | APPROVED FOR FINAL FREEZE |
| Implementation head | `bdde1abd6c15120909a3fbeda2a28b613334f3ac` |
