# Phase 4.2 冻结记录 — Security Factors Backend

- 日期：2026-08-09
- 范围：P4.2 —— Security Factors Backend（TOTP / Passkey lifecycle；Recovery Codes 按架构 DEFERRED，ADR-0006 §9）：reauth 接缝泛化（generic target binding）、ZITADEL factor provider 接缝（真实 gRPC 适配 + sentinel 错误族）、`/me/security` 七端点 HTTP 契约、enrollment token 的 claim/release/consume 生命周期与补偿。
- 状态：**PASSED / FROZEN**（本 docs-only freeze commit 生效）

## 1. 冻结谱系

| 项 | 值 |
| --- | --- |
| P4.0 frozen head | `f28e29edeccc396a14c60c8284b2f2495deb1bf5`（ADR-0006 架构与契约冻结） |
| P4.1 re-frozen implementation head | `e6c57eb02419e6a5274da94e398d2bcec5cd2fcb`（`fix(session): complete session revocation audit and partial cleanup`，PASSED / FROZEN，见 p41-freeze-record.md C1–C5） |
| P4.2 implementation commit 1 | `7da75d7`（`feat(auth): generalize reauth seam for account factor actions (P4.2)`，5 files，+256/-26） |
| P4.2 implementation commit 2 | `8358d1f`（`feat(auth): security factor provider seam for TOTP and passkeys (P4.2)`，9 files，+1234/-2） |
| P4.2 implementation commit 3 | `8b13bd8`（`feat(account): TOTP and passkey lifecycle endpoints with enrollment tokens (P4.2)`，6 files，+1563） |
| P4.2 review closure 1 | `504b301`（`fix(account): harden factor provider and enrollment invariants`，9 files，+624/-86：A1 sentinel/HTTP 映射、A2 claim/release/consume、A3 补偿） |
| P4.2 implementation acceptance head | `8261ee2037c81b50561b8a284b92f049ab25eea3`（`fix(account): preserve provider forbidden in factor summary`，2 files，+19/-1：真实 FactorSummary 路径 errProviderPermission → ErrProviderForbidden） |
| Official P4.2 frozen head | 本 freeze commit（docs-only，append-only 追加于 `8261ee2` 之后） |
| Blocking defects | 0 |
| P4.3+ scope leakage | 0 |

谱系为 append-only 直线：`f28e29e → … → e6c57eb → 8261ee2 → 本 commit`，无 rewrite、无分叉（复审人已独立核对 GitHub main）。

## 2. 复审通过的核心不变量

| 不变量 | 实现 |
| --- | --- |
| A1 sentinel 与 HTTP 映射 | factor 错误族五个 sentinel（`ErrFactorAlreadySet` / `ErrFactorNotSet` / `ErrInvalidFactorCode` / `ErrProviderUnavailable` / `ErrProviderForbidden`），全部不携带 secret 材料；provider 类失败 → 503 `provider.unavailable` / `provider.forbidden`，绝不伪装成用户输入错误。write 路径 InvalidArgument = 服务端故障（fail closed）；confirm 路径 InvalidArgument/FailedPrecondition = `factor.invalid_code` |
| A1 SA 授权失败类 | ZITADEL NotFound + `AUTHZ-*` → `errProviderPermission` → `ErrProviderForbidden`，**所有路径一致**（begin/remove 写路径与只读 `FactorSummary`），从不塌成 provider.unavailable（ADR-0006 §10） |
| A2 enrollment claim/release/consume | enrollment token 走 MFA/reauth 同款模式：SHA-256 hash 为 Redis key、user+session 绑定、claim lock `SET NX PX` 单赢家、Lua 原子 claim/consume；confirm 成功后 consume（single-use，消费后不可重放），瞬态失败 release 允许重试；challenge TTL 不因 claim 延长 |
| A3 provider 失败补偿 | provider confirm 失败（invalid code/attestation、binding mismatch）consume challenge（防重放刷 provider）；仅瞬态故障 release。provider 是 factor 唯一权威，本地无 factor 状态 |
| Reauth target binding | factor 写操作各自消费专属 reauth action（`account.totp.enroll` / `account.totp.remove` / `account.passkey.enroll` / `account.passkey.remove`）；passkey 删除要求 `grant.Target == route.passkeyId`，为 A 铸造的 grant 永远删不了 B（wrong target ⇒ fail closed，ADR-0006 §4/§12） |
| Secret 处理 | TOTP `secret` 与 `otpauthUri` 同为 secret-bearing：仅出现在 begin 响应（`Cache-Control: no-store`），绝不入日志/audit payload/PostgreSQL，响应后唯一权威副本是 provider 的 pending registration；attestation payload 只记 size/outcome |
| 非枚举契约 | unknown/consumed/expired enrollment → 稳定 404；passkey 删除沿用 session 的 stable-404 非枚举规则；double registration 由 provider `already set up` 映射稳定 409（幂等安全） |
| Factor summary | provider readback（`ListAuthenticationMethodTypes` + passkey 列表），REMOVED 状态过滤，绝不从本地内存推断；`recoveryCodes.available=false` + `deferredReason=provider_unsupported`（§9 Option B） |

## 3. HTTP 契约（ADR-0006 §7/§8，全部 RequireSession + RequireCSRF）

| 端点 | 行为 |
| --- | --- |
| `GET /api/v1/me/security` | 200 summary：password.set / totp.enabled / passkeys[]（每 passkey 一行）/ recoveryCodes 恒定 deferred |
| `POST /api/v1/me/security/totp/enrollment` | 消费 `account.totp.enroll` reauth → `{enrollmentToken, secret, otpauthUri}`（no-store） |
| `POST /api/v1/me/security/totp/enrollment/confirm` | enrollmentToken 单赢家 claim → VerifyTOTPRegistration → consume |
| `DELETE /api/v1/me/security/totp` | 消费 `account.totp.remove` → RemoveTOTP + provider readback |
| `POST /api/v1/me/security/passkeys/enrollment` | 消费 `account.passkey.enroll` → `{enrollmentToken, passkeyId, publicKeyCredentialCreationOptions}`（verbatim 透传） |
| `POST /api/v1/me/security/passkeys/enrollment/confirm` | enrollmentToken claim → VerifyPasskeyRegistration → consume |
| `DELETE /api/v1/me/security/passkeys/{passkeyId}` | 消费 target=passkeyId 的 `account.passkey.remove` → RemovePasskey + readback |

## 4. 门禁证据

| 检查 | 结果 | 说明 |
| --- | --- | --- |
| gofmt / go vet / go build | ✅ PASS | user-reported local execution evidence |
| go test ./... -race -count=1 | ✅ PASS | user-reported local execution evidence |
| Redis 集成测试（-tags integration，SSH 隧道实连，-race） | ✅ PASS（52.5s） | user-reported local execution evidence |
| Postgres 定向集成 `TestIntegration_SecurityEventStoreSessionRevocationPayload` | ✅ PASS（5.7s） | 属 P4.1 closure 证据，随谱系携带 |
| 真实 ZITADEL 验收 | provider 写路径全部 P4.0 live-probed（V-2 TOTP lifecycle / V-4 passkey register-list-remove-verify）；浏览器 attestation 仪式留 P4.5 handler 上线时实演（ADR-0006 §8） | |
| GitHub Actions | 未验证 | 组织额度耗尽，本地门禁先行（仓库根 AGENTS.md） |

复审人独立确认：测试存在且覆盖关键断言、production 实现与测试一致、append-only 谱系成立、GitHub main head = `8261ee2`。

## 5. Known non-blocking debt

- **provider-success 后 enrollment Redis Consume 失败**：当前 Warn + challenge TTL bounded（自然过期兜底）；不重开 P4.2；**deferred to P4.8 settlement hardening**（届时专门 pin settlement-failure regression / detached retry 语义）。
- Recovery Codes 按架构 DEFERRED（ADR-0006 §9，P4.6 不排期），仅当 pinned provider 提供可验证的发放生命周期才重议。
- 前端 factor 管理 UI seam 按既定排期保留至后续阶段。
- **明确不属于 P4.2 debt**：partial bulk revoke 的 durable failure audit（forensic coverage 扩张）——属 P4.1/P4.8 observability hardening 议题，当前不构成冻结不变量缺陷，不得借此改动 frozen audit result model。

## 6. Reopen criteria

> 仅当后续出现证明冻结的 factor lifecycle / enrollment settlement / provider 错误分类不变量存在缺陷的证据时才可重开 P4.2。Recovery Codes 的架构性 deferral 与 P4.5 attestation 实演不构成 reopen 触发。

> **P4.7 closure amendment（2026-08-09；`e0dcc47`）**：该 criterion 曾被
> provider-compatible fake 的 TOTP invalid-code pending-state 证据触发。原
> handler 消耗本地 token 后 provider pending 仍存活，导致 fresh begin 永久
> `already set`。`e0dcc47` 以 invalid-code provider cleanup + capability-bound
> cancel endpoint 关闭该 reachability blocker；action binding、provider authority
> 与 provider-derived readback 均未改变。详见 ADR-0009 / `p47-freeze-record.md`。

## 7. 正式状态

| 项 | 状态 |
| --- | --- |
| P4.0 Architecture & Contract Freeze | PASSED / APPROVED / FROZEN 🔒（`f28e29e`） |
| P4.1 Session Inventory & Lifecycle | PASSED / FROZEN 🔒（re-frozen head `e6c57eb`，blocking defects 0） |
| P4.2 Security Factors Backend | PASSED / FROZEN 🔒（本 commit 生效；implementation acceptance head `8261ee2`，blocking defects 0） |
| P4.3+ | NOT STARTED / NOT YET AUTHORIZED |
