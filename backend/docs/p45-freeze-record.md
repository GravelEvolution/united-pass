# Phase 4.5 冻结记录 — Passkey Browser Ceremony and Abandonment Settlement

- 日期：2026-08-09
- 范围：P4.5 —— 真实 WebAuthn browser ceremony、多 Passkey 的 provider-authoritative Security Summary、action/target-bound reauthentication、enrollment capability cancellation、Redis cleanup record/index、claim-aware expiry worker 与 active-credential preservation（ADR-0008）。
- 状态：**PASSED / FROZEN**（本 docs-only freeze commit 生效；A14 真实 ZITADEL 浏览器仪式仍按事实标记 Pending，纳入 Phase 4 final live acceptance）

## 1. 冻结谱系

| 项 | 值 |
| --- | --- |
| P4.3 official frozen head | `1e4a7423dd4ae9700296ba7960d460ecff2347e6`（见 `p43-freeze-record.md`） |
| P4.5 architecture head | `d868ce8d06a63d65ccad196ec3ec99694880dfbd`（`docs(adr): define passkey browser ceremony settlement`，ADR-0008） |
| P4.5 implementation commit | `124cce4c04e27d19313c0604efa22ecf84afa16c`（`feat(account): implement passkey browser ceremonies`，27 files，+2611/−269） |
| P4.5 review closure | `194b6d2791f5c8eeaa1344a0fda262270039b047`（`fix(account): abort closed passkey enrollment ceremonies`，9 files，+313/−49；关闭 A7 begin-in-flight modal-close race，补 A7/A12/confirmed-disposition executable evidence） |
| P4.5 implementation acceptance head | `194b6d2`（completion audit：A1–A13 PASS，blocking defects 0；A14 Pending） |
| Official P4.5 frozen head | 本 freeze commit（docs-only，append-only 追加于 `194b6d2` 之后） |
| Blocking defects | 0 |
| P4.7 scope leakage | 0（password/TOTP/Session mutation 在 real mode 仍未迁移） |

谱系为 append-only 直线：`1e4a742 → d868ce8 → 124cce4 → 194b6d2 → 本 commit`，无 rewrite、无分叉。

## 2. A1–A14 验收矩阵

| Gate | 结论 | 权威证据 |
| --- | --- | --- |
| A1 summary model | ✅ PASS | `SecuritySummary` 取代 flat factor；`parseSecuritySummary` 覆盖 multiple、active/pending、`createdAt:null`；`SecurityOverview` 每 passkey 独立 row；real recovery panel 不渲染 |
| A2 runtime narrowing | ✅ PASS | `response-validators.test.ts`：malformed summary、reauth union、unknown MFA、missing options、confirmation ID mismatch 全部 fail closed；`webauthn.test.ts`：required option 与 extension 白名单 |
| A3 WebAuthn conversion | ✅ PASS | `webauthn.test.ts`：无 padding base64url round-trip；creation 的 challenge/user.id/exclude ID 与 assertion allow ID 转 ArrayBuffer |
| A4 credential serialization | ✅ PASS | attestation/assertion exact JSON；rawId、clientDataJSON、attestationObject、authenticatorData、signature、userHandle 与 extension buffers 全部 base64url，不会退化成 `{}` |
| A5 reauth binding | ✅ PASS | enroll `target=""`；remove `target=passkeyId`；account action app/client binding 为空；backend `TestRemovePasskey_GrantTargetMismatch` 证明 A grant 不能删 B |
| A6 token handling | ✅ PASS | `browser-http-client.test.ts` / `security-commands.test.ts` 钉住 CSRF 与 constrained reauth header；enrollment token 只在 JSON body；Redis 只存 SHA-256 token hash；无 generic header escape hatch |
| A7 browser cancellation | ✅ PASS（closure） | `passkey-enrollment.test.ts`：post-begin `NotAllowedError` 调 cancel 且 confirm=0；begin 返回同时 modal abort 时 WebAuthn=0、cancel=1；同一 AbortSignal 贯穿 begin/create/confirm。`194b6d2` 修复 begin-in-flight 关闭后仍启动 WebAuthn 的 blocker |
| A8 invalid attestation | ✅ PASS | `TestConfirmPasskeyEnrollment_BadAttestation` 终态 abandon；cleanup worker 对 pending/unlisted target 调 provider remove |
| A9 expiry cleanup | ✅ PASS | Redis 集成覆盖 abandon→lease→requeue→complete、challenge expiry + live claim skip；worker provider failure capped-backoff requeue |
| A10 active preservation | ✅ PASS | `TestPasskeyCleanupWorker_PreservesActiveCredential`：provider readback active 时 remove=0，只清 marker；保护 provider-success / Redis-finalization ambiguity |
| A11 provider readback | ✅ PASS | confirm/remove 成功后仅触发 `router.refresh()`，无 real optimistic row；backend remove 返回 fresh provider summary，readback failure 不伪造状态 |
| A12 Mock regression | ✅ PASS | `passkeyCredentialCreator(true)` 在无 WebAuthn 环境仍返回 mock credential；targeted Playwright 添加→删除全流程 PASS，navigator create/get 探针调用数=0 |
| A13 sensitive sweep | ✅ PASS | password/grant/enrollment/credential 只在函数或组件内存；无 storage、URL、console/slog；cleanup record 仅 user/target/hash/attempt 元数据；provider detail 不进 HTTP/log |
| A14 live ceremony | ⏳ Pending | 必须在 pinned ZITADEL v2.71.18 做真实 browser registration → active readback → removal。当前不冒充通过，随 Phase 4 final live acceptance 补证 |

## 3. 冻结的不变量与实现锚点

| 不变量 | 实现锚点 |
| --- | --- |
| Browser ceremony 的二进制转换与 provider wire contract 分离 | `frontend/src/features/account/utils/webauthn.ts` |
| enrollment envelope 先收窄，credential 立即序列化且只存在函数栈 | `response-validators.ts`、`webauthn.ts`、`passkey-enrollment.ts` |
| modal close 中止 begin/create/confirm；已取得 enrollmentToken 的失败用独立 cancel 请求结算 | `passkey-enrollment.ts`；AbortSignal 由 `browser-http-client.ts` 传入 fetch |
| confirmed 原子删除 challenge + claim + cleanup record + index member | `redis/enrollment_store.go` `ConsumeEnrollment`；真实 Redis confirmed-disposition 集成断言 |
| abandoned/terminal invalid 立即烧毁浏览器 capability，但保留 cleanup work | `AbandonEnrollment` + `SecurityHandlers.settleEnrollment` |
| transient provider failure release claim，不烧 enrollment | `settleEnrollment` / cancel handler provider failure 分支 |
| cleanup 只处理无 live challenge/claim 的到期 work，lease + capped backoff | `ClaimExpiredPasskeyEnrollments`、`PasskeyEnrollmentCleanupWorker` |
| provider readback active 永不删除 | `PasskeyEnrollmentCleanupWorker.settle` active-preservation guard |
| provider confirm/cancel deadline 严格短于 claim TTL | 10s provider timeout < 60s enrollment claim TTL；cleanup lease 45s |
| real UI 只认 provider summary，Mock/real seam 不交叉 | `SecurityOverview` + `serverQueries.getSecuritySummary` + `USE_MOCK_DATA_SOURCE` |

## 4. 门禁证据

| 检查 | 结果 | 说明 |
| --- | --- | --- |
| 后端 gofmt / diff-check / tidy / vet / build（含 integration tags） | ✅ PASS | `194b6d2` closure 最终状态本地执行 |
| 后端 unit | ✅ PASS | `go test ./...` |
| 后端 Race | ✅ PASS | `go test -race ./...` |
| PostgreSQL 集成 Race | ✅ PASS | SSH 隧道 + `.env`，`./internal/adapters/postgres/...` |
| Redis 集成 Race | ✅ PASS（35.560s） | SSH 隧道 + `.env`；含 cleanup index/lease/requeue/live-claim skip/confirmed disposition |
| 前端 install / lint / typecheck / unit / build | ✅ PASS | Node 24 + pnpm 10；14 files / 188 tests；Next.js production build PASS |
| Targeted Mock E2E | ✅ PASS（1/1，16.0s） | 独立端口、单 worker；add/remove + WebAuthn probe=0。一次全量 dev-cold 并发运行发生既有页面超时，不作为通过证据 |
| OpenAPI YAML / local `$ref` | ✅ PASS | YAML 可解析，57 个 local refs 全解析 |
| 真实 ZITADEL 验收 | Pending | A14，留 Phase 4 final live acceptance |
| GitHub Actions | 未验证 | 组织额度耗尽，本地门禁先行（根 `AGENTS.md`） |

## 5. Known non-blocking debt / deferred scope

- P4.6 Recovery Codes 按 ADR-0006 §9 **DEFERRED BY ARCHITECTURE**；real mode 已隐藏，provider 提供可验证发放生命周期前不重开。
- P4.8 继续承接跨冻结阶段的 settlement/observability hardening；不得借 hardening 改写 P4.1/P4.2/P4.3/P4.5 冻结业务语义。
- P4.9 / Phase 4 final live acceptance 必须完成 A14，并补演 password settlement、TOTP、Session 与 sensitive leakage matrix。
- GitHub Actions 配额恢复后补跑，只追加证据，不改变冻结不变量。

## 6. Reopen criteria

> 仅当后续证据证明 WebAuthn wire conversion、action/target reauth binding、enrollment capability disposition、claim-aware expiry、active-preservation guard、provider-authoritative UI 或敏感材料零持久化中的冻结不变量存在缺陷时，才可重开 P4.5。A14 live 补演和 CI 恢复本身不构成 reopen；若 live 结果暴露不变量缺陷，则按证据重开。

## 7. 正式状态

| 项 | 状态 |
| --- | --- |
| P4.0 Architecture & Contract Freeze | PASSED / FROZEN 🔒（`f28e29e`） |
| P4.1 Session Inventory & Lifecycle | PASSED / FROZEN 🔒（`e6c57eb`） |
| P4.2 Security Factors Backend | PASSED / FROZEN 🔒（`562950e`；acceptance `8261ee2`） |
| P4.3 Password Credential Settlement | PASSED / FROZEN 🔒（`1e4a742`；acceptance `75f7492`） |
| P4.5 Passkey Browser Ceremony & Settlement | PASSED / FROZEN 🔒（本 commit 生效；architecture `d868ce8`，acceptance `194b6d2`，A14 Pending） |
| P4.6 Recovery Codes | DEFERRED BY ARCHITECTURE（不阻塞 Phase 4） |
| 下一实施阶段 | P4.7 remaining Account Security frontend real-seam migration |

## P4.9 closure amendment — 2026-08-09

A14 is Passed: production Chrome registration → ZITADEL confirm 200 → provider
active readback → passkey step-up → target-bound DELETE 200 → provider readback
zero. Historical Pending rows above describe the P4.5 freeze-time state; this
amendment is the final authority for live status.
