# Phase 4.3 冻结记录 — Password Credential Settlement（ADR-0007 rework）

- 日期：2026-08-09
- 范围：P4.3 rework —— Password Credential Settlement and Security-Generation Invalidation（ADR-0007，对 ADR-0006 §6 的 narrow reopen）：PostgreSQL 权威安全状态（`users.security_epoch` + durable `password_mutation_intents` ledger）、四态 settlement 生命周期（active → outcome_recorded → local_settlement → settled，全 CAS-fenced）、epoch stamping（SessionRecord / reauth challenge / grant / enrollment）、共享 promotion validator（RequireSession + OptionalSession）、generation-scoped cleanup（`RevokeSessionsBeforeEpoch`）、四态 crash/takeover recovery、providerOutcome + settlementOutcome durable audit。
- 状态：**PASSED / FROZEN**（本 docs-only freeze commit 生效）

## 1. 冻结谱系

| 项 | 值 |
| --- | --- |
| P4.2 frozen head | `8261ee2037c81b50561b8a284b92f049ab25eea3`（见 p42-freeze-record.md） |
| P4.3 首版实现（BLOCKED） | `acd35f2a9a2f765e6abb99fa7bcdb8f62e8b0c2f`（`feat(account): reauth-gated password change (P4.3)`，复审发现 B1–B5，被 ADR-0007 架构修正取代） |
| ADR-0007 docs-only 谱系 | `8801e66`（初版）→ `1b265e4`（F1–F5 closure）→ `ab9817c`（F6 closure） |
| Official architecture head | `ab9817c9e64cdb15ea4775a010a74987cd42280a`（`docs(adr): define post-provider intent recovery`，PASSED / APPROVED / FROZEN，B1–B5 + F1–F6 全 ✅，architecture blockers 0） |
| P4.3 rework implementation commit | `75f74925da8c45e9dbabef4317e477275bf04f19`（`feat(account): settle password mutations via durable intent ledger (P4.3 rework)`，单笔 review-gated，38 files，+4453/−294，无 ADR/docs 夹带，未扩大 narrow reopen 边界） |
| P4.3 implementation acceptance head | `75f7492`（复审 PASSED，BLOCKERS 0） |
| Official P4.3 frozen head | 本 freeze commit（docs-only，append-only 追加于 `75f7492` 之后） |
| Blocking defects | 0 |
| P4.4+ scope leakage | 0 |

谱系为 append-only 直线：`8261ee2 → acd35f2 → 8801e66 → 1b265e4 → ab9817c → 75f7492 → 本 commit`，无 rewrite、无分叉（复审人已独立核对 GitHub main）。

## 2. 复审通过的核心不变量（B1–B5 + F1–F6）

| 发现 | 不变量 | 实现锚点 |
| --- | --- | --- |
| B1 | rotate failure 不再决定账户 invalidation：epoch advancement 是 provider outcome 已知后的**第一个**本地效应，与 outcome record 同一 PG 事务 | `SecurityStateStore.RecordOutcomeAdvanceEpoch` / `advanceEpoch`（intent UPDATE 与 `users.security_epoch + 1` 同事务提交） |
| B2 | Redis ambiguity 无法复活旧 generation：epoch 从不依赖 Redis，Redis 只做热路径 mirror，任何分歧以 PG ledger 为准 | `security_state_store.go` 头部契约（"Redis never decides here"）；session/grant/enrollment 全部凭 stamped epoch 对照 PG 权威 epoch 校验 |
| B3 | 旧 generation 的 grant/enrollment 随 generation 死亡：消费/确认前校验 stamped epoch == 权威当前 epoch + intent barrier | `ReauthGrants.VerifyAndConsume` 与 `claimEnrollmentData` 的 `AllowSensitiveConsumption` gate（stale → 烧毁 artifact；barrier → 按 frozen lifecycle 拒绝） |
| B4 | user-scoped 单赢家 mutation fencing：非 terminal intent 阻止第二次 mutation，provider 调用前 fail closed（`password.change_in_progress`），settled 后允许重新 acquire | `AcquireIntent`：`ON CONFLICT (user_id) DO UPDATE ... WHERE status = 'settled'`，user_id PK 单行约束；8-goroutine SQL 集成验证恰一赢家 |
| B5 | provider-committed 终态必留 durable audit：`providerOutcome`（success/unknown）与 `settlementOutcome`（settled/settled_relogin/degraded）双正交字段 | settlement lifecycle 在每条 provider-committed 终态路径（含 vanished-session / infra-failure / outcome-unknown）attempt audit；confirmed_failure 无 durable event（frozen 行为保留） |
| F1 | 共享 promotion validator：RequireSession 与 OptionalSession 走同一 `validateAndPromote`；epoch stale 清双 cookies（frozen no-clearing 规则唯一 pinned exception），transient barrier 拒绝不清 cookies，observed 非终态 intent 触发 detached recovery | `session_middleware.go`；`session_middleware_test.go` 双路径矩阵 |
| F2 | legacy decode 可执行：missing/zero securityEpoch 在 persistence-adapter decode 边界归一为 1，业务层从不 special-case；写侧 fail closed | Redis 适配器 `normalizeStamp` / `normalizeReauthChallengeEpoch` / `normalizeReauthGrantEpoch` + `requireStamped`；`redis/epoch_stamp_test.go` |
| F3 | crash fencing：provider 调用在硬 deadline D（严格位于 lease L 内）；每次状态转换 CAS-fenced `(user_id, intent_id, expected status)`；epoch advancement 每 intent 恰一次；takeover 修复了 `$4` 参数缺失的真实 bug | `security_state_store.go` 全 CAS 语句；`TakeoverExpiredAdvanceEpoch` |
| F4 | generation-scoped cleanup：只杀 stamp 早于新 epoch 的 session，新 generation 与 foreign user session 绝不被 settlement cleanup 误杀；绝不复用 `RevokeAllOtherSessions` | `session.Service.RevokeSessionsBeforeEpoch`；`session/epoch_test.go` |
| F5 | audit payload 保留 providerOutcome + settlementOutcome | audit 双字段 additive（不改 frozen result model） |
| F6 | 四态 crash/takeover recovery：active 过期 → CAS takeover（outcome unknown + epoch 恰一次）→ continue settlement；outcome_recorded → providerOutcome 不可变、epoch 不再推进、幂等 resume；local_settlement → 幂等重试 cleanup、bounded 失败后 degraded settle；settled 不可变。recovery 绝不重调 provider，detached bounded context，bounded attempts 保证 terminalization 不停滞 | `securitystate.Service.Recover` + `TriggerRecovery`；`service_test.go` 八情形矩阵 |

两阶段 barrier 闭环：pre-outcome `active` 全拒（promotion / sensitive consumption / 新 mutation）；post-epoch `outcome_recorded`/`local_settlement` 拒旧 epoch session、sensitive consumption 与新 mutation，允许 current-epoch 普通 promotion；`settled` 无 barrier。

## 3. 回归证据（ADR-0007 Consequences 预钉清单全部在位）

| 证据 | 测试 |
| --- | --- |
| B1 vanished-session race：rotation 失败不阻止账户级 invalidation | `securitystate/service_test.go` settlement 矩阵 + `httpapi/password_handlers_test.go` |
| B2 Redis ambiguity 模拟 / 权威 epoch | `session/epoch_test.go`（权威 stamping）、`postgres/security_state_store_integration_test.go` |
| B3 grant/enrollment generation invalidation | `httpapi/security_gate_test.go`（stale 烧毁 / barrier 可重试 / lookup fail closed，provider 0 调用） |
| B4 并发 mutation fencing 确定性单赢家 | `securitystate/service_test.go` Acquire + `TestIntegration_AcquireIntentConcurrentSingleWinner`（8 goroutine） |
| B5 provider-committed 终态 audit attempt | `httpapi/password_handlers_test.go` audit 断言（含 degraded / relogin / unknown 路径） |
| F1 双 promotion 路径 stale/transient cookie 策略 | `httpapi/session_middleware_test.go`（RequireSession 6 情形 + OptionalSession 4 情形） |
| F2 zero-epoch legacy decode 归一 | `redis/epoch_stamp_test.go`（legacy JSON / corrupt / 显式 zero 写侧 fail closed） |
| F3 barrier fail closed + confirmed_failure 恢复旧 generation + stale-worker CAS fence | `service_test.go` BarrierPhases / SettleConfirmedFailureZeroSideEffects / fence-loser 不 bump epoch |
| F4 新 generation session 存活于 cleanup | `session/epoch_test.go` RevokeSessionsBeforeEpoch 矩阵 |
| F5 audit payload 双字段 | `httpapi/password_handlers_test.go` audit payload 断言 |
| F6 crash-after-outcome_recorded（epoch 恰一次、绝不重调 provider）、crash-during-local_settlement（幂等 resume、新 generation 存活）、stale takeover（CAS loser 不能 bump/rewrite/settle）、post-epoch barrier phase | `service_test.go` Recover 八情形 + `TestIntegration_TakeoverExpiredAdvanceEpoch`（live lease 拒 / backdate 后恰一次 + exactly-once） |

## 4. 门禁证据

| 检查 | 结果 | 说明 |
| --- | --- | --- |
| gofmt -l internal/ cmd/ / go vet ./... / go build ./... | ✅ PASS | 本地执行（含 integration tags 编译） |
| go test ./... -race -count=1 | ✅ PASS（12 包） | 本地执行 |
| Postgres 集成（-tags integration，SSH 隧道实连 15432，-race） | ✅ PASS（324.9s） | 含 00007 migration fresh-install 与 00005→head 升级路径、intent ledger 全 CAS fence、并发单赢家、takeover exactly-once |
| Redis 集成（-tags integration，SSH 隧道实连 16379，-race） | ✅ PASS（34.2s） | 含 epoch stamping / legacy decode 归一 / 既有 session·grant·enrollment 生命周期 |
| 真实 ZITADEL 验收 | Pending | provider seam（SA-privileged newPassword-only SetPassword）与 frozen §6 一致、未改动；P4.0 已 live-probe 该路径。settlement 侧以确定性回归覆盖；live rework 验收留待运行环境复通时补演，不构成本冻结的 blocking 证据（复审人已判 PASS） |
| GitHub Actions | 未验证 | 组织额度耗尽，本地门禁先行（仓库根 AGENTS.md） |

复审人独立确认：单笔 implementation commit、无 docs 夹带、PG 唯一权威（Redis 无决策权）、B1–B5 + F1–F6 逐项 PASS、`$4` 参数修复后的 takeover fence path 正确、GitHub main head = `75f7492`。

## 5. Known non-blocking debt

- **intent sequence 消耗间隙**（复审 minor observation，明确不要求修改）：`AcquireIntent` 的 `nextval('password_mutation_intent_seq')` 在 acquire 失败时也消耗 sequence，intent_id 可能不连续——不影响 monotonic、fencing 与安全模型，属正常 PostgreSQL sequence 行为。
- P4.2 记录的 enrollment Redis Consume 失败兜底（Warn + challenge TTL bounded）维持 deferred to P4.8 settlement hardening，不变。
- Recovery Codes 按架构 DEFERRED（ADR-0006 §9），不变。
- live ZITADEL settlement 补演（见 §4）：环境复通后执行，仅补充运行证据，不改任何冻结不变量。

## 6. Reopen criteria

> 仅当后续出现证明冻结的 password credential settlement 不变量（epoch 权威性、intent CAS fencing、exactly-once advancement、generation-scoped cleanup、两阶段 barrier、四态 recovery、durable audit 双字段）存在缺陷的证据时才可重开 P4.3。live 补演结果与 sequence 间隙观察不构成 reopen 触发。

## 7. 正式状态

| 项 | 状态 |
| --- | --- |
| P4.0 Architecture & Contract Freeze | PASSED / APPROVED / FROZEN 🔒（`f28e29e`；§6 由 ADR-0007 narrow amendment 治理） |
| P4.1 Session Inventory & Lifecycle | PASSED / FROZEN 🔒（re-frozen head `e6c57eb`；narrow reopen 接缝已按 ADR-0007 实现并随 P4.3 冻结） |
| P4.2 Security Factors Backend | PASSED / FROZEN 🔒（acceptance head `8261ee2`；narrow reopen 接缝已按 ADR-0007 实现并随 P4.3 冻结） |
| P4.3 Password Credential Settlement | PASSED / FROZEN 🔒（本 commit 生效；architecture head `ab9817c`，implementation acceptance head `75f7492`，blocking defects 0） |
| P4.4+ | NOT AUTHORIZED |
