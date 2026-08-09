# Phase 4.9 真实实例验收与最终冻结记录

- 日期：2026-08-09
- 状态：**PASSED / FROZEN**（本 final freeze commit 生效）
- 验收对象：pinned ZITADEL `v2.71.18`、United Pass schema migration `v7`
- 验收基线 head：`f8281d2`；本轮补齐 ZITADEL WebAuthn envelope/name 合同后冻结

> password/TOTP/session 子矩阵与真实 browser WebAuthn registration → provider
> active readback → target-bound removal 已全部实演。P4.6 Recovery Codes 仍按
> ADR-0006 §9 架构性 Deferred，不阻塞 Phase 4 完成。

## 1. 冻结谱系

| 阶段 | 权威 head | 状态 |
| --- | --- | --- |
| P4.5 browser ceremony | `60dc6a7`（acceptance `194b6d2`） | FROZEN；A14 carried to P4.9 |
| P4.7 remaining real seams | `0b6aa6e`（implementation `e0dcc47`） | FROZEN；A15 carried to P4.9 |
| P4.8 settlement hardening | `0adee99`（implementation `b0ef98b`） | FROZEN；cross-invariant live matrix carried to P4.9 |
| Initializer secret closure | `4e73c94` | PUSHED |
| Browser fallback closure | `f8281d2` | PUSHED |
| P4.9 final frozen head | 本提交 | 全量门禁与敏感扫描通过后生效 |

## 2. 真实环境与前置校准

- ZITADEL 使用 `ghcr.io/zitadel/zitadel:v2.71.18`，不是浮动 tag。
- backend、frontend 和同源 acceptance proxy 均使用本轮代码；frontend 的最终
  browser matrix 使用 `next build` + `next start`，而不是 Mock data source。
- 初始数据库停留在 migration `v6`，导致 session 创建缺少
  `security_epoch`；执行正式 migration command 升至 `v7` 后恢复。该项记录为
  environment drift，不伪装成业务代码缺陷。
- SSH tunnel 曾留下失效 PID 记录；清理后 PostgreSQL `15432` 与 Redis `16379`
  均重新连通。provider/tunnel 抖动期间的失败不计为通过证据。
- ZITADEL initializer 的请求创建名不是 provider-authoritative preferred login。
  `4e73c94` 改为回读 `preferredLoginName`、状态文件 `0600`、终端不输出密码或
  TOTP secret，并以静态回归测试钉住。

## 3. P4.9 live matrix

| Gate | 结果 | 真实证据 |
| --- | --- | --- |
| Provider adapter E2E | ✅ PASS | `TestIntegration_ZitadelAuthenticatorE2E` 18.56s；wrong-password 3.14s；package integration race 22.769s |
| Targeted own-session revoke | ✅ PASS | 两个独立真实 session；victim revoke 返回 204，victim 后续 401，current session 保持有效；重复 revoke 稳定 404 |
| Bulk revoke others | ✅ PASS | 新建 victim 后返回 `{revoked:1}`；victim 后续 401；current session inventory 保留且 `currentCount=1` |
| Password settlement | ✅ PASS | 当前 session 完成 password + TOTP reauth；change 返回 204；当前 generation 保留、旧 generation victim 401；旧密码登录 401、新密码进入 202 MFA；随后恢复验收基线密码并反向验证 |
| TOTP lifecycle | ✅ PASS | remove reauth 202→TOTP grant→DELETE 200/readback disabled；enroll begin 返回 secret/URI/token（仅检查存在性）、confirm 200/readback enabled；再 remove 清理并由 initializer 恢复基线 TOTP |
| P4.8 enrollment settlement | ✅ PASS（跨路径） | TOTP live confirm/remove 与 failed passkey ceremony 的 cancel settlement 后 provider summary 均保持可达；未发现 pending factor 阻塞后续 begin |
| Browser credential query fallback | ✅ PASS（修复） | 真实 Chrome 首轮发现无水合 form 默认 GET 会把 identifier/password 放入 URL；`f8281d2` 将 auth/account 敏感 form 回退显式改为 POST，并新增 native-submit E2E：URL 零凭据 |
| P4.5 A14 browser passkey | ✅ PASS | Chrome 真实 WebAuthn credential 创建成功；begin 200、confirm 200；provider summary 回读 active `passkeyId`；以该 passkey 完成 step-up 后，target-bound DELETE 200；再次回读归零 |
| Current-session logout | ✅ PASS | 真实 UI `/logout` 调用 `DELETE /api/v1/auth/session` 返回 204 并回到 `/login`；随后保护资源 `GET /api/v1/me` 返回 401 |
| `prompt=none` after revoke/logout | ✅ PASS | logout 后创建一次临时 LoginV2 OIDC probe app；authorize 302 进入 `/_interaction/login`，无 cookie gateway 302 回调精确携带 `error=login_required` 与原 state、无 code；probe app 随后删除 |
| Sensitive-material sweep | ✅ PASS | initializer stdout/state 权限、tracked diff 对 `.env`/init-state 值、credential URL fallback 与最终 browser ceremony 后 terminal sweep 均通过 |

## 4. 真实浏览器发现的安全缺陷

### 4.1 无水合时敏感 form 默认 GET

首轮真实 browser run 暴露：React 未水合或 client script 失败时，原生 `<form>`
没有显式 `method`，浏览器按 GET 回退，identifier/password 进入 query string，继而
进入地址栏、history 和 dev server request log。

修复 `f8281d2`：

- login/register/reset/MFA 与 account security/profile/contact 等敏感 form
  显式 `method="post"`；
- React 正常水合时仍由现有 `preventDefault` + frozen JSON HTTP seam 处理，不改变
  API contract；
- 新增 E2E 直接调用 native form submit，断言 fallback request 为 POST，且 URL
  不含 identifier/password；
- 删除本轮包含本地测试凭据的生成型 Next dev log。该 log 不受 Git 管理，可由
  后续 dev run 重新生成。

该 finding 属真实验收 blocker，已修复、全前端门禁通过并独立提交；不是文档性
观察项。

### 4.2 ZITADEL WebAuthn wire contract

最终 A14 实演又发现两个仅真实 provider 可见的合同差异：

- ZITADEL v2.71.18 返回的 creation/request options 是标准
  `{ "publicKey": { ... } }` envelope；严格转换器现同时接受该单层 envelope
  与冻结的内部对象，并拒绝 envelope 与顶层字段混用；
- `VerifyPasskeyRegistrationRequest.passkeyName` 要求 1–200 Unicode 字符。
  前端提交稳定名称“当前设备”，后端在 claim enrollment capability 前完成
  trim/rune-count 校验，非法名称不会触达 provider 或消耗 enrollment。

两项均有单元测试。真实浏览器随后完成 credential creation，ZITADEL confirm
返回 200，provider-authoritative summary 显示 active credential；该 credential
又用于删除 step-up，证明 registration 与 assertion wire conversion 均有效。

## 5. 当前门禁证据

| 类别 | 结果 | 记录 |
| --- | --- | --- |
| 本地静态检查 | Passed | backend P4.8/P4.9 code heads：gofmt/diff/tidy/vet/build（含 integration tags）；frontend `f8281d2`：lint/typecheck/build |
| 本地单元测试 | Passed | backend `go test ./...`；frontend 14 files / 197 tests |
| 本地 Race | Passed | backend `go test -race ./...` |
| 本地集成测试 | Passed | PostgreSQL/Redis `-tags integration -race`；P4.8 PG 379.765s，Redis passed；P4.9 ZITADEL package race 22.769s |
| Targeted browser fallback E2E | Passed | 1/1，4.7s；native POST fallback、URL 无 credential |
| 真实 ZITADEL 验收 | Passed | password/TOTP/session/logout/`prompt=none` 与 A14 browser registration/readback/removal 全部通过 |
| GitHub Actions | 因额度耗尽暂未验证 | 根 `AGENTS.md`：远程 CI 当前不作为门禁 |

最终 freeze commit 已在最终 docs/code head 重新执行根 `AGENTS.md` 全量 backend
与 frontend 门禁；结果见提交报告。

## 6. 最终关闭条件

P4.9 以下关闭条件均已满足：

1. DevTools CTAP2 virtual authenticator 下，真实 UI 完成 passkey registration；
2. provider-authoritative security summary 出现同一 active `passkeyId`；
3. target-bound reauth 删除该 credential，provider readback 回到零；
4. 真实 UI logout 完成，旧 session 后续 401；
5. revoked/logged-out session 的 `prompt=none` 返回 `login_required`；
6. final sensitive sweep、backend 全门禁、必要的 frontend 全门禁通过；
7. ADR-0008 A14、ADR-0009 A15、ADR-0010 live status 与 P4.5/P4.7/P4.8
   amendments 统一从 Pending 更新为 P4.9 live passed；
8. 创建 final freeze commit 并按根规则推送 `main`。

## 7. Phase 4 最终状态

| 项 | 状态 |
| --- | --- |
| P4.0–P4.5 | PASSED / FROZEN |
| P4.6 Recovery Codes | DEFERRED BY ARCHITECTURE（不阻塞） |
| P4.7–P4.9 | PASSED / FROZEN |
| Blocking defects | 0 |
| Scope leakage | 0 |
| Phase 4 | **COMPLETE / FROZEN** |
