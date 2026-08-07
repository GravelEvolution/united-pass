# P3.6 OAuth Endpoint Topology 验收记录

- 日期：2026-08-07
- 范围：Phase 3.6 任务书 —— OAuth Endpoint Topology 与 LoginVersion 强制配置的实机验收（ADR-0005 §1）。对应 commit：`feat(oauth): expose provider endpoint topology`、`feat(zitadel): enforce login v2 interaction configuration`。
- 结论：
  - **live read-back verification: passed**（创建原子提交 LoginVersion + UpdateClient RMW 后双重读回）；
  - **live path-prefix probe: passed**（集成测试与 `scripts/topology-probe.sh` 两条独立通道均判定 `prefix preserved: YES`）；
  - **discovery / issuer 一致性: passed**（issuer == public origin，全部协议端点齐备）。

## 1. 验收环境

| 项目 | 值 |
| --- | --- |
| 执行环境 | 宿主 macOS（darwin arm64）；colima 0.10.3 VM（2 CPU / 4 GiB）+ docker 29.5.2（server）/ docker-compose 5.4.0 |
| ZITADEL | **v2.71.0**（镜像 `ghcr.io/zitadel/zitadel:v2.71.0`，linux/arm64），PostgreSQL 16-alpine，`start-from-init --masterkeyFromEnv` |
| 宿主端口 | **18080**（宿主 8080 被一个无关的既有开发服务占用，未触碰该进程；临时 compose 副本将发布端口与 `ZITADEL_EXTERNALPORT` 同时改为 18080，仅本次验收使用，不入库） |
| public origin | `http://localhost:18080`（开发允许 http；生产强制 HTTPS 由 `validateOAuthPublicOrigin` 单测覆盖） |
| interaction base URI（唯一派生，非独立配置） | `http://localhost:18080/_interaction` = `config.OAuthConfig{PublicOrigin}.InteractionBaseURI()` |
| 初始化 | `scripts/zitadel-init.sh`（`ZITADEL_BASE_URL=http://localhost:18080`）：测试 human 用户（密码 + TOTP）、后端 Service Account + JSON key、ORG_OWNER 授权；项目 "United Pass" 由 init SA 创建并授予 SA `PROJECT_OWNER` |

## 2. Live read-back（LoginVersion 强制配置）

执行：`TestIntegration_ProvisionerLoginVersionTopology`（`go test -tags integration -race -count=1`），**PASS**。

| 步骤 | 观察值 | 结果 |
| --- | --- | --- |
| ProvisionClient（AddOIDCApp 原子携带 LoginVersion） | probe app `applicationId=385236664332582915` | ✅ |
| 读回 1（创建后） | `GetAppByID` → `LoginVersion = LoginV2{BaseUri = http://localhost:18080/_interaction}` | ✅ |
| UpdateClient（RMW 全字段保留 + 强制 LoginVersion） | 改 redirect 后再次 `GetAppByID` 读回，LoginV2 BaseUri 不变 | ✅ |
| 清理 | probe app 已删除（defer DeleteClient） | ✅ |

## 3. Discovery（`/.well-known/openid-configuration`）

| 字段 | 观察值 |
| --- | --- |
| issuer | `http://localhost:18080`（== public origin ✅） |
| authorization_endpoint | `http://localhost:18080/oauth/v2/authorize` |
| token_endpoint | `http://localhost:18080/oauth/v2/token` |
| jwks_uri | `http://localhost:18080/oauth/v2/keys` |
| userinfo_endpoint | `http://localhost:18080/oidc/v1/userinfo` |
| end_session_endpoint | `http://localhost:18080/oidc/v1/end_session` |
| device_authorization_endpoint | `http://localhost:18080/oauth/v2/device_authorization` |

## 4. Path-prefix probe（observed login redirect，authRequest 脱敏）

两条独立通道，结论一致：

| 通道 | authorize 状态 | observed login redirect | 判定 |
| --- | --- | --- | --- |
| 集成测试 `observeAuthorizeRedirect` | 302 | `http://localhost:18080/_interaction/login?authRequest=V2_38523…（redacted，21 chars）` | **prefix preserved: YES** |
| `scripts/topology-probe.sh`（独立 probe app，Management API 建后即删） | 302 | `http://localhost:18080/_interaction/login?authRequest=V2_38523…（redacted，21 chars）` | **prefix preserved: YES** |

即：ZITADEL v2.71 的 login redirect 构造保留 `/_interaction` 路径前缀（`url.URL.JoinPath` 语义），无需退到 dedicated interaction host（ADR-0005 §1 的 fallback 分支不触发）。两次 probe 各留下 1 个未完成 auth request，随 provider 默认 TTL 过期作废，未被消费。

## 5. 遗留与后续

- P3.9 最终 acceptance 须对同一拓扑再跑一遍上述 probe（runbook §4 步骤 6–7）。
- 生产部署时 `UP_OAUTH_PUBLIC_ORIGIN` 必须为 HTTPS origin；`interactionBaseURI` 一律派生，禁止独立配置（见 `docs/topology-runbook.md` §2）。
