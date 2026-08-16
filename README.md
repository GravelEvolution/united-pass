# 砾石进化统一登录门户平台（United Pass）

United Pass 是统一身份、账户安全、OAuth 2.0 / OpenID Connect 授权、组织与员工、
Identity Provider、策略和审计的管理平台。仓库同时包含 Next.js 前端、Go API、
数据库迁移、OpenAPI 合同、架构决策记录和上线运行手册。

> 当前状态（2026-08-16）：Phase 0–8 及原前端 Mock 对应的生产 API 已完成技术实现。
> 真实飞书租户、真实 Cerbos、法律批准、生产 HTTPS/Secret Manager、备份恢复和正式
> 流量切换仍有外部验收项；Recovery Codes 因当前 Provider 能力保持架构性 Deferred。
> 仓库实现完成不等同于生产已正式上线。

## 系统架构

生产和完整联调采用单一浏览器 Origin。反向代理按路径把流量交给不同服务：

```text
Browser
  └── HTTPS reverse proxy (single origin)
        ├── /*, /login, /account, /admin       → Next.js frontend
        ├── /api/v1/*, /_interaction/*         → Go backend
        └── /oauth/v2/*, /oidc/v1/*,
            /.well-known/openid-configuration  → ZITADEL

Go backend
  ├── PostgreSQL  → 用户、组织、授权、策略、审计等权威持久数据
  ├── Redis       → 会话、挑战、限流和短期任务状态
  ├── ZITADEL     → 身份认证、凭据和 OAuth/OIDC Provider
  ├── Feishu      → 可选的登录与通讯录观察数据
  └── Cerbos      → 可选的运行时策略判定与发布
```

OAuth 协议端点由 ZITADEL 提供，United Pass 不自行实现 token、userinfo、revoke、
introspect 或 discovery。详细路由所有权和上线顺序见
[OAuth 拓扑运行手册](backend/docs/topology-runbook.md)。

## 技术栈

- Frontend：Next.js 16.3、React 19、TypeScript strict、Semi Design、pnpm 10
- Backend：Go 1.26.5、Chi、pgx、go-redis、ZITADEL Go SDK
- Data：PostgreSQL 16+、Redis 7+
- Identity / Policy：ZITADEL v2.71.x、Feishu OpenAPI、Cerbos
- Contracts：OpenAPI 3.1、前后端运行时响应收窄、ADR 与 freeze record

## 仓库结构

```text
.
├── frontend/                 Next.js 应用、组件、API 客户端与前端 ADR
├── backend/                  Go API、迁移、OpenAPI、适配器、worker 与后端 ADR
├── docs/                     PRD、法律文本和项目交接资料
├── AGENTS.md                 提交门禁与推送约束
└── README.md                 项目总览
```

子项目的详细说明分别见 [frontend/README.md](frontend/README.md) 和
[backend/README.md](backend/README.md)。

## Phase 状态

| Phase | 范围 | 当前状态 |
| --- | --- | --- |
| P0 | 配置、HTTP server、中间件、健康检查、日志、OpenAPI | 完成 |
| P1 | PostgreSQL 身份、Redis 会话、登录/MFA/退出、`/me`、权限 | 完成；真实 ZITADEL 本地验收通过 |
| P2 | OAuth Application / Client、密钥轮换、补偿、重认证与审计 | Passed / Frozen；前端真实 API 已接通 |
| P3 | OAuth 授权请求、登录恢复、Consent、Grant 与撤销、协议拓扑 | Passed / Frozen |
| P4 | 会话清单、密码、TOTP、Passkey、step-up 与结算加固 | Passed / Frozen；Recovery Codes 架构性 Deferred |
| P5 | 用户、员工档案、部门、离职和访问收敛 | Passed / Frozen |
| P6 | 飞书登录、目录 staging、同步历史与显式身份关联 | 实现冻结；真实飞书租户验收 Pending |
| P7 | Cerbos capability、策略版本/发布、审计查询与导出 | 技术实现完成；真实 Cerbos/ZITADEL 验收 Pending |
| P8 | 法律发布门禁、个人数据导出、30 天延迟注销 | 技术实现完成；法务和生产 go/no-go Pending |

权威状态以各阶段记录为准：
[P3](backend/docs/p3-freeze-record.md)、
[P4](backend/docs/p49-freeze-record.md)、
[P5](backend/docs/p5-freeze-record.md)、
[P6](backend/docs/p6-freeze-record.md)、
[P7](backend/docs/p7-freeze-record.md)、
[P8](backend/docs/p8-freeze-record.md)。

## 已实现的主要能力

- 密码登录、TOTP MFA、飞书 OAuth 登录入口、退出与限流；
- 公开注册、邮箱验证、抗账户枚举的密码找回/重置，以及重置后的旧会话失效；
- HttpOnly opaque session、CSRF、会话清单、单个/批量撤销和空闲超时；
- 密码修改、TOTP 和 WebAuthn Passkey 的 step-up 与 provider-authoritative 状态；
- 个人资料、服务端净化头像、Provider 验证的邮箱/手机号变更；
- OAuth/OIDC 交互登录、授权同意、可复用 Grant 和授权撤销；
- OAuth Application / Client 的完整管理界面与权限裁剪的真实管理仪表盘；
- 用户、员工、部门、Provider 同步与身份冲突的显式处理；
- fail-closed 管理权限、Cerbos 策略草稿/模拟/发布、持久审计和短期导出；
- 个人数据导出、30 天可取消的账户注销，以及带审批引用与源码哈希的法律发布门禁。

`frontend/src/lib/mock/` 仍作为显式选择的开发/单元测试 fixture 保留，但生产模式下
所有 `UnitedPassQueries` / `UnitedPassCommands` seam 均调用真实 HTTP API，不会静默
回落或写入 Mock。登录、注册、邮箱验证和密码恢复即使在 fixture 数据模式下也不会
伪造服务器会话或凭据成功。Recovery Codes 不提供伪实现：真实 UI 明确显示当前
Provider 不支持，待 Provider 提供可审计 API 后再单独设计。

## 登录态与 Cookie

- `up_session`：HttpOnly opaque Cookie；浏览器 JavaScript 不可读取，Redis 只保存
  token 的 SHA-256 哈希。
- `up_csrf`：同源 CSRF Cookie；写请求通过 `X-CSRF-Token` 回传并与会话绑定。
- 默认绝对有效期为 12 小时；勾选“记住登录状态”后为 720 小时（30 天）。
- 默认空闲超时为 2 小时；Redis touch 最短间隔为 5 分钟。
- 两种登录方式当前都会设置带 Max-Age 的持久 Cookie，区别是有效期，不是
  “关闭浏览器立即退出”。
- 生产必须使用 HTTPS、`Secure=true`、`SameSite=Lax`；HTTP 仅用于受控本地或
  测试环境，届时才允许 `Secure=false`。
- 已登录用户访问 `/login` 时，前端服务端会先通过后端 `/me` 确认会话：有效会话
  跳转 `/account`；带 OAuth `requestId` 时继续 `/authorize`；过期或已撤销会话
  仍显示登录页。Cookie 存在本身不会被当作已认证。

Redis 是临时状态存储而不是用户数据源；Redis 数据丢失会使相关会话和挑战失效，
不会删除 PostgreSQL 中的用户。

## 开发环境要求

- Node.js 24.x（仓库基准为 24.17.0）
- pnpm 10.x（`frontend/package.json` 固定 package manager）
- Go 1.26.5
- PostgreSQL 16+、Redis 7+
- 完整身份流程需要 ZITADEL；远程 PostgreSQL/Redis 若没有 TLS，必须走仓库提供的
  SSH 隧道，禁止在公网明文直连

不要提交 `.env`、Provider 密钥、数据库凭据、Session 加密密钥或验收账户材料。

## 本地启动

### 1. Backend

首次配置时，从模板创建本地文件并填入实际值；已有 `.env` 时不要覆盖：

```bash
cd backend
cp .env.template .env
./scripts/dev.sh up --migrate
```

该命令建立 SSH 隧道、执行迁移并以前台进程启动 API；退出时会停止它启动的隧道。
只查看或管理隧道可使用：

```bash
./scripts/dev.sh status
./scripts/dev.sh down
```

Backend 默认监听 `:8080`，`GET /healthz` 是存活检查，`GET /readyz` 会检查
PostgreSQL、Redis 和认证 Provider。完整配置变量见
[backend/README.md](backend/README.md#environment-variables)。

### 2. Frontend

```bash
cd frontend
fnm use 24.17.0
pnpm install --frozen-lockfile
cp .env.example .env.local
pnpm dev
```

打开 [http://localhost:3000](http://localhost:3000)。`.env.local` 中：

```dotenv
NEXT_PUBLIC_USE_MOCK=false
API_BASE_URL=http://localhost:8080/api/v1
```

`NEXT_PUBLIC_USE_MOCK=true` 只用于显式的界面 fixture 和单元测试；任何其他值都让
全部数据 seam 调用真实 API。认证凭据流程不受该开关伪造。该变量进入浏览器 bundle，
不得放入任何秘密。`API_BASE_URL` 只供 Next.js 服务端读取。

### 3. 完整同源联调

真实浏览器写请求固定调用同源 `/api/v1`，Next.js 本身不提供 API rewrite。因此完整
登录、Cookie、CSRF 与 OAuth 流程必须放在反向代理后运行，至少满足：

| 路径 | 上游 |
| --- | --- |
| `/api/v1/*`、`/_interaction/*` | Go backend |
| `/oauth/v2/*`、`/oidc/v1/*`、`/.well-known/openid-configuration` | ZITADEL |
| 其余路径 | Next.js frontend |

不要通过跨域 Cookie 或临时 CORS 绕过这一拓扑。详细配置、backfill、探针和切换顺序
见 [backend/docs/topology-runbook.md](backend/docs/topology-runbook.md)。

## 质量门禁

提交前以根 [AGENTS.md](AGENTS.md) 为准。Frontend 有修改时执行：

```bash
cd frontend
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Backend 有修改时执行：

```bash
cd backend
gofmt -w .
git diff --check
go mod tidy
git diff --exit-code go.mod go.sum
go vet ./...
go vet -tags integration ./...
go test ./...
go test -race ./...
go test -tags integration -race \
  ./internal/adapters/postgres/... \
  ./internal/adapters/redis/...
go build ./...
go build -tags integration ./...
```

集成测试需要独立的 `UP_TEST_*` 数据库/Redis 配置和 SSH 隧道。GitHub Actions 因
组织额度耗尽当前不作为提交门禁；不得用未分配 runner 的远程 job 代替本地检查。

## 安全与授权边界

- 前端菜单、布局和 `/admin` pre-render gate 只负责 UX 与提前阻断；Go API 对每个
  资源和动作独立执行权限检查，后端才是权威边界。
- 权限、Provider、Redis、Cerbos 或响应结构异常时默认拒绝，不降级为允许。
- 状态变更使用 session-bound CSRF；高风险操作另需 action/target-bound、单次使用
  的重认证 grant。
- 用户专属 SSR 请求均使用 `cache: no-store`；服务端只转发 `up_session` 和请求 ID。
- 生产必须启用 HTTPS、安全 Cookie、Secret Manager、数据库/Redis TLS 或私网，
  并完成 [P8 上线手册](backend/docs/p8-launch-runbook.md) 的外部签字。

## 文档索引

- [产品需求文档](docs/PRD.md)
- [Backend 使用、配置与 API 概览](backend/README.md)
- [Frontend 路由、数据源与开发说明](frontend/README.md)
- [OpenAPI 3.1 合同](backend/openapi/openapi.yaml)
- [前端人类可读 API 合同](frontend/docs/api-contracts.md)
- [OAuth 拓扑运行手册](backend/docs/topology-runbook.md)
- [Phase 8 上线手册](backend/docs/p8-launch-runbook.md)
- [法律文本与审批边界](docs/legal_terms/README.md)

后端 ADR 位于 `backend/docs/adr-*.md`，前端 ADR 位于
`frontend/docs/adr-*.md`；阶段验收以 `backend/docs/*freeze-record.md` 为准。
