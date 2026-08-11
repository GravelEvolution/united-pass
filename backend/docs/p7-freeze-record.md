# Phase 7 策略与审计实现冻结记录

- 日期：2026-08-11
- 状态：**IMPLEMENTATION COMPLETE；LOCAL GATES PASSED；LIVE CERBOS/ZITADEL PENDING**
- 基线：Phase 6 `fb1fac5`
- 验收对象：schema migration `v10`、Cerbos PDP/Admin、策略版本/发布、审计筛选/导出

## 1. 冻结范围

- PostgreSQL 权威 Principal context 与离职前置拒绝；
- 15 项 capability 到 action/resource 的稳定映射；
- Cerbos `CheckResources` 每批最多 50 项、显式 deny 优先、默认拒绝；
- 草稿、乐观锁、不可变版本、已发布版本继续生效；
- durable publication job、Cerbos Admin 发布和选定版本/audit 事务；
- 单策略 side-effect-free simulation；
- canonical security event 游标/类型/actor/result/request/time/text 筛选；
- durable audit export job、stale reclaim、10,000 条上限、固定字段 CSV、15 分钟下载；
- `policy.publish` / `audit.export` target-bound step-up；
- P7 frontend real queries/commands、runtime validators、发布/导出真实状态 UX；
- ADR-0013、frontend ADR-0009、OpenAPI 0.7.0。

## 2. 明确不宣称

- 当前工作区尚未配置可变存储的真实 Cerbos Admin API，live policy install/check
  不标记 Passed；
- 本轮尚未重复执行真实 ZITADEL 浏览器回归；
- 本文件的最终门禁表必须在完整门禁执行后更新，不能以单元测试代替。

## 3. 安全边界

- 浏览器属性只用于 simulation，不进入真实权限判断；
- PDP/存储超时、错误、空策略和不完整响应全部 fail closed；
- Cerbos Admin Basic 凭据只在 server config 和 outbound header；
- 导出只含固定展示字段，不读取 `security_events.payload`，并中和电子表格公式前缀；
- 发布/导出成功状态与 durable audit 同事务；
- artifact 仅请求者可下载，15 分钟后拒绝下载并由 worker 清空内容。

## 4. 最终门禁记录

| 门禁 | 结果 | 证据 |
| --- | --- | --- |
| 本地静态检查 | Passed | `gofmt -w .`、`git diff --check`、`go mod tidy` 后 go.mod/go.sum 无差异、普通/`integration` tag `go vet`、OpenAPI 0.7.0 YAML 与 682 个本地 `$ref` 均可解析 |
| 本地单元测试 | Passed | `go test ./...`；前端 Node v24.17.0 下 17 个 test files / 216 tests Passed |
| 本地 Race | Passed | `go test -race ./...` |
| 本地集成测试 | Passed | SSH 隧道 + `.env`：`go test -tags integration -race ./internal/adapters/postgres/... ./internal/adapters/redis/...`；PostgreSQL 510.289s、Redis 129.024s |
| 本地构建 | Passed | 普通/`integration` tag `go build ./...`；Node v24.17.0 下 `pnpm install --frozen-lockfile`、lint、typecheck、Next.js production build |
| 真实 Cerbos 验收 | Pending | 本机 `.env` 未配置 PDP/Admin URL 与 Admin 凭据，未执行 live install/check；不冒充 Passed |
| 真实 ZITADEL 验收 | Pending | 本轮未重复执行浏览器登录/step-up 回归 |
| GitHub Actions | 因额度耗尽暂未验证 | 按仓库门禁约定，远程 job 当前不作为提交门禁 |
