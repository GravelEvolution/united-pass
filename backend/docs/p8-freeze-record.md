# Phase 8 正式上线技术实现冻结记录

- 日期：2026-08-11
- 状态：**TECHNICAL IMPLEMENTATION COMPLETE；EXTERNAL SIGN-OFF PENDING**
- 基线：Phase 7 `777d39b`
- 验收对象：schema migration v11、法律发布门禁、数据导出、延迟注销、上线 runbook

## 已实现范围

- 法律内容版本/哈希双端清单、审批引用持久化、显式 CLI 发布和公开状态 API；
- `account.data_export` 单次重认证、owner-bound JSON、15 分钟 artifact 与物理清理；
- `account.delete` 单次重认证、30 天冷静期、冷静期取消；
- provider delete → durable proof → session purge → local anonymisation 的可重试状态机；
- PII/身份关联/员工档案/授权清理，稳定 ID 与最小审计证明保留；
- 前端真实 API seam、runtime validator、轮询下载与注销状态 UX；
- OpenAPI 0.8.0、ADR-0014 与生产上线 runbook。

## 明确不宣称

- AI 审查报告不构成法务批准；本实现没有运行 `legal-publish`，两份文档仍未生效；
- 未执行真实生产流量切换、生产备份恢复演练或生产事故值班签字；
- 最终门禁结果在完整门禁执行后记录，不能以局部测试替代；
- 真实 ZITADEL 的破坏性注销验收必须使用可丢弃账户并由生产操作方明确批准。

## 最终门禁记录

| 门禁 | 结果 | 证据 |
| --- | --- | --- |
| 本地静态检查 | Passed | `gofmt -w .`、`git diff --check`、`go mod tidy` 后 go.mod/go.sum 无差异、普通/`integration` tag `go vet`；OpenAPI 0.8.0 YAML 与 719 个本地 `$ref` 均可解析；两份法律源文件 SHA-256 与双端 manifest 一致 |
| 本地单元测试 | Passed | `go test ./...`；前端 Node v24.17.0 下 18 个 test files / 220 tests Passed |
| 本地 Race | Passed | `go test -race ./...` |
| 本地集成测试 | Passed | SSH 隧道 + `.env`：`go test -tags integration -race ./internal/adapters/postgres/... ./internal/adapters/redis/...`；PostgreSQL 426.910s；Redis 另以 `-count=1` 强制重跑 54.999s；最终 P8 用例再以 `-count=1 -v` 强制重跑，v1–v11 migration 与全生命周期 Passed（19.739s） |
| 本地构建 | Passed | 普通/`integration` tag `go build ./...`；Node v24.17.0 下 frozen install、lint、typecheck、Next.js 16 production build |
| 真实 ZITADEL 验收 | Pending | 未对真实实例执行破坏性账户注销；需使用可丢弃生产-like 用户并取得操作方批准 |
| 法务批准 / 法律发布 | Pending | 未运行 `cmd/legal-publish`；隐私 v1.2 与条款 v1.1 仍为 Draft / Not Effective |
| 生产 go/no-go / 流量切换 | Pending | 备份恢复、值班归属、HTTPS/Secret Manager 与真实切流属于外部上线签字 |
| GitHub Actions | 因额度耗尽暂未验证 | 按仓库门禁约定，远程 job 当前不作为提交门禁 |
