# United Pass — Agent 提交门禁（本地先审查，再上传）

自 2026-08-07 起，所有提交必须先通过本地门禁再推送。
**暂不依赖 GitHub Actions 远程检查**（组织 Actions 分钟额度耗尽，job 无法分配
runner；配额恢复前远程 CI 不作为门禁项，恢复后另行启用）。

## 后端门禁（backend 有修改时必跑）

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

集成测试需要 SSH 隧道与测试库：先 `./scripts/tunnel.sh start`，
并在 backend 目录 source `.env`（`UP_TEST_*` 变量）；跑完 `./scripts/tunnel.sh stop`。
无法执行时如实记录"未执行及原因"，不得冒充通过。

## 前端门禁（frontend 有修改时必跑）

```bash
cd frontend

pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

## 审查结论格式（每次提交报告中必须明确区分）

- 本地静态检查：Passed / Failed
- 本地单元测试：Passed / Failed
- 本地 Race：Passed / Failed
- 本地集成测试：Passed / Failed / 未执行及原因
- 真实 ZITADEL 验收：Passed / Pending
- GitHub Actions：因额度耗尽暂未验证

## 每次提交后保留的输出

```bash
git status --short
git log -1 --oneline
git show --stat --oneline HEAD
```

## 推送约束

- 推送只使用本机 Mac 的正常 git 凭据（`git push origin main`）；
  不使用 GitHub Actions `GITHUB_TOKEN`、GitHub API `update_ref` 或 Contents API
  作为 main 分支的最终推送方式；
- 直接工作于 main，禁止分支绕行、禁止 `reset --hard` / `clean -fd` / 强推；
- 提交信息遵循 Conventional Commits；提交前检查 diff 无密钥/凭据泄漏；
- `docs/HANDOFF_260806.md` 保持未跟踪，绝不提交。
