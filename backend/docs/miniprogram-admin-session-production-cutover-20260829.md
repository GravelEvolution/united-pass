# DreamUP 小程序活动管理会话授权生产切换记录

- 切换时间：2026-08-29 02:39 UTC
- API release：`mini-admin-session-f299a05-20260829T0248Z`
- 源提交：`f299a05bbdf1dea578f328959df95b76cd5dd044`
- 源 tree：`0e3ffaeb4740e81732267112811a34c0104e7f7c`
- 构建：Go 1.26.6，linux/amd64，CGO disabled，release profile
- 二进制：59,288,566 bytes
- SHA-256：`2d00c3cc4747cf108a44ecb271df0732a9f396e9b9f6b8fe83bb084f6a5a52c8`

## 范围

仅切换 `moonstone-up-api.service` 的 release 符号链接并重启该服务一次。未修改 DreamUP 官网、United Pass 网页、nginx、TUN/代理或其他服务。本次没有数据库迁移，也没有写入或迁移 authority PostgreSQL。

服务端允许新版小程序以短期原生会话、安全纪元、近期登录、赛事 RBAC/角色绑定和对象级授权完成活动管理，不再要求客户端安全问题。浏览器管理员二次验证保持不变；旧小程序原生 step-up 路由保留一个兼容窗口。

## 构建与制品

第一次候选因源仓库内未跟踪缓存被 Go 标记为 `vcs.modified=true`，未部署。最终候选从同一提交的独立干净 Git worktree 构建，上传后在服务器执行 `--build-info`，提交、tree、profile、平台与本记录完全一致；远端 SHA-256 和字节长度均与本地候选一致。

## 切换前保护

- 上一 release：`/srv/moonstone-up-api/releases/wechat-onboarding-c0f519a-20260829T010309Z`
- 部署元数据备份：`/var/backups/moonstone/pre-mini-admin-session-20260829T0248Z`
- 备份目录权限：root `0700`；文件 `0600`
- 记录内容：原 release、原二进制 SHA-256/构建信息、切换前后服务状态、新 release 与新二进制 SHA-256
- 上一 release 保持不变，可通过原子切换 `current` 符号链接并仅重启 API 回滚

数据库没有结构或数据变更，因此沿用 2026-08-29 已验证的生产全量备份，不执行会造成额外锁和 I/O 的重复数据库导出。

## 验证结果

- `current` 指向新 release
- `moonstone-up-api.service`：active，`NRestarts=0`
- loopback `/healthz`：200
- loopback `/readyz`：200
- 未认证 `/api/v1/admin/dreamup/session`：401
- 新进程日志：无 error、fatal 或 panic
- `moonstone-dreamup.service`：active
- `moonstone-up-web.service`：active
- 新二进制权限：`0750 moonstone-up-api:moonstone-up-api`

远端部署脚本在打印 `DEPLOYED`、`BACKUP` 和 SHA-256 后，Windows 管道额外附带的末尾 CR 被 Bash 解释为一个空白命令并返回 127。该错误发生在健康、构建信息、401 探针、`NRestarts=0`、备份收尾以及 `trap - ERR` 完成之后，没有触发回滚。随后独立执行了以上全部运行态核验，确认切换成功。

## 小程序制品

- 版本：`dreamup-mini-20260829-r5`
- 源提交：`925ada46942d9716fe3dac358bca73af95ca148a`
- bundle SHA-256：`09f9b45511298d135d03f5e312b2850fd53ff3cb2cfaa3ae1d975bb2ca6ef69c`
- 微信开发者工具 CLI：上传成功，状态为开发版本
- 下一门禁：在微信后台设为体验版，并在真机执行首次冷启动顶栏、登录—绑定—退出—再登录、普通用户越权和管理员会话失效回归
