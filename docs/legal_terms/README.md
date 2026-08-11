# Legal Documents

United Pass 法律文档索引。所有文档当前为**草案状态**，尚未正式生效。

## Status

| 项目 | 状态 |
| --- | --- |
| Overall status | Draft / Not Effective |
| Approved by | Pending — legal review |
| Effective date | Pending |
| Frontend publication | Controlled / Not activated（无匹配审批记录时显示“暂未生效”） |

> 正式生效应安排在 Phase 8 产品正式上线阶段，由法务最终确认后统一发布。

## Privacy Policy

| 版本 | 文件 | 审查报告 | 状态 |
| --- | --- | --- | --- |
| v1.2 (current draft) | `drafts/privacy-policy-v1.2.md` | `reviews/privacy-policy-review-v1.1.md` | Draft |

## Terms of Service

| 版本 | 文件 | 审查报告 | 状态 |
| --- | --- | --- | --- |
| v1.1 (current draft) | `drafts/terms-of-service-v1.1.md` | `reviews/terms-of-service-review-v1.1.md` | Draft |

## Directory Layout

```
docs/legal_terms/
├── README.md                # 本文件：版本索引与状态
├── drafts/                  # 政策条款草案（最新版）
│   ├── privacy-policy-v1.2.md
│   └── terms-of-service-v1.1.md
└── reviews/                 # 对应版本的审查报告
    ├── privacy-policy-review-v1.1.md
    └── terms-of-service-review-v1.1.md
```

旧版本通过 Git 历史保留，不保留在工作目录中以避免版本混淆。

## Publishing Checklist

正式生效前需要完成：

- [ ] 法务最终签字确认
- [ ] 版本号与生效日期锁定
- [x] 前端 `/privacy` 和 `/terms` 仅在版本 + SHA-256 与后端审批记录一致时显示生效状态
- [x] 后端提供受控发布命令和公开状态 API
- [x] 发布事务写入 durable Audit log
- [ ] 使用真实审批引用运行受控发布命令（当前未运行）
