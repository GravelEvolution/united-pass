"use client";

import { useState } from "react";
import { Input } from "@douyinfe/semi-ui";
import { IconSearch } from "@douyinfe/semi-icons";
import { MockActionButton } from "@/components/common/mock-action-button";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { AuditEvent, DepartmentRecord, EmployeeRecord, IdentityProviderRecord, ManagedUser } from "@/features/admin/types";
import type { OAuthApplication } from "@/features/applications/types";
import type { AuthorizationPolicy } from "@/features/policies/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./admin.module.css";

type DirectoryProps =
  | { kind: "users"; records: ManagedUser[] }
  | { kind: "employees"; records: EmployeeRecord[] }
  | { kind: "departments"; records: DepartmentRecord[] }
  | { kind: "providers"; records: IdentityProviderRecord[] }
  | { kind: "applications"; records: OAuthApplication[] }
  | { kind: "policies"; records: AuthorizationPolicy[] }
  | { kind: "audit"; records: AuditEvent[] };

const directoryCopy = {
  users: { eyebrow: "Identity directory", title: "用户", description: "查询稳定用户身份及其关联的人格类型。邮箱仅作为联系方式，不作为用户标识。", search: "搜索姓名、邮箱或用户 ID", action: "邀请用户" },
  employees: { eyebrow: "Workforce", title: "员工", description: "管理员工档案与入离职状态；员工档案始终关联到既有统一账户。", search: "搜索员工、编号或部门", action: "关联员工档案" },
  departments: { eyebrow: "Organization", title: "部门", description: "查看组织结构、负责人和成员规模。", search: "搜索部门或负责人", action: "创建部门" },
  providers: { eyebrow: "Identity connections", title: "Provider 管理", description: "管理外部身份提供方的接入状态。飞书目前仅记录为未来能力，尚未启用登录。", search: "搜索 Provider、厂商或接入方式", action: "新增 Provider" },
  applications: { eyebrow: "OAuth 2.0 / OIDC", title: "OAuth 应用", description: "管理应用元数据、客户端类型和重定向 URI。客户端密钥不会在列表中展示。", search: "搜索应用或负责人", action: "注册应用" },
  policies: { eyebrow: "ABAC policies", title: "授权策略", description: "管理业务授权策略。OAuth Scope 与 ABAC 业务权限保持独立。", search: "搜索策略或资源", action: "新建策略" },
  audit: { eyebrow: "Security audit", title: "审计事件", description: "查看重要身份、安全和管理操作。时间统一显示为北京时间并保留完整日期。", search: "搜索事件、操作者或目标", action: "导出审计日志" },
} satisfies Record<DirectoryProps["kind"], { eyebrow: string; title: string; description: string; search: string; action: string }>;

function statusForUser(status: ManagedUser["status"]) {
  if (status === "active") return <StatusBadge label="正常" tone="success" />;
  if (status === "pending") return <StatusBadge label="待验证" tone="warning" />;
  return <StatusBadge label="已停用" tone="danger" />;
}

function recordMatchesSearch(record: object, normalizedQuery: string): boolean {
  return !normalizedQuery || Object.values(record).join(" ").toLocaleLowerCase("zh-CN").includes(normalizedQuery);
}

function filterRecords<RecordType extends object>(records: RecordType[], normalizedQuery: string): RecordType[] {
  return records.filter((record) => recordMatchesSearch(record, normalizedQuery));
}

function countMatchingRecords(records: readonly object[], normalizedQuery: string): number {
  return records.filter((record) => recordMatchesSearch(record, normalizedQuery)).length;
}

export function ManagementDirectory(props: DirectoryProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const copy = directoryCopy[props.kind];
  const normalizedQuery = searchQuery.trim().toLocaleLowerCase("zh-CN");

  const filteredRecordCount = countMatchingRecords(props.records, normalizedQuery);

  return (
    <>
      <PageHeader
        eyebrow={copy.eyebrow}
        title={copy.title}
        description={copy.description}
        action={<MockActionButton primary message={copy.action}>{copy.action}</MockActionButton>}
      />

      <section className={styles.directoryCard}>
        <div className={styles.toolbar}>
          <Input
            value={searchQuery}
            onChange={setSearchQuery}
            prefix={<IconSearch />}
            placeholder={copy.search}
            showClear
            aria-label={copy.search}
          />
          <span>共 {filteredRecordCount} 条 mock 记录</span>
        </div>
        <div className={styles.tableScroll}>
          {props.kind === "users" && (
            <table><thead><tr><th>用户</th><th>人格</th><th>状态</th><th>最近活动</th><th>操作</th></tr></thead><tbody>
              {filterRecords(props.records, normalizedQuery).map((record) => <tr key={record.userId}><td><strong>{record.displayName}</strong><span>{record.email}<br />{record.userId}</span></td><td>{record.personaLabel}</td><td>{statusForUser(record.status)}</td><td>{formatSecurityDateTime(record.lastActiveAt)}</td><td><MockActionButton message={`查看用户 ${record.displayName}`}>查看</MockActionButton></td></tr>)}
            </tbody></table>
          )}
          {props.kind === "employees" && (
            <table><thead><tr><th>员工</th><th>员工编号</th><th>部门 / 职位</th><th>状态</th><th>操作</th></tr></thead><tbody>
              {filterRecords(props.records, normalizedQuery).map((record) => <tr key={record.userId}><td><strong>{record.displayName}</strong><span>{record.userId}</span></td><td>{record.employeeId}</td><td>{record.departmentName}<span>{record.title}</span></td><td><StatusBadge label={record.status === "active" ? "在职" : "离职处理中"} tone={record.status === "active" ? "success" : "warning"} /></td><td><MockActionButton message={`查看员工 ${record.displayName}`}>查看</MockActionButton></td></tr>)}
            </tbody></table>
          )}
          {props.kind === "departments" && (
            <table><thead><tr><th>部门</th><th>上级部门</th><th>负责人</th><th>成员</th><th>操作</th></tr></thead><tbody>
              {filterRecords(props.records, normalizedQuery).map((record) => <tr key={record.departmentId}><td><strong>{record.name}</strong><span>{record.departmentId}</span></td><td>{record.parentName}</td><td>{record.ownerName}</td><td>{record.memberCount}</td><td><MockActionButton message={`查看部门 ${record.name}`}>查看</MockActionButton></td></tr>)}
            </tbody></table>
          )}
          {props.kind === "applications" && (
            <table><thead><tr><th>应用</th><th>客户端类型</th><th>负责人</th><th>重定向 URI</th><th>状态</th><th>操作</th></tr></thead><tbody>
              {filterRecords(props.records, normalizedQuery).map((record) => <tr key={record.applicationId}><td><strong>{record.name}</strong><span>{record.applicationId}</span></td><td>{record.clientType === "public" ? "公共客户端（PKCE）" : "机密客户端"}</td><td>{record.ownerName}</td><td>{record.redirectUriCount} 个</td><td><StatusBadge label={record.status === "active" ? "正常" : "已停用"} tone={record.status === "active" ? "success" : "danger"} /></td><td><MockActionButton message={`查看应用 ${record.name}`}>查看</MockActionButton></td></tr>)}
            </tbody></table>
          )}
          {props.kind === "providers" && (
            <table><thead><tr><th>Provider</th><th>接入方式</th><th>状态</th><th>登录</th><th>已关联用户</th><th>最近更新</th><th>操作</th></tr></thead><tbody>
              {filterRecords(props.records, normalizedQuery).map((record) => <tr key={record.providerId}><td><strong>{record.displayName}</strong><span>{record.providerId} · {record.vendor}</span></td><td>{record.integrationLabel}</td><td><StatusBadge label={record.status === "active" ? "正常" : record.status === "disabled" ? "已停用" : "规划中"} tone={record.status === "active" ? "success" : record.status === "disabled" ? "danger" : "warning"} /></td><td><StatusBadge label={record.loginEnabled ? "已启用" : "未启用"} tone={record.loginEnabled ? "success" : "neutral"} /></td><td>{record.linkedUserCount}</td><td>{formatSecurityDateTime(record.updatedAt)}</td><td><MockActionButton message={`查看 Provider ${record.displayName}`}>查看</MockActionButton></td></tr>)}
            </tbody></table>
          )}
          {props.kind === "policies" && (
            <table><thead><tr><th>策略</th><th>资源</th><th>版本</th><th>状态</th><th>最近更新</th><th>操作</th></tr></thead><tbody>
              {filterRecords(props.records, normalizedQuery).map((record) => <tr key={record.policyId}><td><strong>{record.name}</strong><span>{record.policyId}</span></td><td><code>{record.resource}</code></td><td>v{record.version}</td><td><StatusBadge label={record.status === "published" ? "已发布" : "草稿"} tone={record.status === "published" ? "success" : "warning"} /></td><td>{record.updatedBy}<span>{formatSecurityDateTime(record.updatedAt)}</span></td><td><MockActionButton message={`查看策略 ${record.name}`}>查看</MockActionButton></td></tr>)}
            </tbody></table>
          )}
          {props.kind === "audit" && (
            <table><thead><tr><th>事件</th><th>操作者</th><th>目标</th><th>结果</th><th>发生时间</th></tr></thead><tbody>
              {filterRecords(props.records, normalizedQuery).map((record) => <tr key={record.eventId}><td><strong>{record.eventType}</strong><span>{record.eventId}</span></td><td>{record.actorName}</td><td>{record.targetLabel}</td><td><StatusBadge label={record.result === "success" ? "成功" : "已拒绝"} tone={record.result === "success" ? "success" : "danger"} /></td><td>{formatSecurityDateTime(record.occurredAt)}</td></tr>)}
            </tbody></table>
          )}
        </div>
        {filteredRecordCount === 0 && <div className={styles.emptyState}><strong>没有匹配记录</strong><p>请调整搜索关键词后重试。</p></div>}
      </section>
    </>
  );
}
