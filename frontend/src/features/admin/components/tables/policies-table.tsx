//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Policies listing table
//

"use client";

import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import Link from "next/link";
import { Button } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import type { AuthorizationPolicy } from "@/features/policies/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import type { CursorPage } from "@/types/pagination";
import {
  createScopedColumn,
  ManagementDirectory,
  PrimaryCell,
  SecondaryCell,
  type DirectoryCopy,
} from "../management-directory";

const copy = {
  eyebrow: "ABAC policies",
  title: "授权策略",
  description: "管理业务授权策略。OAuth Scope 与 ABAC 业务权限保持独立。",
  searchPlaceholder: "搜索策略或资源",
  actionLabel: "新建策略",
} satisfies DirectoryCopy;

const columns: ColumnProps<AuthorizationPolicy>[] = [
  createScopedColumn({
    title: "策略",
    dataIndex: "name",
    width: 260,
    render: (_value: unknown, record: AuthorizationPolicy) => <PrimaryCell primary={record.name} secondary={record.policyId} />,
  }),
  createScopedColumn({
    title: "资源",
    dataIndex: "resource",
    width: 170,
    render: (_value: unknown, record: AuthorizationPolicy) => <SecondaryCell><code>{record.resource}</code></SecondaryCell>,
  }),
  createScopedColumn({
    title: "版本",
    dataIndex: "version",
    width: 90,
    render: (_value: unknown, record: AuthorizationPolicy) => `v${record.version}`,
  }),
  createScopedColumn({
    title: "状态",
    dataIndex: "status",
    width: 110,
    render: (_value: unknown, record: AuthorizationPolicy) => (
      <StatusBadge label={record.status === "published" ? "已发布" : "草稿"} tone={record.status === "published" ? "success" : "warning"} />
    ),
  }),
  createScopedColumn({
    title: "最近更新",
    dataIndex: "updatedAt",
    width: 200,
    render: (_value: unknown, record: AuthorizationPolicy) => (
      <PrimaryCell primary={record.updatedBy} secondary={formatSecurityDateTime(record.updatedAt)} />
    ),
  }),
  createScopedColumn({
    title: "操作",
    width: 100,
    render: (_value: unknown, record: AuthorizationPolicy) => (
      <Link href={`/admin/policies/${record.policyId}`}>
        <Button theme="borderless">查看</Button>
      </Link>
    ),
  }),
];

type PoliciesTableProps = {
  records: AuthorizationPolicy[];
  actionHref?: string;
  page: CursorPage<unknown>["page"];
  query?: string;
  hasPrevious: boolean;
};

export function PoliciesTable({ records, actionHref, page, query, hasPrevious }: PoliciesTableProps) {
  const action = actionHref ? (
    <Link href={actionHref}>
      <Button theme="solid" type="primary">新建策略</Button>
    </Link>
  ) : undefined;

  return (
    <ManagementDirectory
      columns={columns}
      copy={copy}
      getSearchText={(record) => [record.name, record.resource, record.policyId].join(" ")}
      records={records}
      rowKey="policyId"
      action={action}
      basePath="/admin/policies"
      initialQuery={query}
      page={page}
      hasPrevious={hasPrevious}
    />
  );
}
