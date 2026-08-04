"use client";

import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import Link from "next/link";
import { Button } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { AUDIENCE_LABELS, type OAuthApplication } from "@/features/applications/types";
import {
  createScopedColumn,
  ManagementDirectory,
  PrimaryCell,
  type DirectoryCopy,
} from "../management-directory";

const copy = {
  eyebrow: "OAuth 2.0 / OIDC",
  title: "OAuth 应用",
  description: "管理 OAuth 应用和客户端配置。客户端密钥不会在列表中展示。",
  searchPlaceholder: "搜索应用或负责人",
  actionLabel: "注册应用",
} satisfies DirectoryCopy;

const columns: ColumnProps<OAuthApplication>[] = [
  createScopedColumn({
    title: "应用",
    dataIndex: "name",
    width: 220,
    render: (_value: unknown, record: OAuthApplication) => (
      <Link href={`/admin/applications/${record.applicationId}`}>
        <PrimaryCell primary={record.name} secondary={record.applicationId} />
      </Link>
    ),
  }),
  createScopedColumn({
    title: "受众",
    dataIndex: "audience",
    width: 180,
    render: (_value: unknown, record: OAuthApplication) => AUDIENCE_LABELS[record.audience],
  }),
  createScopedColumn({ title: "负责人", dataIndex: "ownerName", width: 150 }),
  createScopedColumn({
    title: "Client 数量",
    dataIndex: "clientCount",
    width: 130,
    render: (_value: unknown, record: OAuthApplication) => `${record.clientCount} 个`,
  }),
  createScopedColumn({
    title: "状态",
    dataIndex: "status",
    width: 110,
    render: (_value: unknown, record: OAuthApplication) => (
      <StatusBadge label={record.status === "active" ? "正常" : "已停用"} tone={record.status === "active" ? "success" : "danger"} />
    ),
  }),
  createScopedColumn({
    title: "操作",
    width: 100,
    render: (_value: unknown, record: OAuthApplication) => (
      <Link href={`/admin/applications/${record.applicationId}`}>
        <Button size="small" theme="borderless">查看</Button>
      </Link>
    ),
  }),
];

export function ApplicationsTable({ records }: { records: OAuthApplication[] }) {
  return (
    <ManagementDirectory
      columns={columns}
      copy={copy}
      getSearchText={(record) => [record.name, record.ownerName, record.applicationId, record.audience].join(" ")}
      records={records}
      rowKey="applicationId"
      action={
        <Link href="/admin/applications/new">
          <Button type="primary" theme="solid">{copy.actionLabel}</Button>
        </Link>
      }
    />
  );
}
