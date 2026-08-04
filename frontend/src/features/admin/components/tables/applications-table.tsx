"use client";

import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import Link from "next/link";
import { Button } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import type { OAuthApplication } from "@/features/applications/types";
import {
  createScopedColumn,
  ManagementDirectory,
  PrimaryCell,
  type DirectoryCopy,
} from "../management-directory";

const copy = {
  eyebrow: "OAuth 2.0 / OIDC",
  title: "OAuth 应用",
  description: "管理应用元数据、客户端类型和重定向 URI。客户端密钥不会在列表中展示。",
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
    title: "客户端类型",
    dataIndex: "clientType",
    width: 180,
    render: (_value: unknown, record: OAuthApplication) => record.clientType === "public" ? "公共客户端（PKCE）" : "机密客户端",
  }),
  createScopedColumn({ title: "负责人", dataIndex: "ownerName", width: 150 }),
  createScopedColumn({
    title: "重定向 URI",
    dataIndex: "redirectUriCount",
    width: 130,
    render: (_value: unknown, record: OAuthApplication) => `${record.redirectUriCount} 个`,
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
      getSearchText={(record) => [record.name, record.ownerName, record.applicationId].join(" ")}
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
