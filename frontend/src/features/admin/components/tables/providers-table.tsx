//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Providers listing table
//

"use client";

import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import Link from "next/link";
import { Button } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import type { IdentityProviderRecord } from "@/features/admin/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import {
  createScopedColumn,
  ManagementDirectory,
  PrimaryCell,
  SecondaryCell,
  type DirectoryCopy,
} from "../management-directory";

const copy = {
  eyebrow: "Identity connections",
  title: "Provider 管理",
  description: "管理飞书登录、服务端凭据状态、目录同步作业与显式身份关联。",
  searchPlaceholder: "搜索 Provider、厂商或接入方式",
  actionLabel: "新增 Provider",
} satisfies DirectoryCopy;

function providerStatus(record: IdentityProviderRecord) {
  if (record.status === "active") return <StatusBadge label="正常" tone="success" />;
  if (record.status === "disabled") return <StatusBadge label="已停用" tone="danger" />;
  return <StatusBadge label="规划中" tone="warning" />;
}

const columns: ColumnProps<IdentityProviderRecord>[] = [
  createScopedColumn({
    title: "Provider",
    dataIndex: "displayName",
    width: 220,
    render: (_value: unknown, record: IdentityProviderRecord) => (
      <PrimaryCell primary={record.displayName} secondary={`${record.providerId} · ${record.vendor}`} />
    ),
  }),
  createScopedColumn({ title: "接入方式", dataIndex: "integrationLabel", width: 230 }),
  createScopedColumn({
    title: "状态",
    dataIndex: "status",
    width: 110,
    render: (_value: unknown, record: IdentityProviderRecord) => providerStatus(record),
  }),
  createScopedColumn({
    title: "登录",
    dataIndex: "loginEnabled",
    width: 110,
    render: (_value: unknown, record: IdentityProviderRecord) => (
      <StatusBadge label={record.loginEnabled ? "已启用" : "未启用"} tone={record.loginEnabled ? "success" : "neutral"} />
    ),
  }),
  createScopedColumn({ title: "已关联用户", dataIndex: "linkedUserCount", width: 120 }),
  createScopedColumn({
    title: "最近更新",
    dataIndex: "updatedAt",
    width: 190,
    render: (_value: unknown, record: IdentityProviderRecord) => <SecondaryCell>{formatSecurityDateTime(record.updatedAt)}</SecondaryCell>,
  }),
  createScopedColumn({
    title: "操作",
    width: 100,
    render: (_value: unknown, record: IdentityProviderRecord) => (
      <Link href={`/admin/providers/${record.providerId}`}>
        <Button theme="borderless">查看</Button>
      </Link>
    ),
  }),
];

export function ProvidersTable({ records }: { records: IdentityProviderRecord[] }) {
  return (
    <ManagementDirectory
      columns={columns}
      copy={copy}
      getSearchText={(record) => [record.displayName, record.vendor, record.integrationLabel].join(" ")}
      records={records}
      rowKey="providerId"
    />
  );
}
