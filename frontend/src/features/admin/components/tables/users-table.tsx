"use client";

import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import Link from "next/link";
import { Button } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import type { ManagedUser } from "@/features/admin/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import {
  createScopedColumn,
  ManagementDirectory,
  PrimaryCell,
  SecondaryCell,
  type DirectoryCopy,
} from "../management-directory";

const copy = {
  eyebrow: "Identity directory",
  title: "用户",
  description: "查询稳定用户身份及其关联的人格类型。邮箱仅作为联系方式，不作为用户标识。",
  searchPlaceholder: "搜索姓名、邮箱或用户 ID",
  actionLabel: "邀请用户",
} satisfies DirectoryCopy;

function userStatus(status: ManagedUser["status"]) {
  if (status === "active") return <StatusBadge label="正常" tone="success" />;
  if (status === "pending") return <StatusBadge label="待验证" tone="warning" />;
  return <StatusBadge label="已停用" tone="danger" />;
}

const columns: ColumnProps<ManagedUser>[] = [
  createScopedColumn({
    title: "用户",
    dataIndex: "displayName",
    width: 240,
    render: (_value: unknown, record: ManagedUser) => (
      <PrimaryCell primary={record.displayName} secondary={<>{record.email}<br />{record.userId}</>} />
    ),
  }),
  createScopedColumn({ title: "人格", dataIndex: "personaLabel", width: 140 }),
  createScopedColumn({
    title: "状态",
    dataIndex: "status",
    width: 110,
    render: (_value: unknown, record: ManagedUser) => userStatus(record.status),
  }),
  createScopedColumn({
    title: "最近活动",
    dataIndex: "lastActiveAt",
    width: 190,
    render: (_value: unknown, record: ManagedUser) => <SecondaryCell>{formatSecurityDateTime(record.lastActiveAt)}</SecondaryCell>,
  }),
  createScopedColumn({
    title: "操作",
    width: 100,
    render: (_value: unknown, record: ManagedUser) => (
      <Link href={`/admin/users/${record.userId}`}>
        <Button theme="borderless">查看</Button>
      </Link>
    ),
  }),
];

export function UsersTable({ records }: { records: ManagedUser[] }) {
  return (
    <ManagementDirectory
      columns={columns}
      copy={copy}
      getSearchText={(record) => [record.displayName, record.email, record.userId].join(" ")}
      records={records}
      rowKey="userId"
    />
  );
}
