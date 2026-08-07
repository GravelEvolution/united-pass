//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Employees listing table
//

"use client";

import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import Link from "next/link";
import { Button } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import type { EmployeeRecord } from "@/features/admin/types";
import {
  createScopedColumn,
  ManagementDirectory,
  PrimaryCell,
  type DirectoryCopy,
} from "../management-directory";

const copy = {
  eyebrow: "Workforce",
  title: "员工",
  description: "管理员工档案与入离职状态；员工档案始终关联到既有统一账户。",
  searchPlaceholder: "搜索员工、编号或部门",
  actionLabel: "关联员工档案",
} satisfies DirectoryCopy;

const columns: ColumnProps<EmployeeRecord>[] = [
  createScopedColumn({
    title: "员工",
    dataIndex: "displayName",
    width: 200,
    render: (_value: unknown, record: EmployeeRecord) => <PrimaryCell primary={record.displayName} secondary={record.userId} />,
  }),
  createScopedColumn({ title: "员工编号", dataIndex: "employeeId", width: 130 }),
  createScopedColumn({
    title: "部门 / 职位",
    dataIndex: "departmentName",
    width: 210,
    render: (_value: unknown, record: EmployeeRecord) => <PrimaryCell primary={record.departmentName} secondary={record.title} />,
  }),
  createScopedColumn({
    title: "状态",
    dataIndex: "status",
    width: 130,
    render: (_value: unknown, record: EmployeeRecord) => (
      <StatusBadge
        label={record.status === "active" ? "在职" : "离职处理中"}
        tone={record.status === "active" ? "success" : "warning"}
      />
    ),
  }),
  createScopedColumn({
    title: "操作",
    width: 100,
    render: (_value: unknown, record: EmployeeRecord) => (
      <Link href={`/admin/employees/${record.userId}`}>
        <Button theme="borderless">查看</Button>
      </Link>
    ),
  }),
];

export function EmployeesTable({ records, actionHref }: { records: EmployeeRecord[]; actionHref?: string }) {
  const action = actionHref ? (
    <Link href={actionHref}>
      <Button theme="solid" type="primary">关联员工档案</Button>
    </Link>
  ) : undefined;

  return (
    <ManagementDirectory
      columns={columns}
      copy={copy}
      getSearchText={(record) => [record.displayName, record.employeeId, record.departmentName, record.title].join(" ")}
      records={records}
      rowKey="userId"
      action={action}
    />
  );
}
