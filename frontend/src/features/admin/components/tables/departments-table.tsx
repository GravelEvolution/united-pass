//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Departments listing table
//

"use client";

import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import Link from "next/link";
import { Button } from "@douyinfe/semi-ui";
import type { DepartmentRecord } from "@/features/admin/types";
import {
  createScopedColumn,
  ManagementDirectory,
  PrimaryCell,
  type DirectoryCopy,
} from "../management-directory";

const copy = {
  eyebrow: "Organization",
  title: "部门",
  description: "查看组织结构、负责人和成员规模。",
  searchPlaceholder: "搜索部门或负责人",
  actionLabel: "创建部门",
} satisfies DirectoryCopy;

const columns: ColumnProps<DepartmentRecord>[] = [
  createScopedColumn({
    title: "部门",
    dataIndex: "name",
    width: 220,
    render: (_value: unknown, record: DepartmentRecord) => <PrimaryCell primary={record.name} secondary={record.departmentId} />,
  }),
  createScopedColumn({ title: "上级部门", dataIndex: "parentName", width: 180 }),
  createScopedColumn({ title: "负责人", dataIndex: "ownerName", width: 140 }),
  createScopedColumn({ title: "成员", dataIndex: "memberCount", width: 100 }),
  createScopedColumn({
    title: "操作",
    width: 100,
    render: (_value: unknown, record: DepartmentRecord) => (
      <Link href={`/admin/departments/${record.departmentId}`}>
        <Button theme="borderless">查看</Button>
      </Link>
    ),
  }),
];

export function DepartmentsTable({ records }: { records: DepartmentRecord[] }) {
  return (
    <ManagementDirectory
      columns={columns}
      copy={copy}
      getSearchText={(record) => [record.name, record.parentName, record.ownerName].join(" ")}
      records={records}
      rowKey="departmentId"
    />
  );
}
