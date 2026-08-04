"use client";

import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import { StatusBadge } from "@/components/common/status-badge";
import type { AuditEvent } from "@/features/admin/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import {
  createScopedColumn,
  ManagementDirectory,
  PrimaryCell,
  SecondaryCell,
  type DirectoryCopy,
} from "../management-directory";

const copy = {
  eyebrow: "Security audit",
  title: "审计事件",
  description: "查看重要身份、安全和管理操作。时间统一显示为北京时间并保留完整日期。",
  searchPlaceholder: "搜索事件、操作者或目标",
  actionLabel: "导出审计日志",
} satisfies DirectoryCopy;

const columns: ColumnProps<AuditEvent>[] = [
  createScopedColumn({
    title: "事件",
    dataIndex: "eventType",
    width: 220,
    render: (_value: unknown, record: AuditEvent) => <PrimaryCell primary={record.eventType} secondary={record.eventId} />,
  }),
  createScopedColumn({ title: "操作者", dataIndex: "actorName", width: 150 }),
  createScopedColumn({ title: "目标", dataIndex: "targetLabel", width: 220 }),
  createScopedColumn({
    title: "结果",
    dataIndex: "result",
    width: 110,
    render: (_value: unknown, record: AuditEvent) => (
      <StatusBadge label={record.result === "success" ? "成功" : "已拒绝"} tone={record.result === "success" ? "success" : "danger"} />
    ),
  }),
  createScopedColumn({
    title: "发生时间",
    dataIndex: "occurredAt",
    width: 200,
    render: (_value: unknown, record: AuditEvent) => <SecondaryCell>{formatSecurityDateTime(record.occurredAt)}</SecondaryCell>,
  }),
];

export function AuditTable({ records }: { records: AuditEvent[] }) {
  return (
    <ManagementDirectory
      columns={columns}
      copy={copy}
      getSearchText={(record) => [record.eventType, record.actorName, record.targetLabel, record.eventId].join(" ")}
      records={records}
      rowKey="eventId"
    />
  );
}
