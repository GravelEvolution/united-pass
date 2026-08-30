"use client";

import Link from "next/link";
import { Button, Empty, Table, Tag } from "@douyinfe/semi-ui";
import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import { PageHeader } from "@/components/common/page-header";
import type { DreamUPApplication, DreamUPApplicationStatus } from "../types";
import styles from "./dreamup-admin.module.css";

const statusCopy: Record<DreamUPApplicationStatus, { label: string; color: "blue" | "green" | "red" | "amber" | "grey" }> = {
  submitted: { label: "待审核", color: "blue" },
  under_review: { label: "审核中", color: "amber" },
  accepted: { label: "已录取", color: "green" },
  waitlisted: { label: "候补", color: "amber" },
  rejected: { label: "已拒绝", color: "red" },
  withdrawn: { label: "已撤回", color: "grey" },
};

function formatTime(value: string | number | null): string {
  if (value === null) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  }).format(date);
}

export function DreamUPApplicationDirectory({
  eventId,
  eventName,
  applications,
}: {
  eventId: string;
  eventName: string;
  applications: DreamUPApplication[];
}) {
  const columns: ColumnProps<DreamUPApplication>[] = [
    {
      title: "报名代号",
      dataIndex: "displayHandle",
      width: 210,
      render: (_value, record) => <strong className={styles.handle}>{record.displayHandle}</strong>,
    },
    {
      title: "方向",
      width: 220,
      render: (_value, record) => String(record.reviewAnswers.primary_role ?? "未填写"),
    },
    {
      title: "状态",
      width: 120,
      render: (_value, record) => <Tag color={statusCopy[record.status].color}>{statusCopy[record.status].label}</Tag>,
    },
    {
      title: "提交时间",
      width: 150,
      render: (_value, record) => formatTime(record.submittedAt),
    },
    {
      title: "操作",
      width: 110,
      render: (_value, record) => (
        <Link href={`/admin/dreamup/${encodeURIComponent(eventId)}/applications/${encodeURIComponent(record.id)}`}>
          <Button theme="borderless">在线审核</Button>
        </Link>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        eyebrow="报名审核"
        title={eventName}
        description="基础审核视图仅显示报名代号和评审所需答案，不加载身份信息或法律材料。"
        action={<Link href="/admin/dreamup"><Button theme="outline">返回活动</Button></Link>}
      />
      <section className={styles.tableCard} aria-label="报名列表">
        <Table<DreamUPApplication>
          columns={columns}
          dataSource={applications}
          rowKey="id"
          pagination={false}
          empty={<Empty title="暂无报名" description="提交后的报名会出现在这里。" />}
          scroll={{ x: 820 }}
        />
      </section>
    </>
  );
}
