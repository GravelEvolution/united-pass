//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Security audit log explorer UI
//

"use client";

import { useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Button,
  DatePicker,
  Empty,
  Input,
  Modal,
  Select,
  SideSheet,
  Table,
  Toast,
} from "@douyinfe/semi-ui";
import type { ColumnProps } from "@douyinfe/semi-ui/lib/es/table";
import { IconSearch, IconExport } from "@douyinfe/semi-icons";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import { AccountReauthenticationForm } from "@/features/account/components/security-overview";
import type { AuditEvent, AuditExportResult } from "@/features/admin/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import type { CursorPage } from "@/types/pagination";
import styles from "./admin.module.css";

const EVENT_TYPE_OPTIONS = [
  { value: "", label: "全部事件类型" },
  { value: "policy.published", label: "策略发布" },
  { value: "policy.publication_failed", label: "策略发布失败" },
  { value: "authorization.denied", label: "管理操作拒绝" },
  { value: "session.revoked", label: "会话撤销" },
  { value: "consent.grant_allowed", label: "OAuth 授权同意" },
  { value: "oauth_client.secret_rotated", label: "Client Secret 轮换" },
  { value: "application.disabled", label: "应用停用" },
  { value: "employee.linked", label: "员工档案关联" },
  { value: "provider.directory_sync_completed", label: "Provider 同步" },
  { value: "account.password_changed", label: "密码修改" },
  { value: "audit.export_requested", label: "审计导出" },
];

const RESULT_OPTIONS = [
  { value: "", label: "全部结果" },
  { value: "success", label: "成功" },
  { value: "denied", label: "已拒绝" },
];

type AuditExplorerProps = {
  records: AuditEvent[];
  page: CursorPage<unknown>["page"];
  hasPrevious: boolean;
  canExport: boolean;
};

export function AuditExplorer({ records, page, hasPrevious, canExport }: AuditExplorerProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportResult, setExportResult] = useState<AuditExportResult | null>(null);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const exportOperation = useRef<AbortController | null>(null);

  function updateFilter(key: string, value: string): void {
    const params = new URLSearchParams(searchParams.toString());
    if (value) {
      params.set(key, value);
    } else {
      params.delete(key);
    }
    params.delete("cursor");
    router.push(`/admin/audit?${params.toString()}`);
  }

  function handleDateRange(dates: [Date, Date] | undefined): void {
    const params = new URLSearchParams(searchParams.toString());
    if (dates && dates.length === 2) {
      params.set("from", dates[0].toISOString());
      params.set("to", dates[1].toISOString());
    } else {
      params.delete("from");
      params.delete("to");
    }
    params.delete("cursor");
    router.push(`/admin/audit?${params.toString()}`);
  }

  function navigateCursor(cursor?: string): void {
    const params = new URLSearchParams(searchParams.toString());
    if (cursor) params.set("cursor", cursor);
    else params.delete("cursor");
    router.push(`/admin/audit?${params.toString()}`);
  }

  function buildExportQuery(): Record<string, string | undefined> {
    const params: Record<string, string | undefined> = {};
    const query = searchParams.get("q") ?? undefined;
    const eventType = searchParams.get("eventType") ?? undefined;
    const result = searchParams.get("result") ?? undefined;
    const actorName = searchParams.get("actorName") ?? undefined;
    const requestId = searchParams.get("requestId") ?? undefined;
    const from = searchParams.get("from") ?? undefined;
    const to = searchParams.get("to") ?? undefined;
    if (query) params.query = query;
    if (eventType) params.eventType = eventType;
    if (result) params.result = result;
    if (actorName) params.actorName = actorName;
    if (requestId) params.requestId = requestId;
    if (from) params.from = from;
    if (to) params.to = to;
    return params;
  }

  async function handleExport(reauthToken: string, signal: AbortSignal): Promise<void> {
    setExporting(true);
    try {
      let result = await browserCommands.exportAuditEvents(
        buildExportQuery(),
        reauthToken,
        { signal },
      );
      setExportResult(result);
      for (let attempt = 0; attempt < 30 && (result.status === "pending" || result.status === "processing"); attempt += 1) {
        await waitForPoll(signal);
        result = await browserCommands.getAuditExport(result.exportId, { signal });
        setExportResult(result);
      }
      if (result.status === "failed") throw new Error("audit export failed");
      if (result.status !== "completed") {
        Toast.info({ content: "导出仍在后台处理中，可稍后刷新查看。" });
      } else {
        Toast.success({ content: `导出完成，共 ${result.totalEvents} 条事件。` });
      }
      setExportDialogOpen(false);
    } catch {
      Toast.error({ content: "导出失败，请重试。" });
      throw new Error("audit export failed");
    } finally {
      setExporting(false);
    }
  }

  function openExportModal(): void {
    setExportDialogOpen(true);
  }

  const columns: ColumnProps<AuditEvent>[] = [
    {
      title: "事件",
      dataIndex: "eventType",
      width: 220,
      onHeaderCell: () => ({ scope: "col" }),
      render: (_value: unknown, record: AuditEvent) => (
        <span className={styles.primaryCell}>
          <strong>{record.eventType}</strong>
          <span>{record.eventId}</span>
        </span>
      ),
    },
    {
      title: "操作者",
      dataIndex: "actorName",
      width: 140,
      onHeaderCell: () => ({ scope: "col" }),
      render: (_value: unknown, record: AuditEvent) => (
        <span className={styles.primaryCell}>
          <strong>{record.actorName}</strong>
          <span>{record.actorId}</span>
        </span>
      ),
    },
    {
      title: "目标",
      dataIndex: "targetLabel",
      width: 200,
      onHeaderCell: () => ({ scope: "col" }),
      render: (_value: unknown, record: AuditEvent) => (
        <span className={styles.primaryCell}>
          <strong>{record.targetLabel}</strong>
          <span>{record.targetId}</span>
        </span>
      ),
    },
    {
      title: "结果",
      dataIndex: "result",
      width: 100,
      onHeaderCell: () => ({ scope: "col" }),
      render: (_value: unknown, record: AuditEvent) => (
        <StatusBadge
          label={record.result === "success" ? "成功" : "已拒绝"}
          tone={record.result === "success" ? "success" : "danger"}
        />
      ),
    },
    {
      title: "Request ID",
      dataIndex: "requestId",
      width: 160,
      onHeaderCell: () => ({ scope: "col" }),
      render: (_value: unknown, record: AuditEvent) => (
        <span className={styles.secondaryCell}>
          <code>{record.requestId}</code>
        </span>
      ),
    },
    {
      title: "发生时间",
      dataIndex: "occurredAt",
      width: 200,
      onHeaderCell: () => ({ scope: "col" }),
      render: (_value: unknown, record: AuditEvent) => (
        <span className={styles.secondaryCell}>{formatSecurityDateTime(record.occurredAt)}</span>
      ),
    },
    {
      title: "操作",
      width: 90,
      onHeaderCell: () => ({ scope: "col" }),
      render: (_value: unknown, record: AuditEvent) => (
        <Button
          theme="borderless"
          size="small"
          onClick={() => setSelectedEvent(record)}
        >
          详情
        </Button>
      ),
    },
  ];

  const currentQuery = searchParams.get("q") ?? "";
  const currentEventType = searchParams.get("eventType") ?? "";
  const currentResult = searchParams.get("result") ?? "";
  const currentActorName = searchParams.get("actorName") ?? "";
  const currentRequestId = searchParams.get("requestId") ?? "";

  let dateRange: [Date, Date] | undefined = undefined;
  const fromParam = searchParams.get("from");
  const toParam = searchParams.get("to");
  if (fromParam && toParam) {
    dateRange = [new Date(fromParam), new Date(toParam)];
  }

  return (
    <>
      <PageHeader
        eyebrow="Security audit"
        title="审计事件"
        description="查看重要身份、安全和管理操作。支持按事件类型、操作者、结果和时间范围筛选。"
        action={canExport ? (
          <Button
            theme="solid"
            type="primary"
            icon={<IconExport />}
            loading={exporting}
            disabled={exporting}
            onClick={openExportModal}
          >
            导出审计日志
          </Button>
        ) : undefined}
      />

      <section className={styles.directoryCard} aria-label="审计事件目录">
        <div className={styles.toolbar} style={{ flexWrap: "wrap", gap: 12 }}>
          <Input
            value={currentQuery}
            onChange={(value) => updateFilter("q", value)}
            prefix={<IconSearch />}
            placeholder="搜索事件、操作者或目标"
            showClear
            aria-label="搜索审计事件"
            style={{ width: 240 }}
          />
          <Select
            value={currentEventType}
            onChange={(value) => updateFilter("eventType", value as string)}
            style={{ width: 180 }}
            optionList={EVENT_TYPE_OPTIONS}
            aria-label="按事件类型筛选"
          />
          <Select
            value={currentResult}
            onChange={(value) => updateFilter("result", value as string)}
            style={{ width: 140 }}
            optionList={RESULT_OPTIONS}
            aria-label="按结果筛选"
          />
          <Input
            value={currentActorName}
            onChange={(value) => updateFilter("actorName", value)}
            placeholder="操作者"
            showClear
            aria-label="按操作者筛选"
            style={{ width: 140 }}
          />
          <Input
            value={currentRequestId}
            onChange={(value) => updateFilter("requestId", value)}
            placeholder="Request ID"
            showClear
            aria-label="按 Request ID 筛选"
            style={{ width: 180 }}
          />
          <DatePicker
            type="dateRange"
            value={dateRange}
            onChange={(dates) => handleDateRange(dates as [Date, Date] | undefined)}
            aria-label="按日期范围筛选"
            style={{ width: 280 }}
          />
        </div>
        <div style={{ padding: "0 20px", color: "var(--up-muted)", fontSize: 13 }}>
          共 {records.length} 条审计事件
        </div>
        <div className={styles.tableScroll}>
          <Table<AuditEvent>
            className={styles.directoryTable}
            columns={columns}
            dataSource={records}
            empty={<Empty title="没有匹配记录" description="请调整筛选条件后重试。" />}
            pagination={false}
            rowKey="eventId"
            scroll={{ x: 1200 }}
            size="middle"
          />
        </div>
        {(page.hasMore || hasPrevious) && (
          <div className={styles.toolbar} style={{ justifyContent: "flex-end" }}>
            <Button theme="outline" onClick={() => router.back()} disabled={!hasPrevious}>
              上一页
            </Button>
            <Button
              theme="solid"
              type="primary"
              onClick={() => navigateCursor(page.nextCursor ?? undefined)}
              disabled={!page.hasMore || !page.nextCursor}
            >
              下一页
            </Button>
          </div>
        )}
      </section>

      {exportResult && (
        <div style={{ marginTop: 16, padding: 16, border: "1px solid var(--up-line)", borderRadius: "var(--up-radius-md)", background: "var(--up-surface)" }}>
          <h3 style={{ margin: "0 0 8px", fontSize: 14 }}>最近导出</h3>
          <p style={{ margin: 0, color: "var(--up-muted)", fontSize: 13 }}>
            导出 ID：<code>{exportResult.exportId}</code> · 状态：{exportResult.status === "completed" ? "已完成" : exportResult.status} · 事件数：{exportResult.totalEvents} · 请求时间：{formatSecurityDateTime(exportResult.requestedAt)}
          </p>
          {exportResult.downloadUrl && (
            <p style={{ margin: "8px 0 0" }}>
              <a href={exportResult.downloadUrl}>下载 CSV（链接 15 分钟内有效）</a>
            </p>
          )}
        </div>
      )}

      <Modal
        title="重新认证并导出审计日志"
        visible={exportDialogOpen}
        footer={null}
        maskClosable={false}
        closeOnEsc={false}
        onCancel={() => {
          exportOperation.current?.abort();
          exportOperation.current = null;
          setExportDialogOpen(false);
        }}
      >
        <p>将按当前筛选条件创建后端异步 CSV 导出任务。导出内容仅包含固定、脱敏的审计字段。</p>
        <AccountReauthenticationForm
          action="audit.export"
          target="audit"
          submitLabel="验证并导出"
          browserOperationRef={exportOperation}
          onGranted={handleExport}
          onCancel={() => setExportDialogOpen(false)}
          operationError="审计导出失败。授权不会被重复使用，请重新验证后再试。"
        />
      </Modal>

      <SideSheet
        title="审计事件详情"
        visible={selectedEvent !== null}
        onCancel={() => setSelectedEvent(null)}
        width={480}
      >
        {selectedEvent && (
          <div style={{ display: "grid", gap: 16 }}>
            <dl style={{ margin: 0, display: "grid", gap: 12 }}>
              <div>
                <dt style={{ color: "var(--up-muted)", fontSize: 13, fontWeight: 600 }}>事件 ID</dt>
                <dd style={{ margin: "4px 0 0", fontSize: 14 }}><code>{selectedEvent.eventId}</code></dd>
              </div>
              <div>
                <dt style={{ color: "var(--up-muted)", fontSize: 13, fontWeight: 600 }}>事件类型</dt>
                <dd style={{ margin: "4px 0 0", fontSize: 14 }}>{selectedEvent.eventType}</dd>
              </div>
              <div>
                <dt style={{ color: "var(--up-muted)", fontSize: 13, fontWeight: 600 }}>操作者</dt>
                <dd style={{ margin: "4px 0 0", fontSize: 14 }}>
                  {selectedEvent.actorName} · <code>{selectedEvent.actorId}</code>
                </dd>
              </div>
              <div>
                <dt style={{ color: "var(--up-muted)", fontSize: 13, fontWeight: 600 }}>目标</dt>
                <dd style={{ margin: "4px 0 0", fontSize: 14 }}>
                  {selectedEvent.targetLabel} · <code>{selectedEvent.targetId}</code>
                </dd>
              </div>
              <div>
                <dt style={{ color: "var(--up-muted)", fontSize: 13, fontWeight: 600 }}>结果</dt>
                <dd style={{ margin: "4px 0 0" }}>
                  <StatusBadge
                    label={selectedEvent.result === "success" ? "成功" : "已拒绝"}
                    tone={selectedEvent.result === "success" ? "success" : "danger"}
                  />
                </dd>
              </div>
              <div>
                <dt style={{ color: "var(--up-muted)", fontSize: 13, fontWeight: 600 }}>Request ID</dt>
                <dd style={{ margin: "4px 0 0", fontSize: 14 }}><code>{selectedEvent.requestId}</code></dd>
              </div>
              <div>
                <dt style={{ color: "var(--up-muted)", fontSize: 13, fontWeight: 600 }}>发生时间</dt>
                <dd style={{ margin: "4px 0 0", fontSize: 14 }}>{formatSecurityDateTime(selectedEvent.occurredAt)}</dd>
              </div>
              <div>
                <dt style={{ color: "var(--up-muted)", fontSize: 13, fontWeight: 600 }}>事件详情</dt>
                <dd style={{ margin: "4px 0 0", fontSize: 14, lineHeight: 1.6 }}>{selectedEvent.details}</dd>
              </div>
            </dl>
          </div>
        )}
      </SideSheet>
    </>
  );
}

function waitForPoll(signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(resolve, 1000);
    signal.addEventListener("abort", () => {
      window.clearTimeout(timeout);
      reject(new DOMException("Aborted", "AbortError"));
    }, { once: true });
  });
}
