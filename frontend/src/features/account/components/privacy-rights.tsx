//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Phase 8 personal-data export and delayed account-deletion controls
//

"use client";

import { useEffect, useRef, useState } from "react";
import { Banner, Button, Modal, Toast } from "@douyinfe/semi-ui";
import { IconDelete, IconDownload } from "@douyinfe/semi-icons";
import type { AccountDeletion, PersonalDataExport } from "@/features/account/types";
import { AccountReauthenticationForm } from "@/features/account/components/security-overview";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./privacy-rights.module.css";

type UserBoundProps = { userId: string };

export function PersonalDataExportPanel({ userId }: UserBoundProps) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [result, setResult] = useState<PersonalDataExport | null>(null);
  const operation = useRef<AbortController | null>(null);

  useEffect(() => () => operation.current?.abort(), []);

  function closeDialog(): void {
    operation.current?.abort();
    operation.current = null;
    setDialogOpen(false);
  }

  async function requestExport(reauthToken: string, signal: AbortSignal): Promise<void> {
    let next = await browserCommands.requestPersonalDataExport(reauthToken, { signal });
    setResult(next);
    setDialogOpen(false);
    for (
      let attempt = 0;
      attempt < 30 && (next.status === "pending" || next.status === "processing");
      attempt += 1
    ) {
      await waitForPoll(signal);
      next = await browserCommands.getPersonalDataExport(next.exportId, { signal });
      setResult(next);
    }
    if (next.status === "failed") throw new Error("personal data export failed");
    if (next.status === "completed") {
      Toast.success({ content: "个人数据副本已生成，下载链接将在 15 分钟后失效。" });
    } else {
      Toast.info({ content: "导出仍在后台处理中，请稍后重新打开此页面查看。" });
    }
  }

  return (
    <>
      <section className={styles.card}>
        <div>
          <p className={styles.eyebrow}>Personal data</p>
          <h2>获取个人数据副本</h2>
          <p className={styles.description}>
            导出账户资料、身份关联、员工档案和应用授权。导出文件不包含密码、令牌或密钥。
          </p>
        </div>
        <Button type="primary" theme="solid" icon={<IconDownload />} onClick={() => setDialogOpen(true)}>
          申请导出
        </Button>
      </section>

      {result && (
        <section className={styles.statusCard} aria-live="polite">
          <h2>最近一次导出</h2>
          <dl className={styles.details}>
            <div><dt>状态</dt><dd>{exportStatusLabel(result.status)}</dd></div>
            <div><dt>申请时间</dt><dd>{formatSecurityDateTime(result.requestedAt)}</dd></div>
            <div><dt>数据分区</dt><dd>{result.totalSections}</dd></div>
            {result.expiresAt && <div><dt>链接失效</dt><dd>{formatSecurityDateTime(result.expiresAt)}</dd></div>}
          </dl>
          {result.downloadUrl ? (
            <a className={styles.downloadLink} href={result.downloadUrl} download>
              下载 JSON 数据副本
            </a>
          ) : result.status === "completed" ? (
            <p className={styles.muted}>
              {USE_MOCK_DATA_SOURCE
                ? "开发数据模式不会生成真实文件。"
                : "下载链接已失效或暂不可用，请重新申请数据副本。"}
            </p>
          ) : null}
        </section>
      )}

      <Modal
        title="验证身份并申请数据导出"
        visible={dialogOpen}
        footer={null}
        maskClosable={false}
        closeOnEsc={false}
        onCancel={closeDialog}
      >
        <p className={styles.modalCopy}>为防止他人获取你的个人数据，需要重新验证当前账户。</p>
        <AccountReauthenticationForm
          action="account.data_export"
          target={userId}
          submitLabel="验证并申请"
          browserOperationRef={operation}
          onGranted={requestExport}
          onCancel={closeDialog}
          operationError="数据导出申请失败。授权不会被重复使用，请重新验证后再试。"
        />
      </Modal>
    </>
  );
}

type AccountDeletionPanelProps = UserBoundProps & { initialDeletion: AccountDeletion };

export function AccountDeletionPanel({ userId, initialDeletion }: AccountDeletionPanelProps) {
  const [deletion, setDeletion] = useState(initialDeletion);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const operation = useRef<AbortController | null>(null);

  useEffect(() => () => operation.current?.abort(), []);

  function closeDialog(): void {
    operation.current?.abort();
    operation.current = null;
    setDialogOpen(false);
  }

  async function requestDeletion(reauthToken: string, signal: AbortSignal): Promise<void> {
    const next = await browserCommands.requestAccountDeletion(reauthToken, { signal });
    setDeletion(next);
    setDialogOpen(false);
    Toast.success({ content: "注销申请已提交。冷静期内可随时取消。" });
  }

  async function cancelDeletion(): Promise<void> {
    setCancelling(true);
    try {
      const next = await browserCommands.cancelAccountDeletion();
      setDeletion(next);
      Toast.success({ content: "注销申请已取消，账户不会被删除。" });
    } catch {
      Toast.error({ content: "无法取消注销申请。申请可能已进入执行阶段，请刷新后确认。" });
    } finally {
      setCancelling(false);
    }
  }

  const mayRequest = deletion.status === "none" || deletion.status === "cancelled" || deletion.status === "failed";
  // The backend is authoritative for the exact cooling-period deadline and
  // rejects a cancellation that races with the worker claim.
  const mayCancel = deletion.status === "pending";

  return (
    <>
      <Banner
        type="warning"
        fullMode={false}
        bordered
        closeIcon={null}
        description="注销不是即时操作：提交后有 30 天冷静期。到期后系统会删除身份提供商账户、撤销会话与授权，并匿名化本地个人信息。审计记录仅保留必要的操作证明。"
      />
      <section className={`${styles.card} ${styles.dangerCard}`}>
        <div>
          <p className={styles.eyebrow}>Account deletion</p>
          <h2>永久注销账户</h2>
          <p className={styles.description}>执行完成后无法恢复账户、员工档案、身份关联或应用授权。</p>
        </div>
        {mayRequest && (
          <Button type="danger" theme="solid" icon={<IconDelete />} onClick={() => setDialogOpen(true)}>
            申请注销
          </Button>
        )}
      </section>

      {deletion.status !== "none" && (
        <section className={styles.statusCard} aria-live="polite">
          <h2>注销申请状态</h2>
          <dl className={styles.details}>
            <div><dt>状态</dt><dd>{deletionStatusLabel(deletion.status)}</dd></div>
            <div><dt>申请时间</dt><dd>{formatSecurityDateTime(deletion.requestedAt)}</dd></div>
            <div><dt>计划执行</dt><dd>{formatSecurityDateTime(deletion.executeAfter)}</dd></div>
          </dl>
          {mayCancel && (
            <Button theme="outline" loading={cancelling} disabled={cancelling} onClick={cancelDeletion}>
              取消注销申请
            </Button>
          )}
          {(deletion.status === "processing" || deletion.status === "provider_deleted") && (
            <p className={styles.muted}>注销已进入执行阶段，无法再取消。系统会以可重试状态机完成清理。</p>
          )}
        </section>
      )}

      <Modal
        title="确认申请注销账户"
        visible={dialogOpen}
        footer={null}
        maskClosable={false}
        closeOnEsc={false}
        onCancel={closeDialog}
      >
        <Banner
          type="danger"
          fullMode={false}
          bordered
          closeIcon={null}
          description="继续后将启动 30 天冷静期。冷静期结束且未取消时，账户删除不可恢复。"
        />
        <div className={styles.reauthBlock}>
          <AccountReauthenticationForm
            action="account.delete"
            target={userId}
            submitLabel="验证并申请注销"
            browserOperationRef={operation}
            onGranted={requestDeletion}
            onCancel={closeDialog}
            operationError="注销申请失败。授权不会被重复使用，请重新验证后再试。"
            destructive
          />
        </div>
      </Modal>
    </>
  );
}

function exportStatusLabel(status: PersonalDataExport["status"]): string {
  return { pending: "等待处理", processing: "生成中", completed: "已完成", failed: "失败" }[status];
}

function deletionStatusLabel(status: Exclude<AccountDeletion["status"], "none">): string {
  return {
    pending: "冷静期中",
    processing: "正在删除身份账户",
    provider_deleted: "正在清理本地数据",
    completed: "已完成",
    cancelled: "已取消",
    failed: "需要重试",
  }[status];
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
