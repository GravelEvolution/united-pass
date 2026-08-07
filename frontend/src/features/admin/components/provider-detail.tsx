//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Identity provider detail panel
//

"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import type { ProviderDetail, DirectorySyncResult, SyncConflict, DirectorySyncHistoryEntry, ManagedUser } from "@/features/admin/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./admin-detail.module.css";

type ProviderDetailProps = {
  detail: ProviderDetail;
  syncHistory: DirectorySyncHistoryEntry[];
  conflicts: SyncConflict[];
  users: ManagedUser[];
};

export function ProviderDetail({ detail, syncHistory, conflicts, users }: ProviderDetailProps) {
  const router = useRouter();
  const [syncing, setSyncing] = useState(false);
  const [lastSync, setLastSync] = useState<DirectorySyncResult | null>(detail.lastSyncResult);

  async function handleSync(): Promise<void> {
    setSyncing(true);
    try {
      const result = await browserCommands.syncProviderDirectory(detail.providerId);
      setLastSync(result);
      Toast.success({ content: "同步完成。" });
      router.refresh();
    } catch {
      Toast.error({ content: "同步失败，请重试。" });
    } finally {
      setSyncing(false);
    }
  }

  return (
    <>
      <Link href="/admin/providers" className={styles.backLink}>
        ← 返回 Provider 列表
      </Link>

      <PageHeader
        eyebrow="Identity Provider"
        title={detail.displayName}
        description={`Provider ID：${detail.providerId}`}
      />

      <div className={styles.headerCard}>
        <div className={styles.headerInfo}>
          <h1>{detail.displayName}</h1>
          <p>厂商：{detail.vendor === "feishu" ? "飞书" : "通用"} · {detail.contactScope}</p>
        </div>
        <div className={styles.headerMeta}>
          <StatusBadge
            label={detail.status === "active" ? "正常" : detail.status === "planned" ? "规划中" : "已停用"}
            tone={detail.status === "active" ? "success" : detail.status === "planned" ? "warning" : "danger"}
          />
          <StatusBadge
            label={detail.loginEnabled ? "登录已启用" : "登录未启用"}
            tone={detail.loginEnabled ? "success" : "neutral"}
          />
        </div>
      </div>

      <div className={styles.tabContent}>
        <dl className={styles.descriptionList}>
          <dt>App ID</dt>
          <dd><code>{detail.appId}</code></dd>

          <dt>Secret</dt>
          <dd>
            {detail.secretConfigured ? (
              "已配置（不显示明文）"
            ) : (
              "未配置"
            )}
          </dd>

          <dt>OAuth 回调地址</dt>
          <dd><code>{detail.callbackUrl}</code></dd>

          <dt>通讯录授权范围</dt>
          <dd>{detail.contactScope}</dd>

          <dt>已关联用户</dt>
          <dd>{detail.linkedUserCount} 人</dd>

          <dt>最近同步</dt>
          <dd>
            {detail.lastSyncAt ? formatSecurityDateTime(detail.lastSyncAt) : "从未同步"}
          </dd>
        </dl>

        <div className={`${styles.notice} ${styles.noticeInfo}`} style={{ marginTop: 20 }}>
          <div>
            <strong>安全提醒</strong>
            飞书 App Secret、Access Token 和签名材料仅在服务端存储和使用，不会暴露到浏览器。
            授权重定向、回调验证、Code 交换和重放保护均由后端执行。
            外部身份通过显式流程关联到既有 userId，不会仅凭邮箱静默合并。
          </div>
        </div>

        <div style={{ marginTop: 20 }}>
          <Button
            theme="solid"
            type="primary"
            loading={syncing}
            disabled={syncing}
            onClick={handleSync}
          >
            立即同步
          </Button>
        </div>

        {lastSync && (
          <div style={{ marginTop: 24 }}>
            <h3 style={{ margin: "0 0 12px", fontSize: 14, color: "var(--up-ink-secondary)" }}>最近同步结果</h3>
            <dl className={styles.descriptionList}>
              <dt>同步 ID</dt>
              <dd><code>{lastSync.syncId}</code></dd>

              <dt>开始时间</dt>
              <dd>{formatSecurityDateTime(lastSync.startedAt)}</dd>

              <dt>完成时间</dt>
              <dd>{formatSecurityDateTime(lastSync.completedAt)}</dd>

              <dt>状态</dt>
              <dd>
                <StatusBadge
                  label={lastSync.status === "success" ? "成功" : lastSync.status === "partial" ? "部分成功" : "失败"}
                  tone={lastSync.status === "success" ? "success" : lastSync.status === "partial" ? "warning" : "danger"}
                />
              </dd>

              <dt>部门变更</dt>
              <dd>新增 {lastSync.departmentsAdded} · 更新 {lastSync.departmentsUpdated}</dd>

              <dt>员工变更</dt>
              <dd>新增 {lastSync.employeesAdded} · 更新 {lastSync.employeesUpdated} · 离职 {lastSync.employeesOffboarded}</dd>

              <dt>冲突</dt>
              <dd>{lastSync.conflictsDetected} 个待处理</dd>
            </dl>
          </div>
        )}
      </div>

      {conflicts.length > 0 && (
        <div className={styles.tabContent} style={{ marginTop: 24 }}>
          <h3 style={{ margin: "0 0 16px", fontSize: 14, color: "var(--up-ink-secondary)" }}>身份关联冲突</h3>
          <div className={`${styles.notice} ${styles.noticeDanger}`} style={{ marginBottom: 16 }}>
            <div>
              <strong>不允许仅凭邮箱静默合并</strong>
              以下冲突需手动确认。仅凭邮箱、手机号、域名或显示名的匹配不构成自动合并。
              必须由管理员显式选择关联到既有的 United Pass 用户，或忽略。
            </div>
          </div>

          {conflicts.map((conflict) => (
            <ConflictRow key={conflict.conflictId} conflict={conflict} users={users} />
          ))}
        </div>
      )}

      {syncHistory.length > 0 && (
        <div className={styles.tabContent} style={{ marginTop: 24 }}>
          <h3 style={{ margin: "0 0 16px", fontSize: 14, color: "var(--up-ink-secondary)" }}>同步历史</h3>
          {syncHistory.map((entry) => (
            <div key={entry.syncId} className={styles.dangerItem}>
              <div>
                <strong>{entry.summary}</strong>
                <p>{formatSecurityDateTime(entry.startedAt)} → {formatSecurityDateTime(entry.completedAt)}</p>
                <StatusBadge
                  label={entry.status === "success" ? "成功" : entry.status === "partial" ? "部分成功" : "失败"}
                  tone={entry.status === "success" ? "success" : entry.status === "partial" ? "warning" : "danger"}
                />
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: 24 }}>
        <Link href="/admin/directory">
          <Button theme="borderless">查看目录同步总览</Button>
        </Link>
      </div>
    </>
  );
}

function ConflictRow({ conflict, users }: { conflict: SyncConflict; users: ManagedUser[] }) {
  const [resolving, setResolving] = useState(false);
  const [selectedUserId, setSelectedUserId] = useState("");
  const [status, setStatus] = useState(conflict.status);

  async function handleResolve(): Promise<void> {
    if (!selectedUserId) {
      Toast.warning({ content: "请选择要关联的用户。" });
      return;
    }
    setResolving(true);
    try {
      await browserCommands.resolveSyncConflict(conflict.conflictId, selectedUserId);
      setStatus("resolved");
      Toast.success({ content: "冲突已解决，外部身份已关联到指定用户。" });
    } catch {
      Toast.error({ content: "操作失败，请重试。" });
    } finally {
      setResolving(false);
    }
  }

  async function handleIgnore(): Promise<void> {
    setResolving(true);
    try {
      await browserCommands.ignoreSyncConflict(conflict.conflictId);
      setStatus("ignored");
      Toast.success({ content: "冲突已忽略。" });
    } catch {
      Toast.error({ content: "操作失败，请重试。" });
    } finally {
      setResolving(false);
    }
  }

  if (status !== "pending") {
    return (
      <div className={styles.dangerItem}>
        <div>
          <strong>{conflict.externalName} · {conflict.externalEmail}</strong>
          <p>匹配原因：{conflict.matchReason === "email" ? "邮箱" : conflict.matchReason === "name" ? "姓名" : "手动"}</p>
          <StatusBadge
            label={status === "resolved" ? "已解决" : "已忽略"}
            tone={status === "resolved" ? "success" : "neutral"}
          />
        </div>
      </div>
    );
  }

  return (
    <div className={styles.dangerItem} style={{ flexDirection: "column", alignItems: "stretch" }}>
      <div style={{ width: "100%" }}>
        <strong>{conflict.externalName} · {conflict.externalEmail}</strong>
        <p>飞书 Subject：{conflict.externalSubject}</p>
        <p>匹配原因：{conflict.matchReason === "email" ? "邮箱匹配" : conflict.matchReason === "name" ? "姓名匹配" : "手动"}</p>
        {conflict.matchedUserName && <p>疑似匹配：{conflict.matchedUserName}（{conflict.matchedUserId}）</p>}
        <p>检测时间：{formatSecurityDateTime(conflict.detectedAt)}</p>
      </div>

      <div style={{ width: "100%", display: "grid", gap: 8, marginTop: 12 }}>
        <select
          value={selectedUserId}
          onChange={(e) => setSelectedUserId(e.target.value)}
          className="semi-input semi-input-default"
          style={{ width: "100%" }}
          aria-label="选择关联用户"
        >
          <option value="">选择要关联的 United Pass 用户</option>
          {users.map((user) => (
            <option key={user.userId} value={user.userId}>
              {user.displayName} · {user.email} · {user.userId}
            </option>
          ))}
        </select>
        <div style={{ display: "flex", gap: 8 }}>
          <Button
            theme="solid"
            type="primary"
            size="small"
            loading={resolving}
            disabled={resolving}
            onClick={handleResolve}
          >
            确认关联
          </Button>
          <Button
            theme="borderless"
            type="danger"
            size="small"
            loading={resolving}
            disabled={resolving}
            onClick={handleIgnore}
          >
            忽略
          </Button>
        </div>
      </div>
    </div>
  );
}
