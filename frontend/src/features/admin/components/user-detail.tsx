//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: User detail panel
//

"use client";

import { useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Empty, Modal, Popconfirm, Tabs, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import type { UserDetail } from "@/features/admin/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { AccountReauthenticationForm } from "@/features/account/components/security-overview";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./admin-detail.module.css";

type UserDetailProps = {
  detail: UserDetail;
  canManage?: boolean;
};

const VALID_TABS = ["profile", "sessions", "authorizations", "audit", "danger"] as const;
type TabKey = (typeof VALID_TABS)[number];

function isTabKey(value: string | null): value is TabKey {
  return value !== null && (VALID_TABS as readonly string[]).includes(value);
}

function personaLabel(personas: UserDetail["personas"]): string {
  return personas.map((p) => (p === "consumer" ? "外部用户" : "员工")).join(" · ");
}

export function UserDetail({ detail, canManage = false }: UserDetailProps) {
  const router = useRouter();
  const tabParam = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("tab") : null;
  const requestedTab: TabKey = isTabKey(tabParam) ? tabParam : "profile";
  const activeTab: TabKey = requestedTab === "danger" && !canManage ? "profile" : requestedTab;

  function handleTabChange(itemKey: string) {
    const params = new URLSearchParams(window.location.search);
    if (itemKey === "profile") {
      params.delete("tab");
    } else {
      params.set("tab", itemKey);
    }
    const queryString = params.toString();
    router.replace(`/admin/users/${detail.userId}${queryString ? `?${queryString}` : ""}`);
  }

  return (
    <>
      <Link href="/admin/users" className={styles.backLink}>
        ← 返回用户列表
      </Link>

      <PageHeader
        eyebrow="Identity"
        title={detail.displayName}
        description={`稳定标识：${detail.userId}`}
      />

      <div className={styles.headerCard}>
        <div className={styles.headerInfo}>
          <h1>{detail.displayName}</h1>
          <p>{detail.email} · {detail.phoneMasked}</p>
        </div>
        <div className={styles.headerMeta}>
          <span>人格：{personaLabel(detail.personas)}</span>
          <StatusBadge
            label={detail.status === "active" ? "正常" : detail.status === "pending" ? "待验证" : "已停用"}
            tone={detail.status === "active" ? "success" : detail.status === "pending" ? "warning" : "danger"}
          />
        </div>
      </div>

      <div className={styles.tabContent}>
        <Tabs type="line" activeKey={activeTab} onChange={handleTabChange}>
          <Tabs.TabPane tab="账户资料" itemKey="profile">
            <ProfileTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="活跃会话" itemKey="sessions">
            <SessionsTab detail={detail} canManage={canManage} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="授权应用" itemKey="authorizations">
            <AuthorizationsTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="审计记录" itemKey="audit">
            <AuditTab detail={detail} />
          </Tabs.TabPane>

          {canManage && (
            <Tabs.TabPane tab="危险操作" itemKey="danger">
              <DangerTab detail={detail} />
            </Tabs.TabPane>
          )}
        </Tabs>
      </div>
    </>
  );
}

function ProfileTab({ detail }: UserDetailProps) {
  return (
    <dl className={styles.descriptionList}>
      <dt>用户 ID</dt>
      <dd><code>{detail.userId}</code></dd>

      <dt>显示名称</dt>
      <dd>{detail.displayName}</dd>

      <dt>邮箱</dt>
      <dd>{detail.email}</dd>

      <dt>手机（脱敏）</dt>
      <dd>{detail.phoneMasked}</dd>

      <dt>人格类型</dt>
      <dd>{personaLabel(detail.personas)}</dd>

      <dt>员工档案</dt>
      <dd>
        {detail.employeeProfile ? (
          <>
            {detail.employeeProfile.employeeId} · {detail.employeeProfile.departmentName} · {detail.employeeProfile.title}
          </>
        ) : (
          "未关联员工档案"
        )}
      </dd>

      <dt>外部身份关联</dt>
      <dd>
        {detail.linkedIdentities.length > 0 ? (
          detail.linkedIdentities.map((identity) => (
            <div key={identity.providerId}>
              {identity.providerName}：{identity.externalSubject}（关联于 {formatSecurityDateTime(identity.linkedAt)}）
            </div>
          ))
        ) : (
          "无"
        )}
      </dd>

      <dt>最近活动</dt>
      <dd>{formatSecurityDateTime(detail.lastActiveAt)}</dd>
    </dl>
  );
}

function SessionsTab({ detail, canManage = false }: UserDetailProps) {
  const router = useRouter();
  const [revokingId, setRevokingId] = useState<string | null>(null);

  async function handleRevoke(sessionId: string): Promise<void> {
    setRevokingId(sessionId);
    try {
      await browserCommands.revokeUserSession(detail.userId, sessionId);
      Toast.success({ content: "会话已撤销。" });
      router.refresh();
    } catch {
      Toast.error({ content: "撤销会话失败，请稍后重试。" });
    } finally {
      setRevokingId(null);
    }
  }

  if (detail.activeSessions.length === 0) {
    return <Empty title="无活跃会话" description="该用户当前没有活跃的登录会话。" />;
  }

  return (
    <div className={styles.section}>
      {detail.activeSessions.map((session) => (
        <div key={session.sessionId} className={styles.dangerItem}>
          <div>
            <strong>{session.deviceName}</strong>
            <p>{formatSecurityDateTime(session.lastActiveAt)}</p>
            {session.isCurrent && <StatusBadge label="当前会话" tone="success" />}
          </div>
          {canManage && !session.isCurrent && (
            <Popconfirm
              title={`撤销 ${session.deviceName} 的会话？`}
              content="该设备上的登录会话将立即失效。"
              type="warning"
              onConfirm={() => handleRevoke(session.sessionId)}
              disabled={revokingId === session.sessionId}
            >
              <Button
                type="danger"
                theme="outline"
                loading={revokingId === session.sessionId}
                disabled={revokingId === session.sessionId}
              >
                撤销会话
              </Button>
            </Popconfirm>
          )}
        </div>
      ))}
    </div>
  );
}

function AuthorizationsTab({ detail }: UserDetailProps) {
  if (detail.authorizedApplications.length === 0) {
    return <Empty title="无授权应用" description="该用户尚未授权任何应用。" />;
  }

  return (
    <div className={styles.section}>
      {detail.authorizedApplications.map((app) => (
        <div key={app.applicationName} className={styles.dangerItem}>
          <div>
            <strong>{app.applicationName}</strong>
            <p>Scope：{app.scopes.join(", ")}</p>
            <p>授权时间：{formatSecurityDateTime(app.grantedAt)}</p>
            <StatusBadge
              label={app.status === "active" ? "有效" : "已撤销"}
              tone={app.status === "active" ? "success" : "danger"}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function AuditTab({ detail }: UserDetailProps) {
  if (detail.recentAuditEvents.length === 0) {
    return <Empty title="无审计记录" description="该用户最近没有审计事件。" />;
  }

  return (
    <dl className={styles.descriptionList}>
      {detail.recentAuditEvents.map((event) => (
        <div key={event.eventId} style={{ display: "contents" }}>
          <dt>事件</dt>
          <dd>{event.eventType}</dd>

          <dt>操作者</dt>
          <dd>{event.actorName}</dd>

          <dt>目标</dt>
          <dd>{event.targetLabel}</dd>

          <dt>时间</dt>
          <dd>{formatSecurityDateTime(event.occurredAt)}</dd>

          <dt>结果</dt>
          <dd>
            <StatusBadge
              label={event.result === "success" ? "成功" : "拒绝"}
              tone={event.result === "success" ? "success" : "danger"}
            />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function DangerTab({ detail }: UserDetailProps) {
  const router = useRouter();
  const [toggling, setToggling] = useState(false);
  const [revokingSessions, setRevokingSessions] = useState(false);
  const [reauthAction, setReauthAction] = useState<"disable" | "sessions" | null>(null);
  const browserOperation = useRef<AbortController | null>(null);

  const isActive = detail.status === "active";

  async function handleToggleStatus(): Promise<void> {
    if (isActive) {
      setReauthAction("disable");
      return;
    }
    Modal.info({
      title: "启用此用户？",
      content: "恢复后用户可重新登录。已有授权保持原状态。",
      okText: "确认启用",
      cancelText: "取消",
      onOk: async () => {
      setToggling(true);
      try {
          await browserCommands.updateUserStatus(detail.userId, "active");
          Toast.success({ content: "用户已启用。" });
        router.refresh();
      } catch {
        Toast.error({ content: "操作失败，请重试。" });
        throw new Error("status change failed");
      } finally {
        setToggling(false);
      }
      },
    });
  }

  function closeReauthentication(): void {
    browserOperation.current?.abort();
    browserOperation.current = null;
    setReauthAction(null);
  }

  async function runHighRiskOperation(reauthToken: string, signal: AbortSignal): Promise<void> {
    if (reauthAction === "disable") {
      setToggling(true);
      try {
        await browserCommands.updateUserStatus(
          detail.userId,
          "disabled",
          reauthToken,
          { signal },
        );
        Toast.success({ content: "用户已停用，关联会话撤销已启动。" });
      } finally {
        setToggling(false);
      }
    } else if (reauthAction === "sessions") {
      setRevokingSessions(true);
      try {
        await browserCommands.revokeUserSessions(detail.userId, reauthToken, { signal });
        Toast.success({ content: "已撤销该用户的所有会话。" });
      } finally {
        setRevokingSessions(false);
      }
    }
    setReauthAction(null);
    router.refresh();
  }

  return (
    <div className={styles.dangerZone}>
      <div className={`${styles.notice} ${styles.noticeDanger}`}>
        <div>
          <strong>危险操作</strong>
          以下操作会影响该用户的登录和会话。后端将强制执行并记录审计事件。
        </div>
      </div>

      <div className={styles.dangerItem}>
        <div>
          <strong>{isActive ? "停用用户" : "启用用户"}</strong>
          <p>
            {isActive
              ? "停用后用户将无法登录，并启动已有会话撤销；OAuth 授权记录保持不变。"
              : "恢复后用户可重新登录。"}
          </p>
        </div>
        <Button
          theme="solid"
          type={isActive ? "danger" : "primary"}
          loading={toggling}
          onClick={handleToggleStatus}
        >
          {isActive ? "停用用户" : "启用用户"}
        </Button>
      </div>

      <div className={styles.dangerItem}>
        <div>
          <strong>撤销所有会话</strong>
          <p>立即撤销该用户在所有设备上的登录会话。用户需要重新登录。</p>
        </div>
        <Button
          type="danger"
          theme="solid"
          loading={revokingSessions}
          disabled={revokingSessions}
          onClick={() => setReauthAction("sessions")}
        >
          撤销所有会话
        </Button>
      </div>

      <Modal
        title={reauthAction === "disable" ? "重新认证并停用用户" : "重新认证并撤销所有会话"}
        visible={reauthAction !== null}
        footer={null}
        onCancel={closeReauthentication}
        closeOnEsc={!toggling && !revokingSessions}
        maskClosable={false}
      >
        <p>
          本次授权仅绑定到用户 <strong>{detail.displayName}</strong>（{detail.userId}），
          且只能使用一次。
        </p>
        {reauthAction !== null && (
          <AccountReauthenticationForm
            action={reauthAction === "disable" ? "user.disable" : "user.sessions.revoke"}
            target={detail.userId}
            submitLabel={reauthAction === "disable" ? "验证并停用" : "验证并撤销"}
            browserOperationRef={browserOperation}
            onGranted={runHighRiskOperation}
            onCancel={closeReauthentication}
            operationError="操作未完成；此次单次授权不会被重复使用，请重新验证后再试。"
            destructive
          />
        )}
      </Modal>
    </div>
  );
}
