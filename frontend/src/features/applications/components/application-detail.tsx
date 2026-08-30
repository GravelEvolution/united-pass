//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Application detail panel
//

"use client";

import type { FormEvent } from "react";
import { useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Button, Empty, Input, Modal, Select, Tabs, TextArea, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import {
  AUDIENCE_LABELS,
  type AllowedScope,
  type ApplicationAudience,
  type OAuthApplicationDetail,
} from "@/features/applications/types";
import { validateApplicationCreateInput } from "@/features/applications/validation";
import { OAuthClientEditor } from "@/features/applications/components/oauth-client-editor";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { AccountReauthenticationForm } from "@/features/account/components/security-overview";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./application-detail.module.css";
import formStyles from "./application-create-form.module.css";

type ApplicationDetailProps = {
  detail: OAuthApplicationDetail;
  availableScopes: AllowedScope[];
  canManage: boolean;
};

const VALID_TABS = ["basic", "clients", "grants", "audit", "danger"] as const;
type TabKey = (typeof VALID_TABS)[number];

function isTabKey(value: string | null): value is TabKey {
  return value !== null && (VALID_TABS as readonly string[]).includes(value);
}

export function ApplicationDetail({ detail, availableScopes, canManage }: ApplicationDetailProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const tabParam = searchParams.get("tab");
  const activeTab: TabKey = isTabKey(tabParam) ? tabParam : "basic";

  function handleTabChange(itemKey: string) {
    const params = new URLSearchParams(searchParams.toString());
    if (itemKey === "basic") {
      params.delete("tab");
    } else {
      params.set("tab", itemKey);
    }
    const queryString = params.toString();
    router.replace(`/admin/applications/${detail.applicationId}${queryString ? `?${queryString}` : ""}`);
  }

  return (
    <>
      <Link href="/admin/applications" className={styles.backLink}>
        ← 返回应用列表
      </Link>

      <PageHeader
        eyebrow="OAuth 2.0 / OIDC"
        title={detail.name}
        description={detail.description}
      />

      <div className={styles.headerCard}>
        <div className={styles.headerInfo}>
          <h1>{detail.name}</h1>
          <p>{detail.description}</p>
        </div>
        <div className={styles.headerMeta}>
          <span>受众: {AUDIENCE_LABELS[detail.audience]}</span>
          <StatusBadge
            label={detail.status === "active" ? "正常" : "已停用"}
            tone={detail.status === "active" ? "success" : "danger"}
          />
        </div>
      </div>

      <div className={styles.tabContent}>
        <Tabs type="line" activeKey={activeTab} onChange={handleTabChange}>
          <Tabs.TabPane tab="基本信息" itemKey="basic">
            <BasicInfoTab detail={detail} canManage={canManage} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="OAuth Clients" itemKey="clients">
            <ClientsTab detail={detail} availableScopes={availableScopes} canManage={canManage} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="授权记录" itemKey="grants">
            <GrantsTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="审计日志" itemKey="audit">
            <AuditTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="危险操作" itemKey="danger">
            <DangerTab detail={detail} canManage={canManage} />
          </Tabs.TabPane>
        </Tabs>
      </div>
    </>
  );
}

function BasicInfoTab({ detail, canManage }: { detail: OAuthApplicationDetail; canManage: boolean }) {
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [name, setName] = useState(detail.name);
  const [description, setDescription] = useState(detail.description);
  const [audience, setAudience] = useState<ApplicationAudience>(detail.audience);
  const [ownerId, setOwnerId] = useState(detail.ownerId);
  const [formError, setFormError] = useState<string>();

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setFormError(undefined);
    const input = {
      name: name.trim(),
      description: description.trim(),
      audience,
      ownerId: ownerId.trim(),
    };
    try {
      validateApplicationCreateInput(input);
      if (input.description.length > 500) throw new Error("应用说明不能超过 500 个字符。");
      setSubmitting(true);
      await browserCommands.updateApplication(detail.applicationId, input);
      Toast.success({ content: "应用基本信息已更新。" });
      setEditing(false);
      router.refresh();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "更新应用失败，请重试。");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className={styles.section}>
      {canManage && <Button theme="outline" onClick={() => setEditing(true)}>编辑基本信息</Button>}
      <dl className={styles.descriptionList}>
        <dt>应用名称</dt><dd>{detail.name}</dd>
        <dt>应用说明</dt><dd>{detail.description || "—"}</dd>
        <dt>受众</dt><dd>{AUDIENCE_LABELS[detail.audience]}</dd>
        <dt>负责人</dt><dd>{detail.ownerName}</dd>
        <dt>状态</dt>
        <dd><StatusBadge label={detail.status === "active" ? "正常" : "已停用"} tone={detail.status === "active" ? "success" : "danger"} /></dd>
        <dt>创建时间</dt><dd>{formatSecurityDateTime(detail.createdAt)}</dd>
        <dt>更新时间</dt><dd>{formatSecurityDateTime(detail.updatedAt)}</dd>
      </dl>
      <Modal title="编辑应用基本信息" visible={editing} footer={null} maskClosable={false} onCancel={() => setEditing(false)}>
        <form className={formStyles.form} onSubmit={(event) => void save(event)}>
          <label className={formStyles.fieldGroup}>
            <span className={formStyles.fieldLabel}>应用名称</span>
            <Input value={name} onChange={setName} minLength={2} maxLength={80} required />
          </label>
          <label className={formStyles.fieldGroup}>
            <span className={formStyles.fieldLabel}>应用说明</span>
            <TextArea value={description} onChange={setDescription} maxCount={500} autosize />
          </label>
          <label className={formStyles.fieldGroup}>
            <span className={formStyles.fieldLabel}>受众</span>
            <Select value={audience} onChange={(value) => {
              if (value === "internal" || value === "external" || value === "hybrid") setAudience(value);
            }}>
              {(Object.keys(AUDIENCE_LABELS) as ApplicationAudience[]).map((value) => (
                <Select.Option key={value} value={value}>{AUDIENCE_LABELS[value]}</Select.Option>
              ))}
            </Select>
          </label>
          <label className={formStyles.fieldGroup}>
            <span className={formStyles.fieldLabel}>负责人 User ID</span>
            <Input value={ownerId} onChange={setOwnerId} required />
          </label>
          {formError && <div className={`${formStyles.notice} ${formStyles.noticeDanger}`} role="alert">{formError}</div>}
          <div className={formStyles.actions}>
            <Button htmlType="submit" type="primary" theme="solid" loading={submitting}>保存</Button>
            <Button theme="outline" onClick={() => setEditing(false)} disabled={submitting}>取消</Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

function ClientsTab({
  detail,
  availableScopes,
  canManage,
}: { detail: OAuthApplicationDetail; availableScopes: AllowedScope[]; canManage: boolean }) {
  const router = useRouter();
  const [creating, setCreating] = useState(false);

  const createAction = canManage ? (
    <Button
      type="primary"
      theme="solid"
      disabled={detail.status !== "active"}
      onClick={() => setCreating(true)}
    >
      新增 OAuth Client
    </Button>
  ) : null;

  const editor = (
    <Modal title="新增 OAuth Client" visible={creating} footer={null} width={680} maskClosable={false} onCancel={() => setCreating(false)}>
      {creating && (
        <OAuthClientEditor
          applicationId={detail.applicationId}
          applicationAudience={detail.audience}
          availableScopes={availableScopes}
          onCancel={() => setCreating(false)}
          onDone={(clientId) => {
            setCreating(false);
            router.push(`/admin/applications/${detail.applicationId}/clients/${clientId}`);
            router.refresh();
          }}
        />
      )}
    </Modal>
  );

  if (detail.clients.length === 0) {
    return (
      <div className={styles.section}>
        {createAction}
        <Empty title="暂无 OAuth Client" description="此应用尚未配置任何 OAuth Client。" />
        {editor}
      </div>
    );
  }

  return (
    <div className={styles.section}>
      {createAction}
      {detail.clients.map((client) => (
        <Link
          key={client.clientId}
          href={`/admin/applications/${detail.applicationId}/clients/${client.clientId}`}
          className={styles.clientSummaryCard}
        >
          <div className={styles.headerMeta}>
            <h3>{client.name}</h3>
            <span>
              Client ID: <code>{client.clientId}</code>
            </span>
            <StatusBadge
              label={client.status === "active" ? "正常" : "已停用"}
              tone={client.status === "active" ? "success" : "danger"}
            />
          </div>
          <div className={styles.clientSummaryMeta}>
            <span>{client.clientType === "public" ? "公共客户端（PKCE）" : "机密客户端"}</span>
            <span>·</span>
            <span>{client.grantTypes.join(", ")}</span>
            <span>·</span>
            <span>{client.tokenEndpointAuthMethod}</span>
            <span>·</span>
            <span>{client.redirectUris.length} 个 Redirect URI</span>
          </div>
        </Link>
      ))}
      {editor}
    </div>
  );
}

function GrantsTab({ detail }: { detail: OAuthApplicationDetail }) {
  if (detail.grants.length === 0) {
    return <Empty title="暂无授权记录" description="用户授权此应用后将显示在此处。" />;
  }

  return (
    <dl className={styles.descriptionList}>
      {detail.grants.map((grant) => (
        <div key={grant.grantId} style={{ display: "contents" }}>
          <dt>用户</dt>
          <dd>{grant.userLabel}</dd>

          <dt>已授权 Scope</dt>
          <dd>{grant.scopes.join(", ")}</dd>

          <dt>授权时间</dt>
          <dd>{formatSecurityDateTime(grant.grantedAt)}</dd>

          <dt>最近使用</dt>
          <dd>{grant.lastUsedAt ? formatSecurityDateTime(grant.lastUsedAt) : "从未使用"}</dd>

          <dt>状态</dt>
          <dd>
            <StatusBadge
              label={grant.status === "active" ? "有效" : "已撤销"}
              tone={grant.status === "active" ? "success" : "danger"}
            />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function AuditTab({ detail }: { detail: OAuthApplicationDetail }) {
  if (detail.auditEntries.length === 0) {
    return <Empty title="暂无审计记录" />;
  }

  return (
    <dl className={styles.descriptionList}>
      {detail.auditEntries.map((entry) => (
        <div key={entry.eventId} style={{ display: "contents" }}>
          <dt>事件</dt>
          <dd>{entry.eventType}</dd>

          <dt>操作者</dt>
          <dd>{entry.actorName}</dd>

          <dt>时间</dt>
          <dd>{formatSecurityDateTime(entry.occurredAt)}</dd>

          <dt>结果</dt>
          <dd>
            <StatusBadge
              label={entry.result === "success" ? "成功" : "拒绝"}
              tone={entry.result === "success" ? "success" : "danger"}
            />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function DangerTab({ detail, canManage }: { detail: OAuthApplicationDetail; canManage: boolean }) {
  const router = useRouter();
  const isActive = detail.status === "active";
  const [toggling, setToggling] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteReauthenticationVisible, setDeleteReauthenticationVisible] = useState(false);
  const [confirmDeleteName, setConfirmDeleteName] = useState("");
  const browserOperation = useRef<AbortController | null>(null);

  if (!canManage) {
    return <div className={`${styles.notice} ${styles.noticeInfo}`}>你只有应用查看权限，无法执行管理操作。</div>;
  }

  function handleToggleStatus() {
    const warningContent = (
      <div>
        {isActive ? (
          <>
            <p>停用 <strong>{detail.name}</strong> 后：</p>
            <ul>
              <li>用户将无法发起新的授权请求</li>
              <li>已有授权不会立即失效，但仍受后端策略控制</li>
              <li>已签发的 Access Token 在过期前仍然有效</li>
              <li>Refresh Token 的续签将被阻止</li>
            </ul>
          </>
        ) : (
          <p>恢复后用户可重新发起新的授权请求。已过期的授权不会自动恢复。</p>
        )}
      </div>
    );

    const onOk = async () => {
      setToggling(true);
      try {
        await browserCommands.updateApplicationStatus(
          detail.applicationId,
          isActive ? "disabled" : "active",
        );
        Toast.success({ content: isActive ? "应用已停用。" : "应用已启用。" });
        router.refresh();
      } catch {
        Toast.error({ content: "操作失败，请重试。" });
        throw new Error("status change failed");
      } finally {
        setToggling(false);
      }
    };

    if (isActive) {
      Modal.warning({
        title: "停用此应用？",
        content: warningContent,
        okText: "确认停用",
        cancelText: "取消",
        okType: "danger",
        onOk,
      });
    } else {
      Modal.info({
        title: "启用此应用？",
        content: warningContent,
        okText: "确认启用",
        cancelText: "取消",
        onOk,
      });
    }
  }

  async function handleDeleteApplication(
    reauthToken: string,
    signal: AbortSignal,
  ): Promise<void> {
    setDeleting(true);
    try {
      await browserCommands.deleteApplication(
        detail.applicationId,
        reauthToken,
        { signal },
      );
      Toast.success({ content: "应用已删除。" });
      setDeleteReauthenticationVisible(false);
      router.push("/admin/applications");
    } finally {
      setDeleting(false);
    }
  }

  function closeDeleteReauthentication(): void {
    browserOperation.current?.abort();
    browserOperation.current = null;
    setDeleteReauthenticationVisible(false);
  }

  return (
    <div className={styles.dangerZone}>
      <div className={`${styles.notice} ${styles.noticeDanger}`}>
        <div>
          <strong>危险操作</strong>
          以下操作会影响此应用的所有用户授权和登录流程，且不可在前端撤销。后端将强制执行并记录审计事件。
        </div>
      </div>

      <div className={styles.dangerItem}>
        <div>
          <strong>{isActive ? "停用应用" : "启用应用"}</strong>
          <p>
            {isActive
              ? "停用后用户将无法发起新的授权请求，已有授权不会立即失效。"
              : "恢复后用户可重新发起新的授权请求。"}
          </p>
        </div>
        <Button
          theme="solid"
          type={isActive ? "danger" : "primary"}
          loading={toggling}
          onClick={handleToggleStatus}
        >
          {isActive ? "停用应用" : "启用应用"}
        </Button>
      </div>

      <div className={styles.dangerItem}>
        <div>
          <strong>删除应用</strong>
          <p>删除后所有 Client、Secret、授权记录将被永久清除。审计日志将按合规策略保留。此操作不可逆。</p>
          <p style={{ marginTop: 8 }}>
            <label>
              请输入应用名称 <code>{detail.name}</code> 以确认：
              <input
                type="text"
                value={confirmDeleteName}
                onChange={(e) => setConfirmDeleteName(e.target.value)}
                placeholder={detail.name}
                style={{
                  display: "block",
                  marginTop: 4,
                  padding: "6px 10px",
                  border: "1px solid var(--semi-color-border)",
                  borderRadius: 4,
                  background: "var(--semi-color-bg-1)",
                  color: "var(--semi-color-text-0)",
                  width: "100%",
                  maxWidth: 320,
                }}
              />
            </label>
          </p>
        </div>
        <Button
          theme="solid"
          type="danger"
          loading={deleting}
          disabled={confirmDeleteName !== detail.name}
          onClick={() => {
            if (confirmDeleteName !== detail.name) {
              Toast.warning({ content: "输入的应用名称不匹配。" });
              return;
            }
            setDeleteReauthenticationVisible(true);
          }}
        >
          永久删除应用
        </Button>
      </div>

      <Modal
        title="重新认证并删除应用"
        visible={deleteReauthenticationVisible}
        footer={null}
        onCancel={closeDeleteReauthentication}
        closeOnEsc={!deleting}
        maskClosable={false}
      >
        <p>
          本次授权仅绑定到应用 <strong>{detail.name}</strong>（{detail.applicationId}），
          且只能使用一次。
        </p>
        {deleteReauthenticationVisible && (
          <AccountReauthenticationForm
            action="application.delete"
            target=""
            applicationId={detail.applicationId}
            submitLabel="验证并永久删除"
            browserOperationRef={browserOperation}
            onGranted={handleDeleteApplication}
            onCancel={closeDeleteReauthentication}
            operationError="应用删除失败；此次单次授权不会被重复使用，请重新验证后再试。"
            destructive
          />
        )}
      </Modal>
    </div>
  );
}
