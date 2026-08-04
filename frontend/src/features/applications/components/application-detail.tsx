"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Empty, Modal, Tabs, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import {
  AUDIENCE_LABELS,
  CONSENT_MODE_LABELS,
  type OAuthApplicationDetail,
  type OAuthClient,
  type OAuthGrantType,
  type SecretRotationResult,
} from "@/features/applications/types";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./application-detail.module.css";

type ApplicationDetailProps = {
  detail: OAuthApplicationDetail;
};

type ClientCardProps = {
  client: OAuthClient;
};

const clientTypeLabel = (clientType: OAuthClient["clientType"]) =>
  clientType === "public" ? "公共客户端（PKCE）" : "机密客户端";

const grantTypeLabel = (grantType: OAuthGrantType) => {
  switch (grantType) {
    case "authorization_code":
      return "Authorization Code";
    case "refresh_token":
      return "Refresh Token";
    case "client_credentials":
      return "Client Credentials";
    default:
      return grantType;
  }
};

export function ApplicationDetail({ detail }: ApplicationDetailProps) {
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
        <Tabs type="line">
          <Tabs.TabPane tab="基本信息" itemKey="basic">
            <BasicInfoTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="OAuth Clients" itemKey="clients">
            <ClientsTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="授权记录" itemKey="grants">
            <GrantsTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="审计日志" itemKey="audit">
            <AuditTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="危险操作" itemKey="danger">
            <DangerTab detail={detail} />
          </Tabs.TabPane>
        </Tabs>
      </div>
    </>
  );
}

function BasicInfoTab({ detail }: ApplicationDetailProps) {
  return (
    <dl className={styles.descriptionList}>
      <dt>应用名称</dt>
      <dd>{detail.name}</dd>

      <dt>应用说明</dt>
      <dd>{detail.description || "—"}</dd>

      <dt>受众</dt>
      <dd>{AUDIENCE_LABELS[detail.audience]}</dd>

      <dt>负责人</dt>
      <dd>{detail.ownerName}</dd>

      <dt>状态</dt>
      <dd>
        <StatusBadge
          label={detail.status === "active" ? "正常" : "已停用"}
          tone={detail.status === "active" ? "success" : "danger"}
        />
      </dd>

      <dt>创建时间</dt>
      <dd>{formatSecurityDateTime(detail.createdAt)}</dd>

      <dt>更新时间</dt>
      <dd>{formatSecurityDateTime(detail.updatedAt)}</dd>
    </dl>
  );
}

function ClientsTab({ detail }: ApplicationDetailProps) {
  if (detail.clients.length === 0) {
    return (
      <Empty
        title="暂无 OAuth Client"
        description="此应用尚未配置任何 OAuth Client。"
      />
    );
  }

  return (
    <div className={styles.section}>
      {detail.clients.map((client) => (
        <ClientCard key={client.clientId} client={client} />
      ))}
    </div>
  );
}

function ClientCard({ client }: ClientCardProps) {
  return (
    <section className={styles.section}>
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

      <dl className={styles.descriptionList}>
        <dt>客户端类型</dt>
        <dd>{clientTypeLabel(client.clientType)}</dd>

        <dt>Grant Types</dt>
        <dd>{client.grantTypes.map(grantTypeLabel).join(", ")}</dd>

        <dt>令牌端点认证方式</dt>
        <dd>{client.tokenEndpointAuthMethod}</dd>

        <dt>用户确认授权</dt>
        <dd>{CONSENT_MODE_LABELS[client.consentMode]}</dd>

        <dt>Logout URI</dt>
        <dd>{client.logoutUri || "未配置"}</dd>
      </dl>

      <ClientRedirectUris client={client} />
      <ClientScopes client={client} />
      <ClientSecrets client={client} />
    </section>
  );
}

function ClientRedirectUris({ client }: ClientCardProps) {
  if (client.redirectUris.length === 0) {
    return (
      <Empty
        title="未配置 Redirect URI"
        description="请添加至少一个已登记的回调地址。"
      />
    );
  }

  return (
    <div className={styles.uriList}>
      {client.redirectUris.map((entry) => (
        <div key={entry.uri} className={styles.uriRow}>
          <code>{entry.uri}</code>
          <span>
            {entry.isLoopback ? "本地回环地址" : "远程地址"}
            {" · "}
            添加于 {formatSecurityDateTime(entry.addedAt)}
          </span>
        </div>
      ))}
      <div className={`${styles.notice} ${styles.noticeWarning}`}>
        <div>
          <strong>安全提示</strong>
          Redirect URI 必须由后端按精确安全语义校验。前端不会静默归一化或拼接用户输入的地址。
        </div>
      </div>
    </div>
  );
}

function ClientScopes({ client }: ClientCardProps) {
  if (client.allowedScopes.length === 0) {
    return <Empty title="未配置允许的 Scope" />;
  }

  return (
    <div className={styles.scopeGrid}>
      {client.allowedScopes.map((scope) => (
        <div key={scope.scope} className={styles.scopeRow}>
          <code>{scope.scope}</code>
          <div>
            <strong>{scope.label}{scope.required && "（必选）"}</strong>
            <p>{scope.description}</p>
          </div>
        </div>
      ))}
      <div className={`${styles.notice} ${styles.noticeInfo}`}>
        <div>
          <strong>Scope 与权限的边界</strong>
          OAuth Scope 仅描述授权数据范围，不代表业务管理权限。应用级 ABAC 权限由后端独立强制执行。
        </div>
      </div>
    </div>
  );
}

function ClientSecrets({ client }: ClientCardProps) {
  const router = useRouter();
  const [rotating, setRotating] = useState(false);
  const [rotatedSecret, setRotatedSecret] = useState<SecretRotationResult>();

  if (client.clientType === "public") {
    return (
      <div className={`${styles.notice} ${styles.noticeInfo}`}>
        <div>
          <strong>公共客户端不使用 Client Secret</strong>
          此客户端使用 Authorization Code + PKCE 流程，客户端密钥不会存储或展示。
        </div>
      </div>
    );
  }

  function handleRotateSecret() {
    Modal.warning({
      title: "轮换 Client Secret",
      content: (
        <div>
          <p>轮换后旧密钥将在 <strong>24 小时</strong>内保持有效，到期后自动失效。</p>
          <p>新密钥仅在此页面展示一次，离开后无法再次查看。</p>
          <p>此操作需要重认证。当前为 Mock 实现，不会真实校验。</p>
        </div>
      ),
      okText: "确认轮换",
      cancelText: "取消",
      okType: "danger",
      onOk: async () => {
        setRotating(true);
        try {
          const result = await mockUnitedPassDataSource.rotateClientSecret(client.clientId);
          setRotatedSecret(result);
          Toast.success({ content: "密钥已轮换，请立即复制新密钥。" });
          router.refresh();
        } catch {
          Toast.error({ content: "密钥轮换失败，请重试。" });
          throw new Error("rotation failed");
        } finally {
          setRotating(false);
        }
      },
    });
  }

  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      Toast.success({ content: "已复制到剪贴板。" });
    } catch {
      Toast.error({ content: "复制失败，请手动选择并复制。" });
    }
  }

  return (
    <div className={styles.section}>
      {client.clientSecrets.length === 0 ? (
        <Empty title="暂无密钥记录" />
      ) : (
        <dl className={styles.descriptionList}>
          {client.clientSecrets.map((secret) => (
            <div key={secret.secretId} style={{ display: "contents" }}>
              <dt>密钥标签</dt>
              <dd>{secret.label}</dd>

              <dt>密钥 ID</dt>
              <dd><code>{secret.secretId}</code></dd>

              <dt>创建时间</dt>
              <dd>{formatSecurityDateTime(secret.createdAt)}</dd>

              <dt>上次轮换</dt>
              <dd>{secret.lastRotatedAt ? formatSecurityDateTime(secret.lastRotatedAt) : "从未轮换"}</dd>
            </div>
          ))}
        </dl>
      )}

      {rotatedSecret && (
        <div className={`${styles.notice} ${styles.noticeDanger}`}>
          <div>
            <strong>新 Client Secret（仅此一次展示）</strong>
            <p style={{ marginTop: 8, marginBottom: 8 }}>
              <code>{rotatedSecret.clientSecret}</code>
              <Button
                size="small"
                theme="borderless"
                onClick={() => copyToClipboard(rotatedSecret.clientSecret)}
              >
                复制
              </Button>
            </p>
            <p>旧密钥将在 {formatSecurityDateTime(rotatedSecret.previousSecretExpiresAt)} 后失效。</p>
          </div>
        </div>
      )}

      <div className={`${styles.notice} ${styles.noticeDanger}`}>
        <div>
          <strong>Client Secret 不会再次展示</strong>
          创建或轮换时展示一次后即从系统中移除明文。此处仅显示密钥元数据，不包含密钥值。
        </div>
      </div>

      <div>
        <Button
          theme="solid"
          type="warning"
          loading={rotating}
          onClick={handleRotateSecret}
        >
          轮换密钥
        </Button>
      </div>
    </div>
  );
}

function GrantsTab({ detail }: ApplicationDetailProps) {
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

function AuditTab({ detail }: ApplicationDetailProps) {
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

function DangerTab({ detail }: ApplicationDetailProps) {
  const router = useRouter();
  const isActive = detail.status === "active";
  const [toggling, setToggling] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmDeleteName, setConfirmDeleteName] = useState("");

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
            <p>此操作需要重认证。当前为 Mock 实现。</p>
          </>
        ) : (
          <p>恢复后用户可重新发起新的授权请求。已过期的授权不会自动恢复。</p>
        )}
      </div>
    );

    const onOk = async () => {
      setToggling(true);
      try {
        await mockUnitedPassDataSource.updateApplicationStatus(
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

  async function handleDeleteApplication() {
    if (confirmDeleteName !== detail.name) {
      Toast.warning({ content: "输入的应用名称不匹配。" });
      return;
    }

    setDeleting(true);
    try {
      await mockUnitedPassDataSource.deleteApplication(detail.applicationId);
      Toast.success({ content: "应用已删除。" });
      router.push("/admin/applications");
    } catch {
      Toast.error({ content: "删除失败，请重试。" });
    } finally {
      setDeleting(false);
    }
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
          onClick={handleDeleteApplication}
        >
          永久删除应用
        </Button>
      </div>
    </div>
  );
}
