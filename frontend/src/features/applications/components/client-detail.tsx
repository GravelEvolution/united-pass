"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Empty, Modal, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import {
  CONSENT_MODE_LABELS,
  type ApplicationStatus,
  type OAuthClient,
  type OAuthGrantType,
  type SecretRotationResult,
} from "@/features/applications/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./application-detail.module.css";
import clientStyles from "./client-detail.module.css";

type ClientDetailProps = {
  applicationId: string;
  applicationName: string;
  applicationStatus: ApplicationStatus;
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

export function ClientDetail({
  applicationId,
  applicationName,
  applicationStatus,
  client,
}: ClientDetailProps) {
  return (
    <>
      <nav className={styles.backLink}>
        <Link href={`/admin/applications/${applicationId}`} className={styles.backLink}>
          ← 返回 {applicationName}
        </Link>
      </nav>

      <PageHeader
        eyebrow="OAuth Client"
        title={client.name}
        description={`${applicationName} · Client ID: ${client.clientId}`}
      />

      <div className={styles.headerCard}>
        <div className={styles.headerInfo}>
          <h1>{client.name}</h1>
          <p>
            属于 <Link href={`/admin/applications/${applicationId}`}>{applicationName}</Link>
            {" · "}
            Client ID: <code>{client.clientId}</code>
          </p>
        </div>
        <div className={styles.headerMeta}>
          <StatusBadge
            label={client.status === "active" ? "正常" : "已停用"}
            tone={client.status === "active" ? "success" : "danger"}
          />
          {applicationStatus === "disabled" && (
            <span>所属应用已停用</span>
          )}
        </div>
      </div>

      <div className={clientStyles.contentLayout}>
        <section className={styles.section}>
          <h3>客户端基本信息</h3>
          <dl className={styles.descriptionList}>
            <dt>客户端名称</dt>
            <dd>{client.name}</dd>

            <dt>Client ID</dt>
            <dd><code>{client.clientId}</code></dd>

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

            <dt>状态</dt>
            <dd>
              <StatusBadge
                label={client.status === "active" ? "正常" : "已停用"}
                tone={client.status === "active" ? "success" : "danger"}
              />
            </dd>

            <dt>创建时间</dt>
            <dd>{formatSecurityDateTime(client.createdAt)}</dd>

            <dt>更新时间</dt>
            <dd>{formatSecurityDateTime(client.updatedAt)}</dd>
          </dl>
        </section>

        <section className={styles.section}>
          <h3>Redirect URI</h3>
          <ClientRedirectUris client={client} />
        </section>

        <section className={styles.section}>
          <h3>允许的 Scope</h3>
          <ClientScopes client={client} />
        </section>

        <section className={styles.section}>
          <h3>Client Secret</h3>
          <ClientSecrets client={client} />
        </section>
      </div>
    </>
  );
}

function ClientRedirectUris({ client }: { client: OAuthClient }) {
  if (client.redirectUris.length === 0) {
    return (
      <Empty
        title="未配置 Redirect URI"
        description="此客户端未配置任何回调地址。"
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

function ClientScopes({ client }: { client: OAuthClient }) {
  if (client.allowedScopes.length === 0) {
    return <Empty title="未配置允许的 Scope" description="此客户端未授权任何 Scope。" />;
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

function ClientSecrets({ client }: { client: OAuthClient }) {
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
          const result = await browserCommands.rotateClientSecret(client.applicationId, client.clientId);
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
