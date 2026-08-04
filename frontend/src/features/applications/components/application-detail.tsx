"use client";

import Link from "next/link";
import { Button, Empty, Tabs, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import type { OAuthApplicationDetail } from "@/features/applications/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./application-detail.module.css";

type ApplicationDetailProps = {
  detail: OAuthApplicationDetail;
};

const clientTypeLabel = (clientType: string) =>
  clientType === "public" ? "公共客户端（PKCE）" : "机密客户端";

const kindLabel = (kind: string) => {
  switch (kind) {
    case "internal":
      return "内部应用";
    case "public-app":
      return "公共应用";
    case "hybrid":
      return "混合应用";
    default:
      return kind;
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
          <span>Client ID: <code>{detail.clientId}</code></span>
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

          <Tabs.TabPane tab="OAuth 配置" itemKey="oauth">
            <OAuthConfigTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="Redirect URI" itemKey="redirect">
            <RedirectUriTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="Scopes 与 Claims" itemKey="scopes">
            <ScopesTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="Client Secret" itemKey="secret">
            <ClientSecretTab detail={detail} />
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

      <dt>应用类型</dt>
      <dd>{kindLabel(detail.kind)}</dd>

      <dt>客户端类型</dt>
      <dd>{clientTypeLabel(detail.clientType)}</dd>

      <dt>Client ID</dt>
      <dd><code>{detail.clientId}</code></dd>

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

function OAuthConfigTab({ detail }: ApplicationDetailProps) {
  return (
    <div className={styles.section}>
      <dl className={styles.descriptionList}>
        <dt>Client ID</dt>
        <dd><code>{detail.clientId}</code></dd>

        <dt>客户端类型</dt>
        <dd>{clientTypeLabel(detail.clientType)}</dd>

        <dt>用户确认授权</dt>
        <dd>{detail.consentRequired ? "需要用户确认" : "无需确认（可信内部应用）"}</dd>

        <dt>Logout URI</dt>
        <dd>{detail.logoutUri || "未配置"}</dd>
      </dl>

      {detail.clientType === "public" ? (
        <div className={`${styles.notice} ${styles.noticeInfo}`}>
          <div>
            <strong>公共客户端安全要求</strong>
            必须使用 Authorization Code + PKCE 流程。不会生成或存储 Client Secret。
          </div>
        </div>
      ) : (
        <div className={`${styles.notice} ${styles.noticeInfo}`}>
          <div>
            <strong>机密客户端</strong>
            使用 Authorization Code 流程，Client Secret 存储在服务端密钥系统中，不会在列表或详情页展示明文。
          </div>
        </div>
      )}
    </div>
  );
}

function RedirectUriTab({ detail }: ApplicationDetailProps) {
  if (detail.redirectUris.length === 0) {
    return <Empty title="未配置 Redirect URI" description="请添加至少一个已登记的回调地址。" />;
  }

  return (
    <div className={styles.uriList}>
      {detail.redirectUris.map((entry) => (
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

function ScopesTab({ detail }: ApplicationDetailProps) {
  if (detail.allowedScopes.length === 0) {
    return <Empty title="未配置允许的 Scope" />;
  }

  return (
    <div className={styles.scopeGrid}>
      {detail.allowedScopes.map((scope) => (
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

function ClientSecretTab({ detail }: ApplicationDetailProps) {
  if (detail.clientType === "public") {
    return (
      <div className={`${styles.notice} ${styles.noticeInfo}`}>
        <div>
          <strong>公共客户端不使用 Client Secret</strong>
          此应用使用 Authorization Code + PKCE 流程，客户端密钥不会存储或展示。
        </div>
      </div>
    );
  }

  return (
    <div className={styles.section}>
      {detail.clientSecrets.length === 0 ? (
        <Empty title="暂无密钥记录" />
      ) : (
        <dl className={styles.descriptionList}>
          {detail.clientSecrets.map((secret) => (
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
          onClick={() => Toast.info({ content: "密钥轮换需要重认证（当前仅为 Mock）。" })}
        >
          轮换密钥（Mock）
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
  const isActive = detail.status === "active";

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
          onClick={() => Toast.info({ content: `${isActive ? "停用" : "启用"}应用需要重认证（当前仅为 Mock）。` })}
        >
          {isActive ? "停用应用（Mock）" : "启用应用（Mock）"}
        </Button>
      </div>

      <div className={styles.dangerItem}>
        <div>
          <strong>删除应用</strong>
          <p>删除后所有授权记录和配置将永久清除，且无法恢复。</p>
        </div>
        <Button
          theme="solid"
          type="danger"
          onClick={() => Toast.info({ content: "删除应用需要重认证（当前仅为 Mock）。" })}
        >
          删除应用（Mock）
        </Button>
      </div>
    </div>
  );
}
