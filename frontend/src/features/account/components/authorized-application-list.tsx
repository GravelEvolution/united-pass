import { MockActionButton } from "@/components/common/mock-action-button";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { AuthorizedApplication } from "@/features/account/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./authorized-application-list.module.css";

type AuthorizedApplicationListProps = {
  applications: AuthorizedApplication[];
};

export function AuthorizedApplicationList({ applications }: AuthorizedApplicationListProps) {
  const activeGrants = applications.filter((grant) => grant.status === "active");
  const revokedGrants = applications.filter((grant) => grant.status === "revoked");

  return (
    <>
      <PageHeader
        eyebrow="Authorized applications"
        title="授权应用"
        description="查看你授权过的 OAuth 应用与已授予的 Scope。撤销授权后应用将无法继续访问你的数据。"
      />

      {applications.length === 0 ? (
        <section className={styles.emptyState}>
          <p>你还没有授权任何应用。</p>
          <p className={styles.emptyHint}>当你在其他应用中使用 United Pass 登录并确认授权后，记录会出现在这里。</p>
        </section>
      ) : (
        <>
          {activeGrants.length > 0 && (
            <section className={styles.section}>
              <h2 className={styles.sectionTitle}>活跃授权（{activeGrants.length}）</h2>
              <div className={styles.grantList}>
                {activeGrants.map((grant) => (
                  <GrantCard key={grant.grantId} grant={grant} />
                ))}
              </div>
            </section>
          )}

          {revokedGrants.length > 0 && (
            <section className={styles.section}>
              <h2 className={styles.sectionTitle}>已撤销（{revokedGrants.length}）</h2>
              <div className={styles.grantList}>
                {revokedGrants.map((grant) => (
                  <GrantCard key={grant.grantId} grant={grant} />
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </>
  );
}

function GrantCard({ grant }: { grant: AuthorizedApplication }) {
  const isActive = grant.status === "active";

  return (
    <article className={styles.grantCard}>
      <div className={styles.grantHeader}>
        <div className={styles.grantIdentity}>
          <div className={styles.appIcon} aria-hidden="true">{grant.applicationName.slice(0, 1)}</div>
          <div>
            <div className={styles.grantTitle}>
              <h3>{grant.applicationName}</h3>
              <StatusBadge
                label={isActive ? "活跃" : "已撤销"}
                tone={isActive ? "success" : "neutral"}
              />
            </div>
            <p>由 {grant.applicationOwner} 提供 · {grant.clientType === "public" ? "Public Client" : "Confidential Client"}</p>
          </div>
        </div>
        {isActive && (
          <MockActionButton danger message={`撤销 ${grant.applicationName} 的授权`}>
            撤销授权
          </MockActionButton>
        )}
      </div>

      <dl className={styles.detailList}>
        <div>
          <dt>授权时间</dt>
          <dd>{formatSecurityDateTime(grant.grantedAt)}</dd>
        </div>
        <div>
          <dt>最近使用</dt>
          <dd>{grant.lastUsedAt ? formatSecurityDateTime(grant.lastUsedAt) : "从未使用"}</dd>
        </div>
      </dl>

      <div className={styles.scopeRow}>
        <span className={styles.scopeLabel}>已授予 Scope</span>
        <div className={styles.scopeTags}>
          {grant.scopes.map((scope) => (
            <code key={scope}>{scope}</code>
          ))}
        </div>
      </div>

      {grant.hasOfflineAccess && (
        <p className={styles.offlineNotice}>
          此授权包含 <code>offline_access</code>，应用可在你不活跃时通过 Refresh Token 继续访问已授权数据。撤销授权后将立即失效。
        </p>
      )}
    </article>
  );
}
