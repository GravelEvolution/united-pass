import { MockActionButton } from "@/components/common/mock-action-button";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { UserSession } from "@/features/account/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./account-panels.module.css";

type SessionListProps = {
  sessions: UserSession[];
};

export function SessionList({ sessions }: SessionListProps) {
  return (
    <>
      <PageHeader
        eyebrow="Active sessions"
        title="活跃会话"
        description="核对登录设备、最近活动与大致位置。IP 地址仅显示脱敏值。"
      />
      <section className={styles.card}>
        <div className={styles.sessionList}>
          {sessions.map((session) => (
            <article key={session.sessionId} className={styles.sessionRow}>
              <div className={styles.deviceIcon} aria-hidden="true">{session.deviceName.includes("iPhone") ? "M" : "D"}</div>
              <div className={styles.sessionCopy}>
                <div className={styles.sessionTitle}>
                  <h2>{session.deviceName}</h2>
                  {session.isCurrent && <StatusBadge label="当前设备" tone="success" />}
                </div>
                <p>{session.clientName}</p>
                <span>{session.approximateLocation} · {session.ipAddressMasked} · {formatSecurityDateTime(session.lastActiveAt)}</span>
              </div>
              {!session.isCurrent && <MockActionButton danger message={`撤销 ${session.deviceName} 的会话`}>撤销会话</MockActionButton>}
            </article>
          ))}
        </div>
      </section>
    </>
  );
}
