//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Admin console overview panel
//

import Link from "next/link";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { AdminDashboard } from "@/lib/api/united-pass-data-source";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./admin.module.css";

type AdminOverviewProps = {
  dashboard: AdminDashboard;
};

export function AdminOverview({ dashboard }: AdminOverviewProps) {
  return (
    <>
      <PageHeader
        eyebrow="Administration"
        title="身份管理工作台"
        description="统一查看账户、员工、OAuth 应用与授权策略的运行概况。前端可见性不是权限边界，所有管理操作仍需后端授权。"
      />

      <section className={styles.metrics} aria-label="关键指标">
        {dashboard.metrics.map((metric) => (
          <article key={metric.label} className={styles.metricCard}>
            <span>{metric.label}</span>
            <strong>{metric.value}</strong>
            <p className={styles[metric.tone]}>{metric.change}</p>
          </article>
        ))}
      </section>

      <div className={styles.dashboardGrid}>
        <section className={styles.card}>
          <div className={styles.cardHeading}>
            <div><span>SECURITY SIGNALS</span><h2>最近安全事件</h2></div>
            <Link href="/admin/audit">查看全部</Link>
          </div>
          <div className={styles.eventList}>
            {dashboard.recentEvents.map((event) => (
              <article key={event.eventId} className={styles.eventRow}>
                <div className={styles.eventDot} data-result={event.result} />
                <div>
                  <h3>{event.eventType}</h3>
                  <p>{event.actorName} · {event.targetLabel}</p>
                </div>
                <div className={styles.eventMeta}>
                  <StatusBadge label={event.result === "success" ? "成功" : "已拒绝"} tone={event.result === "success" ? "success" : "danger"} />
                  <span>{formatSecurityDateTime(event.occurredAt)}</span>
                </div>
              </article>
            ))}
          </div>
        </section>

        <aside className={`${styles.card} ${styles.readinessCard}`}>
          <div className={styles.cardHeading}><div><span>INTEGRATION</span><h2>后端接入准备</h2></div></div>
          <ol>
            <li><StatusBadge label="已完成" tone="success" /><span>数据源接口与 mock 边界</span></li>
            <li><StatusBadge label="待接入" tone="warning" /><span>OIDC 登录与授权请求校验</span></li>
            <li><StatusBadge label="待接入" tone="warning" /><span>服务端会话与权限决策</span></li>
          </ol>
          <p>完整接口清单位于 <code>docs/api-contracts.md</code>。</p>
        </aside>
      </div>
    </>
  );
}
