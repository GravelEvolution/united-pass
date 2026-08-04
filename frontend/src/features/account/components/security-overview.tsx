import { MockActionButton } from "@/components/common/mock-action-button";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { SecurityFactor } from "@/features/account/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./account-panels.module.css";

type SecurityOverviewProps = {
  securityFactors: SecurityFactor[];
};

const factorDescriptions = {
  password: "用于基础凭据验证，建议定期检查是否存在复用风险。",
  totp: "使用身份验证器生成的一次性动态验证码。",
  passkey: "使用设备生物识别或安全密钥进行抗钓鱼验证。",
} satisfies Record<SecurityFactor["kind"], string>;

export function SecurityOverview({ securityFactors }: SecurityOverviewProps) {
  return (
    <>
      <PageHeader
        eyebrow="Account security"
        title="登录与安全"
        description="管理登录凭据和多重验证方式。重要变更将在后端接入后要求重新验证身份。"
      />
      <section className={styles.card}>
        <div className={styles.cardHeading}>
          <div>
            <span className={styles.label}>AUTHENTICATION</span>
            <h2>验证方式</h2>
          </div>
          <StatusBadge label="安全状态良好" tone="success" />
        </div>
        <div className={styles.factorList}>
          {securityFactors.map((factor) => (
            <article key={factor.factorId} className={styles.factorRow}>
              <div className={styles.factorIcon}>{factor.label.slice(0, 1)}</div>
              <div className={styles.factorCopy}>
                <div className={styles.factorTitle}>
                  <h3>{factor.label}</h3>
                  <StatusBadge label={factor.status === "active" ? "已启用" : "建议启用"} tone={factor.status === "active" ? "success" : "warning"} />
                </div>
                <p>{factorDescriptions[factor.kind]}</p>
                {factor.updatedAt && <span>最近更新：{formatSecurityDateTime(factor.updatedAt)}</span>}
              </div>
              <MockActionButton message={`配置${factor.label}`}>{factor.status === "active" ? "管理" : "设置"}</MockActionButton>
            </article>
          ))}
        </div>
      </section>

      <section className={`${styles.card} ${styles.dangerCard}`}>
        <div>
          <h2>安全恢复</h2>
          <p>撤销除当前设备以外的全部会话。接入真实 API 后，此操作需要重新验证并明确确认。</p>
        </div>
        <MockActionButton danger message="撤销其他全部会话">撤销其他会话</MockActionButton>
      </section>
    </>
  );
}
