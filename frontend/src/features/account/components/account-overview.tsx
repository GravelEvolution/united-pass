import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { CurrentUser } from "@/types/identity";
import styles from "./account-panels.module.css";

type AccountOverviewProps = {
  currentUser: CurrentUser;
};

export function AccountOverview({ currentUser }: AccountOverviewProps) {
  return (
    <>
      <PageHeader
        eyebrow="My identity"
        title={`你好，${currentUser.displayName}`}
        description="查看统一账户资料，以及与该账户关联的用户和员工身份。"
      />

      <div className={styles.overviewGrid}>
        <section className={styles.heroCard}>
          <div className={styles.avatar}>{currentUser.displayName.slice(0, 1)}</div>
          <div className={styles.heroCopy}>
            <span className={styles.label}>统一账户</span>
            <h2>{currentUser.displayName}</h2>
            <p>{currentUser.email}</p>
            <div className={styles.badges}>
              <StatusBadge label="外部用户能力" tone="info" />
              {currentUser.employeeProfile && <StatusBadge label="员工档案已关联" tone="success" />}
            </div>
          </div>
          <div className={styles.stableId}>
            <span>稳定用户 ID</span>
            <code>{currentUser.userId}</code>
          </div>
        </section>

        <section className={styles.card}>
          <div className={styles.cardHeading}>
            <div>
              <span className={styles.label}>ACCOUNT DETAILS</span>
              <h2>基本资料</h2>
            </div>
            <StatusBadge label="已验证" tone="success" />
          </div>
          <dl className={styles.detailList}>
            <div><dt>显示名称</dt><dd>{currentUser.displayName}</dd></div>
            <div><dt>邮箱地址</dt><dd>{currentUser.email}</dd></div>
            <div><dt>手机号码</dt><dd>{currentUser.phoneMasked}</dd></div>
          </dl>
        </section>

        <section className={styles.card}>
          <div className={styles.cardHeading}>
            <div>
              <span className={styles.label}>EMPLOYEE PERSONA</span>
              <h2>员工档案</h2>
            </div>
            <StatusBadge label={currentUser.employeeProfile ? "在职" : "未关联"} tone={currentUser.employeeProfile ? "success" : "neutral"} />
          </div>
          {currentUser.employeeProfile ? (
            <dl className={styles.detailList}>
              <div><dt>员工编号</dt><dd>{currentUser.employeeProfile.employeeId}</dd></div>
              <div><dt>所属部门</dt><dd>{currentUser.employeeProfile.departmentName}</dd></div>
              <div><dt>职位</dt><dd>{currentUser.employeeProfile.title}</dd></div>
            </dl>
          ) : (
            <p className={styles.emptyText}>此账户目前没有员工档案，但仍可使用普通用户能力。</p>
          )}
        </section>
      </div>
    </>
  );
}
