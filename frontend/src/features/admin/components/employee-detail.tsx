"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Empty, Modal, Tabs, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import type { EmployeeDetail } from "@/features/admin/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./admin-detail.module.css";

type EmployeeDetailProps = {
  detail: EmployeeDetail;
};

const VALID_TABS = ["profile", "access", "danger"] as const;
type TabKey = (typeof VALID_TABS)[number];

function isTabKey(value: string | null): value is TabKey {
  return value !== null && (VALID_TABS as readonly string[]).includes(value);
}

export function EmployeeDetail({ detail }: EmployeeDetailProps) {
  const router = useRouter();
  const tabParam = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("tab") : null;
  const activeTab: TabKey = isTabKey(tabParam) ? tabParam : "profile";

  function handleTabChange(itemKey: string) {
    const params = new URLSearchParams(window.location.search);
    if (itemKey === "profile") {
      params.delete("tab");
    } else {
      params.set("tab", itemKey);
    }
    const queryString = params.toString();
    router.replace(`/admin/employees/${detail.userId}${queryString ? `?${queryString}` : ""}`);
  }

  return (
    <>
      <Link href="/admin/employees" className={styles.backLink}>
        ← 返回员工列表
      </Link>

      <PageHeader
        eyebrow="Workforce"
        title={detail.displayName}
        description={`员工编号：${detail.employeeId}`}
      />

      <div className={styles.headerCard}>
        <div className={styles.headerInfo}>
          <h1>{detail.displayName}</h1>
          <p>{detail.email} · {detail.title}</p>
        </div>
        <div className={styles.headerMeta}>
          <span>{detail.departmentName}</span>
          <StatusBadge
            label={detail.status === "active" ? "在职" : "离职处理中"}
            tone={detail.status === "active" ? "success" : "warning"}
          />
        </div>
      </div>

      <div className={styles.tabContent}>
        <Tabs type="line" activeKey={activeTab} onChange={handleTabChange}>
          <Tabs.TabPane tab="档案信息" itemKey="profile">
            <ProfileTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="访问权限" itemKey="access">
            <AccessTab detail={detail} />
          </Tabs.TabPane>

          <Tabs.TabPane tab="离职操作" itemKey="danger">
            <DangerTab detail={detail} />
          </Tabs.TabPane>
        </Tabs>
      </div>
    </>
  );
}

function ProfileTab({ detail }: EmployeeDetailProps) {
  return (
    <dl className={styles.descriptionList}>
      <dt>用户 ID</dt>
      <dd><code>{detail.userId}</code></dd>

      <dt>员工编号</dt>
      <dd>{detail.employeeId}</dd>

      <dt>显示名称</dt>
      <dd>{detail.displayName}</dd>

      <dt>邮箱</dt>
      <dd>{detail.email}</dd>

      <dt>部门</dt>
      <dd>{detail.departmentName}</dd>

      <dt>职位</dt>
      <dd>{detail.title}</dd>

      <dt>主管</dt>
      <dd>{detail.supervisorName ?? "未指定"}</dd>

      <dt>入职时间</dt>
      <dd>{formatSecurityDateTime(detail.onboardedAt)}</dd>

      <dt>关联的消费者账户</dt>
      <dd>
        {detail.linkedConsumerAccount ? (
          "已关联统一账户（消费者人格保留）"
        ) : (
          "未关联"
        )}
      </dd>
    </dl>
  );
}

function AccessTab({ detail }: EmployeeDetailProps) {
  if (detail.status === "offboarding") {
    return (
      <Empty
        title="离职处理中"
        description="该员工的访问权限正在撤销中。离职完成后所有管理端访问将被移除。"
      />
    );
  }

  return (
    <div className={styles.section}>
      <div className={styles.dangerItem}>
        <div>
          <strong>管理端访问</strong>
          <p>员工状态为在职，拥有管理端基础访问权限。具体能力由后端 ABAC 策略决定。</p>
        </div>
        <StatusBadge label="已启用" tone="success" />
      </div>

      {detail.linkedConsumerAccount && (
        <div className={styles.dangerItem}>
          <div>
            <strong>消费者人格</strong>
            <p>该员工同时拥有消费者人格。离职后消费者功能不受影响。</p>
          </div>
          <StatusBadge label="保留" tone="info" />
        </div>
      )}
    </div>
  );
}

function DangerTab({ detail }: EmployeeDetailProps) {
  const router = useRouter();
  const [offboarding, setOffboarding] = useState(false);

  async function handleOffboard(): Promise<void> {
    const onOk = async () => {
      setOffboarding(true);
      try {
        await browserCommands.offboardEmployee(detail.userId);
        Toast.success({ content: "离职流程已启动。" });
        router.refresh();
      } catch {
        Toast.error({ content: "操作失败，请重试。" });
        throw new Error("offboard failed");
      } finally {
        setOffboarding(false);
      }
    };

    Modal.warning({
      title: "确认离职？",
      content: (
        <div>
          <p>启动 <strong>{detail.displayName}</strong> 的离职流程后：</p>
          <ul>
            <li>管理端访问权限将被撤销</li>
            <li>活跃会话将被终止</li>
            <li>已授权的 OAuth 应用不会自动撤销</li>
            <li>消费者人格和功能保留不变</li>
            <li>操作不可逆</li>
          </ul>
          <p>此操作需要重认证。当前为 Mock 实现。</p>
        </div>
      ),
      okText: "确认离职",
      cancelText: "取消",
      okType: "danger",
      onOk,
    });
  }

  if (detail.status === "offboarding") {
    return (
      <div className={styles.dangerZone}>
        <div className={`${styles.notice} ${styles.noticeDanger}`}>
          <div>
            <strong>离职处理中</strong>
            该员工的离职流程已启动。管理端访问已撤销，消费者人格保留。
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.dangerZone}>
      <div className={`${styles.notice} ${styles.noticeDanger}`}>
        <div>
          <strong>危险操作</strong>
          离职将撤销该员工的管理端访问和活跃会话。消费者人格不受影响。操作不可逆。
        </div>
      </div>

      <div className={styles.dangerItem}>
        <div>
          <strong>启动离职流程</strong>
          <p>撤销管理端访问、终止活跃会话。消费者人格和功能保留不变。</p>
        </div>
        <Button
          theme="solid"
          type="danger"
          loading={offboarding}
          onClick={handleOffboard}
        >
          确认离职
        </Button>
      </div>
    </div>
  );
}
