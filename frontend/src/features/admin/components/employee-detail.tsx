//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Employee detail panel
//

"use client";

import type { FormEvent } from "react";
import { useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Empty, Modal, Tabs, Toast } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import type { DepartmentRecord, EmployeeDetail, EmployeeRecord } from "@/features/admin/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { AccountReauthenticationForm } from "@/features/account/components/security-overview";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import styles from "./admin-detail.module.css";

type EmployeeDetailProps = {
  detail: EmployeeDetail;
  canManage?: boolean;
  canOffboard?: boolean;
  departments?: DepartmentRecord[];
  supervisors?: EmployeeRecord[];
};

const VALID_TABS = ["profile", "access", "danger"] as const;
type TabKey = (typeof VALID_TABS)[number];

function isTabKey(value: string | null): value is TabKey {
  return value !== null && (VALID_TABS as readonly string[]).includes(value);
}

export function EmployeeDetail({
  detail,
  canManage = false,
  canOffboard = false,
  departments = [],
  supervisors = [],
}: EmployeeDetailProps) {
  const router = useRouter();
  const tabParam = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("tab") : null;
  const requestedTab: TabKey = isTabKey(tabParam) ? tabParam : "profile";
  const activeTab: TabKey = requestedTab === "danger" && !canOffboard ? "profile" : requestedTab;

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
            <ProfileTab
              detail={detail}
              canManage={canManage}
              departments={departments}
              supervisors={supervisors}
            />
          </Tabs.TabPane>

          <Tabs.TabPane tab="访问权限" itemKey="access">
            <AccessTab detail={detail} />
          </Tabs.TabPane>

          {canOffboard && (
            <Tabs.TabPane tab="离职操作" itemKey="danger">
              <DangerTab detail={detail} />
            </Tabs.TabPane>
          )}
        </Tabs>
      </div>
    </>
  );
}

function ProfileTab({
  detail,
  canManage = false,
  departments = [],
  supervisors = [],
}: EmployeeDetailProps) {
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [departmentId, setDepartmentId] = useState(detail.departmentId);
  const [title, setTitle] = useState(detail.title);
  const [supervisorUserId, setSupervisorUserId] = useState(detail.supervisorUserId ?? "");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!departmentId || !title.trim()) return;
    setSubmitting(true);
    try {
      await browserCommands.updateEmployeeProfile(detail.userId, {
        departmentId,
        title: title.trim(),
        supervisorUserId: supervisorUserId || undefined,
      });
      Toast.success({ content: "员工档案已更新。" });
      setEditing(false);
      router.refresh();
    } catch {
      Toast.error({ content: "更新失败，请检查部门与主管状态后重试。" });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      {canManage && detail.status === "active" && (
        <div className={styles.formActions} style={{ marginBottom: 16 }}>
          <Button theme="solid" type="primary" onClick={() => setEditing(true)}>
            编辑员工档案
          </Button>
        </div>
      )}
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
        <dd>{detail.linkedConsumerAccount ? "已关联统一账户（消费者人格保留）" : "未关联"}</dd>
      </dl>

      <Modal
        title="编辑员工档案"
        visible={editing}
        footer={null}
        onCancel={() => {
          if (!submitting) setEditing(false);
        }}
        maskClosable={false}
      >
        <form method="post" className={styles.linkForm} onSubmit={handleSubmit}>
          <label className={styles.formField}>
            <span>部门 *</span>
            <select value={departmentId} onChange={(event) => setDepartmentId(event.target.value)}>
              {departments.map((department) => (
                <option key={department.departmentId} value={department.departmentId}>
                  {department.name}
                </option>
              ))}
            </select>
          </label>
          <label className={styles.formField}>
            <span>职位 *</span>
            <input value={title} onChange={(event) => setTitle(event.target.value)} maxLength={120} />
          </label>
          <label className={styles.formField}>
            <span>主管</span>
            <select value={supervisorUserId} onChange={(event) => setSupervisorUserId(event.target.value)}>
              <option value="">不指定</option>
              {supervisors
                .filter((employee) => employee.status === "active" && employee.userId !== detail.userId)
                .map((employee) => (
                  <option key={employee.userId} value={employee.userId}>
                    {employee.displayName} · {employee.employeeId}
                  </option>
                ))}
            </select>
          </label>
          <div className={styles.formActions}>
            <Button theme="outline" onClick={() => setEditing(false)} disabled={submitting}>取消</Button>
            <Button htmlType="submit" theme="solid" type="primary" loading={submitting} disabled={submitting}>
              保存
            </Button>
          </div>
        </form>
      </Modal>
    </>
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
          <p>员工状态为在职，可由后端策略授予管理能力；在职状态本身不构成授权。</p>
        </div>
        <StatusBadge label="策略决定" tone="info" />
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
  const [reauthVisible, setReauthVisible] = useState(false);
  const browserOperation = useRef<AbortController | null>(null);

  function closeReauthentication(): void {
    browserOperation.current?.abort();
    browserOperation.current = null;
    setReauthVisible(false);
  }

  async function handleOffboard(reauthToken: string, signal: AbortSignal): Promise<void> {
    setOffboarding(true);
    try {
      await browserCommands.offboardEmployee(detail.userId, reauthToken, { signal });
      Toast.success({ content: "离职流程已启动；管理访问已立即拒绝，会话撤销正在收敛。" });
      setReauthVisible(false);
      router.refresh();
    } finally {
      setOffboarding(false);
    }
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
          onClick={() => setReauthVisible(true)}
        >
          确认离职
        </Button>
      </div>

      <Modal
        title="重新认证并启动离职"
        visible={reauthVisible}
        footer={null}
        onCancel={closeReauthentication}
        closeOnEsc={!offboarding}
        maskClosable={false}
      >
        <div>
          <p>离职会立即拒绝管理端访问并启动全部会话撤销。</p>
          <p>消费者人格和 OAuth 授权不会被删除。本次授权仅绑定到 {detail.userId}。</p>
        </div>
        <AccountReauthenticationForm
          action="employee.offboard"
          target={detail.userId}
          submitLabel="验证并启动离职"
          browserOperationRef={browserOperation}
          onGranted={handleOffboard}
          onCancel={closeReauthentication}
          operationError="离职操作未完成；此次单次授权不会被重复使用，请重新验证后再试。"
          destructive
        />
      </Modal>
    </div>
  );
}
