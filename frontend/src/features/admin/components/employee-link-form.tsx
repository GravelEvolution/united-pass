"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Toast } from "@douyinfe/semi-ui";
import { PageHeader } from "@/components/common/page-header";
import type { DepartmentRecord, ManagedUser } from "@/features/admin/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import styles from "./admin-detail.module.css";

type EmployeeLinkFormProps = {
  users: ManagedUser[];
  departments: DepartmentRecord[];
};

export function EmployeeLinkForm({ users, departments }: EmployeeLinkFormProps) {
  const router = useRouter();
  const [userId, setUserId] = useState("");
  const [departmentId, setDepartmentId] = useState("");
  const [title, setTitle] = useState("");
  const [supervisorUserId, setSupervisorUserId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const eligibleUsers = users.filter((u) => u.status === "active");

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();

    const nextErrors: Record<string, string> = {};
    if (!userId) nextErrors.userId = "请选择要关联的用户。";
    if (!departmentId) nextErrors.departmentId = "请选择部门。";
    if (!title.trim()) nextErrors.title = "请填写职位名称。";

    if (Object.keys(nextErrors).length > 0) {
      setErrors(nextErrors);
      return;
    }

    setErrors({});
    setSubmitting(true);
    try {
      await browserCommands.linkEmployeeProfile({
        userId,
        departmentId,
        title: title.trim(),
        supervisorUserId: supervisorUserId || undefined,
      });
      Toast.success({ content: "员工档案已关联。" });
      router.push(`/admin/employees/${userId}`);
    } catch {
      Toast.error({ content: "关联失败，请重试。" });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <Link href="/admin/employees" className={styles.backLink}>
        ← 返回员工列表
      </Link>

      <PageHeader
        eyebrow="Workforce"
        title="关联员工档案"
        description="为既有统一账户建立员工档案。员工档案始终关联到稳定的 userId，不会创建新账户。"
      />

      <div className={styles.tabContent}>
        <div className={`${styles.notice} ${styles.noticeInfo}`} style={{ marginBottom: 20 }}>
          <div>
            <strong>关联原则</strong>
            员工档案关联到已有的统一账户。外部用户升级为员工时，相同的 userId 保持不变，
            消费者人格和功能保留。不会仅凭邮箱或域名自动合并账户。
          </div>
        </div>

        <form onSubmit={handleSubmit} className={styles.linkForm}>
          <label className={styles.formField}>
            <span>用户 *</span>
            <select
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              className="semi-input semi-input-default"
              style={{ width: "100%" }}
              aria-label="选择用户"
            >
              <option value="">请选择用户</option>
              {eligibleUsers.map((user) => (
                <option key={user.userId} value={user.userId}>
                  {user.displayName} · {user.email} · {user.userId}
                </option>
              ))}
            </select>
            {errors.userId && <small style={{ color: "var(--up-danger)" }}>{errors.userId}</small>}
          </label>

          <label className={styles.formField}>
            <span>部门 *</span>
            <select
              value={departmentId}
              onChange={(e) => setDepartmentId(e.target.value)}
              className="semi-input semi-input-default"
              style={{ width: "100%" }}
              aria-label="选择部门"
            >
              <option value="">请选择部门</option>
              {departments.map((dept) => (
                <option key={dept.departmentId} value={dept.departmentId}>
                  {dept.name}
                  {dept.parentName ? `（上级：${dept.parentName}）` : ""}
                </option>
              ))}
            </select>
            {errors.departmentId && <small style={{ color: "var(--up-danger)" }}>{errors.departmentId}</small>}
          </label>

          <label className={styles.formField}>
            <span>职位 *</span>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="例如：产品设计师"
              className="semi-input semi-input-default"
              style={{ width: "100%" }}
              aria-label="职位名称"
            />
            {errors.title && <small style={{ color: "var(--up-danger)" }}>{errors.title}</small>}
          </label>

          <label className={styles.formField}>
            <span>主管（可选）</span>
            <select
              value={supervisorUserId}
              onChange={(e) => setSupervisorUserId(e.target.value)}
              className="semi-input semi-input-default"
              style={{ width: "100%" }}
              aria-label="选择主管"
            >
              <option value="">不指定</option>
              {eligibleUsers
                .filter((u) => u.userId !== userId)
                .map((user) => (
                  <option key={user.userId} value={user.userId}>
                    {user.displayName} · {user.email}
                  </option>
                ))}
            </select>
            <small>主管需为系统中已有关联员工档案的用户。</small>
          </label>

          <div className={styles.formActions}>
            <Link href="/admin/employees">
              <Button theme="borderless">取消</Button>
            </Link>
            <Button
              type="primary"
              theme="solid"
              htmlType="submit"
              loading={submitting}
              disabled={submitting}
            >
              确认关联
            </Button>
          </div>
        </form>
      </div>
    </>
  );
}
