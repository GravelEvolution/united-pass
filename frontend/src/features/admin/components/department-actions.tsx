//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-11
// Description: Real Phase 5 department create, edit and delete controls
//

"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, Modal, Popconfirm, Toast } from "@douyinfe/semi-ui";
import type {
  DepartmentDetail,
  DepartmentInput,
  DepartmentRecord,
  EmployeeRecord,
} from "@/features/admin/types";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import styles from "./admin-detail.module.css";

type DepartmentMutationFormProps = {
  initial?: DepartmentInput;
  departments: DepartmentRecord[];
  employees: EmployeeRecord[];
  excludeDepartmentId?: string;
  submitting: boolean;
  submitLabel: string;
  onCancel: () => void;
  onSubmit: (input: DepartmentInput) => Promise<void>;
};

function DepartmentMutationForm({
  initial,
  departments,
  employees,
  excludeDepartmentId,
  submitting,
  submitLabel,
  onCancel,
  onSubmit,
}: DepartmentMutationFormProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [parentDepartmentId, setParentDepartmentId] = useState(initial?.parentDepartmentId ?? "");
  const [ownerUserId, setOwnerUserId] = useState(initial?.ownerUserId ?? "");

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!name.trim()) return;
    await onSubmit({
      name: name.trim(),
      parentDepartmentId: parentDepartmentId || undefined,
      ownerUserId: ownerUserId || undefined,
    });
  }

  return (
    <form method="post" className={styles.linkForm} onSubmit={handleSubmit}>
      <label className={styles.formField}>
        <span>部门名称 *</span>
        <input
          value={name}
          onChange={(event) => setName(event.target.value)}
          maxLength={120}
          required
          autoFocus
        />
      </label>
      <label className={styles.formField}>
        <span>上级部门</span>
        <select
          value={parentDepartmentId}
          onChange={(event) => setParentDepartmentId(event.target.value)}
        >
          <option value="">无（顶级部门）</option>
          {departments
            .filter((department) => department.departmentId !== excludeDepartmentId)
            .map((department) => (
              <option key={department.departmentId} value={department.departmentId}>
                {department.name}
              </option>
            ))}
        </select>
      </label>
      <label className={styles.formField}>
        <span>负责人</span>
        <select value={ownerUserId} onChange={(event) => setOwnerUserId(event.target.value)}>
          <option value="">不指定</option>
          {employees
            .filter((employee) => employee.status === "active")
            .map((employee) => (
              <option key={employee.userId} value={employee.userId}>
                {employee.displayName} · {employee.employeeId}
              </option>
            ))}
        </select>
      </label>
      <div className={styles.formActions}>
        <Button theme="outline" onClick={onCancel} disabled={submitting}>取消</Button>
        <Button
          htmlType="submit"
          theme="solid"
          type="primary"
          loading={submitting}
          disabled={submitting || !name.trim()}
        >
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}

export function DepartmentCreateButton({
  departments,
  employees,
}: {
  departments: DepartmentRecord[];
  employees: EmployeeRecord[];
}) {
  const router = useRouter();
  const [visible, setVisible] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function create(input: DepartmentInput): Promise<void> {
    setSubmitting(true);
    try {
      const detail = await browserCommands.createDepartment(input);
      Toast.success({ content: "部门已创建。" });
      setVisible(false);
      router.push(`/admin/departments/${detail.departmentId}`);
    } catch {
      Toast.error({ content: "创建失败，请检查同级名称、负责人和上级部门。" });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <Button theme="solid" type="primary" onClick={() => setVisible(true)}>创建部门</Button>
      <Modal
        title="创建部门"
        visible={visible}
        footer={null}
        onCancel={() => {
          if (!submitting) setVisible(false);
        }}
        maskClosable={false}
      >
        {visible && (
          <DepartmentMutationForm
            departments={departments}
            employees={employees}
            submitting={submitting}
            submitLabel="创建"
            onCancel={() => setVisible(false)}
            onSubmit={create}
          />
        )}
      </Modal>
    </>
  );
}

export function DepartmentManageActions({
  detail,
  departments,
  employees,
}: {
  detail: DepartmentDetail;
  departments: DepartmentRecord[];
  employees: EmployeeRecord[];
}) {
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [deleting, setDeleting] = useState(false);

  async function update(input: DepartmentInput): Promise<void> {
    setSubmitting(true);
    try {
      await browserCommands.updateDepartment(detail.departmentId, {
        name: input.name,
        parentDepartmentId: input.parentDepartmentId ?? null,
        ownerUserId: input.ownerUserId ?? null,
      });
      Toast.success({ content: "部门已更新。" });
      setEditing(false);
      router.refresh();
    } catch {
      Toast.error({ content: "更新失败；不能形成循环，负责人必须为在职员工。" });
    } finally {
      setSubmitting(false);
    }
  }

  async function remove(): Promise<void> {
    setDeleting(true);
    try {
      await browserCommands.deleteDepartment(detail.departmentId);
      Toast.success({ content: "空部门已删除。" });
      router.push("/admin/departments");
    } catch {
      Toast.error({ content: "删除失败；请先移走成员并删除所有子部门。" });
    } finally {
      setDeleting(false);
    }
  }

  return (
    <>
      <div className={styles.formActions}>
        <Button theme="outline" onClick={() => setEditing(true)}>编辑部门</Button>
        <Popconfirm
          title={`删除部门“${detail.name}”？`}
          content="只有没有成员和子部门的空部门可以删除。"
          type="warning"
          onConfirm={remove}
          disabled={deleting}
        >
          <Button theme="solid" type="danger" loading={deleting}>删除部门</Button>
        </Popconfirm>
      </div>
      <Modal
        title="编辑部门"
        visible={editing}
        footer={null}
        onCancel={() => {
          if (!submitting) setEditing(false);
        }}
        maskClosable={false}
      >
        {editing && (
          <DepartmentMutationForm
            initial={{
              name: detail.name,
              parentDepartmentId: detail.parentDepartmentId ?? undefined,
              ownerUserId: detail.ownerUserId ?? undefined,
            }}
            departments={departments}
            employees={employees}
            excludeDepartmentId={detail.departmentId}
            submitting={submitting}
            submitLabel="保存"
            onCancel={() => setEditing(false)}
            onSubmit={update}
          />
        )}
      </Modal>
    </>
  );
}
