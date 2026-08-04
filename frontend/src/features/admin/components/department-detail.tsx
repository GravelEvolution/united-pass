"use client";

import Link from "next/link";
import { Empty } from "@douyinfe/semi-ui";
import { StatusBadge } from "@/components/common/status-badge";
import { PageHeader } from "@/components/common/page-header";
import type { DepartmentDetail } from "@/features/admin/types";
import styles from "./admin-detail.module.css";

type DepartmentDetailProps = {
  detail: DepartmentDetail;
};

export function DepartmentDetail({ detail }: DepartmentDetailProps) {
  return (
    <>
      <Link href="/admin/departments" className={styles.backLink}>
        ← 返回部门列表
      </Link>

      <PageHeader
        eyebrow="Organization"
        title={detail.name}
        description={`部门 ID：${detail.departmentId}`}
      />

      <div className={styles.headerCard}>
        <div className={styles.headerInfo}>
          <h1>{detail.name}</h1>
          <p>
            {detail.parentName ? `上级部门：${detail.parentName}` : "顶级部门"}
            {" · "}负责人：{detail.ownerName}
          </p>
        </div>
        <div className={styles.headerMeta}>
          <span>成员：{detail.memberCount} 人</span>
          <StatusBadge label="正常" tone="success" />
        </div>
      </div>

      <div className={styles.tabContent}>
        <dl className={styles.descriptionList}>
          <dt>部门 ID</dt>
          <dd><code>{detail.departmentId}</code></dd>

          <dt>部门名称</dt>
          <dd>{detail.name}</dd>

          <dt>上级部门</dt>
          <dd>{detail.parentName ?? "无（顶级部门）"}</dd>

          <dt>负责人</dt>
          <dd>{detail.ownerName}</dd>

          <dt>成员总数</dt>
          <dd>{detail.memberCount} 人</dd>
        </dl>

        {detail.childDepartments.length > 0 && (
          <div className={styles.section} style={{ marginTop: 24 }}>
            <h3>子部门</h3>
            {detail.childDepartments.map((child) => (
              <Link
                key={child.departmentId}
                href={`/admin/departments/${child.departmentId}`}
                className={styles.dangerItem}
                style={{ textDecoration: "none" }}
              >
                <div>
                  <strong>{child.name}</strong>
                  <p>{child.memberCount} 人</p>
                </div>
              </Link>
            ))}
          </div>
        )}

        <div className={styles.section} style={{ marginTop: 24 }}>
          <h3>成员列表</h3>
          {detail.members.length === 0 ? (
            <Empty title="暂无成员" description="该部门尚未有成员。" />
          ) : (
            detail.members.map((member) => (
              <div key={member.userId} className={styles.dangerItem}>
                <div>
                  <strong>{member.displayName}</strong>
                  <p>{member.employeeId} · {member.title}</p>
                </div>
                <Link href={`/admin/users/${member.userId}`}>
                  查看用户
                </Link>
              </div>
            ))
          )}
        </div>
      </div>
    </>
  );
}
