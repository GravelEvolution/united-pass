"use client";

import Link from "next/link";
import { Button, Card, Empty, Tag } from "@douyinfe/semi-ui";
import { PageHeader } from "@/components/common/page-header";
import type { DreamUPEventSummary } from "../types";
import styles from "./dreamup-admin.module.css";

const roleLabels = {
  admin: "管理员",
  senior_admin: "高级管理员",
  super_admin: "超级管理员",
} as const;

export function DreamUPEventDirectory({ events }: { events: DreamUPEventSummary[] }) {
  return (
    <>
      <PageHeader
        eyebrow="MoonStone DreamUP"
        title="上海站活动管理"
        description="查看报名、提交本人审核意见，并通过三名管理员的独立同意形成录取结果。"
      />
      {events.length === 0 ? (
        <Empty title="没有可管理的活动" description="活动权限由后端按活动范围授予。" />
      ) : (
        <section className={styles.eventGrid} aria-label="获授权活动">
          {events.map((event) => (
            <Card key={event.eventId} className={styles.eventCard} shadows="hover">
              <div className={styles.cardHeading}>
                <div>
                  <span>上海 · 2026</span>
                  <h2>{event.displayName}</h2>
                </div>
                {event.role && <Tag color="blue">{roleLabels[event.role]}</Tag>}
              </div>
              {event.counts && (
                <dl className={styles.countGrid}>
                  <div><dt>报名</dt><dd>{event.counts.total}</dd></div>
                  <div><dt>待审核</dt><dd>{event.counts.pending}</dd></div>
                  <div><dt>已录取</dt><dd>{event.counts.accepted}</dd></div>
                  <div><dt>已拒绝</dt><dd>{event.counts.rejected}</dd></div>
                </dl>
              )}
              <Link href={`/admin/dreamup/${encodeURIComponent(event.eventId)}`}>
                <Button block theme="solid" type="primary">进入报名审核</Button>
              </Link>
            </Card>
          ))}
        </section>
      )}
    </>
  );
}
