//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Active session list UI
//

"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, Popconfirm, Toast } from "@douyinfe/semi-ui";
import { IconDelete } from "@douyinfe/semi-icons";
import { PageHeader } from "@/components/common/page-header";
import { StatusBadge } from "@/components/common/status-badge";
import type { UserSession } from "@/features/account/types";
import { formatSecurityDateTime } from "@/lib/utils/date-time";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { isApiError } from "@/lib/api/api-error";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";
import styles from "./account-panels.module.css";

type SessionListProps = {
  sessions: UserSession[];
};

export function SessionList({ sessions: initialSessions }: SessionListProps) {
  const router = useRouter();
  const [mockSessions, setMockSessions] = useState<UserSession[]>(initialSessions);
  const displayedSessions = USE_MOCK_DATA_SOURCE ? mockSessions : initialSessions;
  const [revokingId, setRevokingId] = useState<string | null>(null);

  async function handleRevoke(sessionId: string): Promise<void> {
    setRevokingId(sessionId);
    try {
      await browserCommands.revokeOwnSession(sessionId);
      Toast.success({ content: "会话已撤销。" });
      if (USE_MOCK_DATA_SOURCE) {
        setMockSessions((current) => current.filter((session) => session.sessionId !== sessionId));
      } else {
        router.refresh();
      }
    } catch (error) {
      if (isApiError(error) && error.kind === "not_found") {
        Toast.info({ content: "该会话已不存在，正在刷新列表。" });
        router.refresh();
        return;
      }
      Toast.error({ content: "撤销会话失败，请稍后重试。" });
    } finally {
      setRevokingId(null);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Active sessions"
        title="活跃会话"
        description="核对登录设备、最近活动与大致位置。IP 地址仅显示脱敏值。"
      />
      <section className={styles.card}>
        <div className={styles.sessionList}>
          {displayedSessions.map((session) => {
            const deviceName = session.deviceName || "未知设备";
            const clientName = session.clientName || "未知浏览器";
            const approximateLocation = session.approximateLocation || "未知位置";
            const ipAddressMasked = session.ipAddressMasked || "未知 IP";
            return (
              <article key={session.sessionId} className={styles.sessionRow}>
                <div className={styles.deviceIcon} aria-hidden="true">{deviceName.includes("iPhone") ? "M" : "D"}</div>
                <div className={styles.sessionCopy}>
                  <div className={styles.sessionTitle}>
                    <h2>{deviceName}</h2>
                    {session.isCurrent && <StatusBadge label="当前设备" tone="success" />}
                  </div>
                  <p>{clientName}</p>
                  <span>{approximateLocation} · {ipAddressMasked} · {formatSecurityDateTime(session.lastActiveAt)}</span>
                </div>
                {!session.isCurrent && (
                  <Popconfirm
                    title={`撤销 ${deviceName} 的会话？`}
                    content="该设备上的登录会话将立即失效，用户需要重新登录。"
                    type="warning"
                    onConfirm={() => handleRevoke(session.sessionId)}
                    disabled={revokingId === session.sessionId}
                  >
                    <Button
                      type="danger"
                      theme="outline"
                      icon={<IconDelete />}
                      loading={revokingId === session.sessionId}
                      disabled={revokingId === session.sessionId}
                    >
                      撤销会话
                    </Button>
                  </Popconfirm>
                )}
              </article>
            );
          })}
        </div>
      </section>
    </>
  );
}
