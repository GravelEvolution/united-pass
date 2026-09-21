//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Post-logout redirect handler
//

"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Banner, Button, Spin } from "@douyinfe/semi-ui";
import { browserCommands } from "@/lib/api/browser/browser-commands";
import { isApiError } from "@/lib/api/api-error";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";
import styles from "./credential-panel.module.css";

const LOGOUT_REDIRECT_DELAY_MS = 800;

export function LogoutRedirect() {
  const router = useRouter();
  const started = useRef(false);
  const [failed, setFailed] = useState(false);

  const logout = useCallback(async (): Promise<void> => {
    setFailed(false);
    if (USE_MOCK_DATA_SOURCE) {
      window.setTimeout(() => router.replace("/login"), LOGOUT_REDIRECT_DELAY_MS);
      return;
    }

    try {
      await browserCommands.logout();
      router.replace("/login");
      router.refresh();
    } catch (error) {
      if (isApiError(error) && error.kind === "unauthorized") {
        router.replace("/login");
        router.refresh();
        return;
      }
      setFailed(true);
    }
  }, [router]);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void logout();
  }, [logout]);

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        {USE_MOCK_DATA_SOURCE && <span className={styles.mockBadge}>MOCK PREVIEW</span>}
        <h1>正在退出登录</h1>
        <p>正在清除当前会话，请稍候。</p>
      </div>
      {failed ? (
        <div className={styles.statusCard} role="alert">
          <Banner
            type="danger"
            fullMode={false}
            bordered
            closeIcon={null}
            description="退出登录失败，当前会话可能仍然有效。请重试。"
          />
          <div className={styles.actions}>
            <Button type="primary" theme="solid" onClick={() => void logout()}>
              重试退出
            </Button>
          </div>
        </div>
      ) : (
        <div className={styles.loadingBlock} role="status" aria-live="polite">
          <Spin size="large" />
          <span>正在退出登录…</span>
        </div>
      )}
      {USE_MOCK_DATA_SOURCE && <p className={styles.notice}>当前为界面 mock，不会撤销任何真实会话。</p>}
    </div>
  );
}
