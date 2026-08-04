"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Spin } from "@douyinfe/semi-ui";
import styles from "./credential-panel.module.css";

const LOGOUT_REDIRECT_DELAY_MS = 800;

export function LogoutRedirect() {
  const router = useRouter();

  useEffect(() => {
    // Mock logout: a real implementation would call the backend session
    // revocation endpoint, clear cookies, and only then redirect. Here we
    // simulate the brief delay before returning to the login screen.
    const timer = window.setTimeout(() => {
      router.replace("/login");
    }, LOGOUT_REDIRECT_DELAY_MS);

    return () => window.clearTimeout(timer);
  }, [router]);

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <span className={styles.mockBadge}>MOCK PREVIEW</span>
        <h1>正在退出登录</h1>
        <p>正在清除当前会话，请稍候。</p>
      </div>
      <div className={styles.loadingBlock} role="status" aria-live="polite">
        <Spin size="large" />
        <span>正在退出登录…</span>
      </div>
      <p className={styles.notice}>当前为界面 mock，不会撤销任何真实会话。</p>
    </div>
  );
}
