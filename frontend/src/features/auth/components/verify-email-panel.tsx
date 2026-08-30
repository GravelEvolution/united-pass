"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Banner, Button, Spin } from "@douyinfe/semi-ui";
import { IconAlertTriangle } from "@douyinfe/semi-icons";
import { verifyRegistrationEmail } from "@/lib/api/browser/registration-commands";
import styles from "./credential-panel.module.css";

type VerifyPhase = "verifying" | "error";

export function VerifyEmailPanel() {
  const router = useRouter();
  const started = useRef(false);
  const [phase, setPhase] = useState<VerifyPhase>("verifying");

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const userId = fragment.get("userId") ?? "";
    const code = fragment.get("code") ?? "";
    const requestId = fragment.get("requestId") ?? "";

    // Erase the one-time code before validation, rendering, network work, or
    // navigation. Fragments never reach HTTP/nginx logs, and this prevents it
    // from lingering in browser history or accidental screenshots.
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);

    async function verify() {
      if (!userId || !code) {
        throw new TypeError("Email verification fragment is incomplete");
      }
      return verifyRegistrationEmail({ userId, code, requestId });
    }

    void verify()
      .then((result) => {
        const destination = result.requestId
          ? `/login?requestId=${encodeURIComponent(result.requestId)}`
          : "/login";
        router.replace(destination);
      })
      .catch(() => setPhase("error"));
  }, [router]);

  if (phase === "verifying") {
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          <h1>正在验证邮箱</h1>
          <p>正在安全地启用你的统一账户，请稍候。</p>
        </div>
        <div className={styles.loadingBlock} role="status" aria-live="polite">
          <Spin size="large" />
          <span>正在验证…</span>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <h1>无法验证邮箱</h1>
        <p>验证链接无效、已失效或已被使用。</p>
      </div>
      <Banner
        type="danger"
        icon={<IconAlertTriangle />}
        description="请使用最新一封验证邮件中的完整链接，或返回注册页重新开始。"
      />
      <div className={styles.actions}>
        <Link href="/register"><Button theme="solid" type="primary" size="large" block>返回注册</Button></Link>
        <Link href="/login"><Button size="large" block>返回登录</Button></Link>
      </div>
    </div>
  );
}
