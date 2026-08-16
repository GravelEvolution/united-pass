//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Real one-time registration email verification panel
//

"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Banner, Button, Spin } from "@douyinfe/semi-ui";
import { IconTick, IconAlertTriangle, IconHourglass } from "@douyinfe/semi-icons";
import { isApiError } from "@/lib/api/api-error";
import { verifyAccountEmail } from "@/lib/api/browser/auth-commands";
import styles from "./credential-panel.module.css";

type VerifyEmailPanelProps = {
  token: string;
  code: string;
};

type VerifyPhase =
  | { phase: "verifying" }
  | { phase: "success" }
  | { phase: "error"; failure: "invalid" | "expired" | "rate_limited" | "unavailable"; message?: string };

export function VerifyEmailPanel({ token, code }: VerifyEmailPanelProps) {
  return <VerifyEmailPanelInner key={`${token}:${code}`} token={token} code={code} />;
}

function VerifyEmailPanelInner({ token, code }: VerifyEmailPanelProps) {
  const [phase, setPhase] = useState<VerifyPhase>({ phase: "verifying" });

  useEffect(() => {
    const controller = new AbortController();
    void verifyAccountEmail({ token, code }, controller.signal)
      .then(() => setPhase({ phase: "success" }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        if (isApiError(error)) {
          if (error.code === "auth.lifecycle_token_expired") {
            setPhase({ phase: "error", failure: "expired" });
          } else if (error.code === "auth.lifecycle_token_invalid" || error.kind === "validation") {
            setPhase({ phase: "error", failure: "invalid" });
          } else if (error.kind === "rate_limited") {
            setPhase({ phase: "error", failure: "rate_limited", message: error.message });
          } else {
            setPhase({ phase: "error", failure: "unavailable" });
          }
        } else {
          setPhase({ phase: "error", failure: "unavailable" });
        }
      });
    return () => controller.abort();
  }, [token, code]);

  if (phase.phase === "verifying") {
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          <h1>正在验证邮箱</h1>
          <p>正在向身份提供方校验一次性验证链接，请稍候。</p>
        </div>
        <div className={styles.loadingBlock} role="status" aria-live="polite">
          <Spin size="large" />
          <span>正在验证并激活账户…</span>
        </div>
      </div>
    );
  }

  if (phase.phase === "success") {
    return (
      <div className={styles.panel}>
        <div className={styles.statusCard} role="status" aria-live="polite">
          <IconTick size="extra-large" style={{ color: "var(--up-success)" }} />
          <h1>邮箱验证成功</h1>
          <p>账户已激活，现在可以使用账户名或已验证邮箱登录。</p>
        </div>
        <div className={styles.actions}>
          <Link href="/login">
            <Button theme="solid" type="primary" size="large" block>前往登录</Button>
          </Link>
        </div>
      </div>
    );
  }

  const descriptions = {
    invalid: "该邮箱验证链接无效或已被使用。请确认链接完整。",
    expired: "该邮箱验证链接已过期，请重新注册或联系管理员获取帮助。",
    rate_limited: phase.message ?? "操作过于频繁，请稍后再试。",
    unavailable: "身份提供方或账户激活服务暂时不可用，请稍后重新打开此链接。",
  } as const;

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <h1>无法验证邮箱</h1>
        <p>邮箱验证链接或服务状态存在问题。</p>
      </div>
      <div role="alert">
        <Banner
          type={phase.failure === "invalid" ? "danger" : "warning"}
          icon={phase.failure === "expired" || phase.failure === "rate_limited" ? <IconHourglass /> : <IconAlertTriangle />}
          description={descriptions[phase.failure]}
        />
      </div>
      <div className={styles.actions}>
        <Link href="/login">
          <Button theme="solid" type="primary" size="large" block>返回登录</Button>
        </Link>
      </div>
    </div>
  );
}
