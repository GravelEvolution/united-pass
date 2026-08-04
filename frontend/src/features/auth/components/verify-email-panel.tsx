"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Banner, Button, Spin } from "@douyinfe/semi-ui";
import { IconMail, IconTick, IconAlertTriangle, IconHourglass } from "@douyinfe/semi-icons";
import type { EmailVerificationResult } from "@/features/auth/types";
import styles from "./credential-panel.module.css";

type VerifyEmailPanelProps = {
  token: string;
};

type VerifyPhase =
  | { phase: "verifying" }
  | { phase: "success" }
  | { phase: "error"; result: Extract<EmailVerificationResult, { status: "invalid_token" | "expired_token" }> };

const VERIFY_DELAY_MS = 900;

const TOKEN_HINTS = [
  { token: "demo-verify-valid", label: "有效令牌" },
  { token: "demo-verify-expired", label: "令牌已过期" },
  { token: "demo-verify-invalid", label: "令牌无效" },
];

function resolveMockVerification(token: string): EmailVerificationResult {
  const normalized = token.toLowerCase();
  if (normalized.includes("expired")) {
    return { status: "expired_token" };
  }
  if (normalized.includes("invalid")) {
    return { status: "invalid_token" };
  }
  return { status: "success" };
}

/**
 * Outer panel. Remounts the inner verifier whenever the token changes so the
 * "verifying" state resets cleanly without calling setState synchronously
 * inside an effect.
 */
export function VerifyEmailPanel({ token }: VerifyEmailPanelProps) {
  return <VerifyEmailPanelInner key={token} token={token} />;
}

function VerifyEmailPanelInner({ token }: VerifyEmailPanelProps) {
  const [phase, setPhase] = useState<VerifyPhase>({ phase: "verifying" });

  useEffect(() => {
    const result = resolveMockVerification(token);
    const timer = window.setTimeout(() => {
      if (result.status === "success") {
        setPhase({ phase: "success" });
      } else {
        setPhase({ phase: "error", result });
      }
    }, VERIFY_DELAY_MS);

    return () => window.clearTimeout(timer);
  }, [token]);

  if (phase.phase === "verifying") {
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          <span className={styles.mockBadge}>MOCK PREVIEW</span>
          <h1>正在验证邮箱</h1>
          <p>正在校验验证链接，请稍候。</p>
        </div>
        <div className={styles.loadingBlock} role="status" aria-live="polite">
          <Spin size="large" />
          <span>正在验证 <code>{token}</code> …</span>
        </div>
        <p className={styles.notice}>当前为界面 mock，不会变更任何账户的邮箱验证状态。</p>
      </div>
    );
  }

  if (phase.phase === "success") {
    return (
      <div className={styles.panel}>
        <div className={styles.statusCard} role="status" aria-live="polite">
          <div className={styles.statusCard}>
            <IconTick size="extra-large" style={{ color: "var(--up-success)" }} />
            <h1>邮箱验证成功</h1>
            <p>你的邮箱地址已完成验证，现在可以使用该邮箱登录并接收账户通知。</p>
          </div>
          <div className={styles.actions}>
            <Link href="/login">
              <Button theme="solid" type="primary" size="large" block>返回登录</Button>
            </Link>
          </div>
        </div>
        <p className={styles.notice}>当前为界面 mock，不会变更任何账户的邮箱验证状态。</p>
        <VerifyDemoLinks currentToken={token} />
      </div>
    );
  }

  const { result } = phase;
  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <span className={styles.mockBadge}>MOCK PREVIEW</span>
        <h1>无法验证邮箱</h1>
        <p>邮箱验证链接存在问题，请根据以下提示处理。</p>
      </div>
      {result.status === "expired_token" && (
        <div role="alert">
          <Banner
            type="warning"
            icon={<IconHourglass />}
            description="该邮箱验证链接已过期。请在账户安全中心重新发送验证邮件以获取新的链接。"
          />
        </div>
      )}
      {result.status === "invalid_token" && (
        <div role="alert">
          <Banner
            type="danger"
            icon={<IconAlertTriangle />}
            description="该邮箱验证链接无效或已被使用。请确认链接完整，或重新发送验证邮件。"
          />
        </div>
      )}
      <div className={styles.actions}>
        <Link href="/login">
          <Button theme="solid" type="primary" size="large" block>返回登录</Button>
        </Link>
      </div>
      <p className={styles.notice}>当前为界面 mock，不会变更任何账户的邮箱验证状态。</p>
      <VerifyDemoLinks currentToken={token} />
    </div>
  );
}

function VerifyDemoLinks({ currentToken }: { currentToken: string }) {
  return (
    <div className={styles.demoLinks}>
      <p>Mock 状态演示（点击切换 token）</p>
      <ul>
        {TOKEN_HINTS.map((hint) => (
          <li key={hint.token}>
            {hint.token === currentToken ? "→ " : ""}
            <Link href={`/verify-email?token=${encodeURIComponent(hint.token)}`}>
              <code>{hint.token}</code> — {hint.label}
            </Link>
          </li>
        ))}
      </ul>
      <p className={styles.demoNote}>
        <IconMail aria-hidden="true" />
        未收到邮件？请在登录后于账户安全中心重新发送验证邮件。
      </p>
    </div>
  );
}
