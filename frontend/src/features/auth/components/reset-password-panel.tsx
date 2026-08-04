"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import Link from "next/link";
import { Banner, Button, Input, Spin } from "@douyinfe/semi-ui";
import { IconKey, IconTick, IconAlertTriangle, IconHourglass } from "@douyinfe/semi-icons";
import type { PasswordResetResult } from "@/features/auth/types";
import styles from "./credential-panel.module.css";

type ResetPasswordPanelProps = {
  token: string;
};

type ResetPhase =
  | { phase: "form" }
  | { phase: "submitting" }
  | { phase: "success" }
  | { phase: "error"; result: Extract<PasswordResetResult, { status: "invalid_token" | "expired_token" | "rate_limited" }> };

const PASSWORD_MIN_LENGTH = 12;

const TOKEN_HINTS = [
  { token: "demo-reset-valid", label: "有效令牌" },
  { token: "demo-reset-expired", label: "令牌已过期" },
  { token: "demo-reset-invalid", label: "令牌无效" },
  { token: "demo-reset-rate", label: "请求过于频繁" },
];

function resolveMockReset(token: string): PasswordResetResult {
  const normalized = token.toLowerCase();
  if (normalized.includes("expired")) {
    return { status: "expired_token" };
  }
  if (normalized.includes("invalid")) {
    return { status: "invalid_token" };
  }
  if (normalized.includes("rate")) {
    return { status: "rate_limited", retryAfter: 60 };
  }
  return { status: "success" };
}

export function ResetPasswordPanel({ token }: ResetPasswordPanelProps) {
  const [phase, setPhase] = useState<ResetPhase>({ phase: "form" });
  const [passwordError, setPasswordError] = useState<string>();
  const [confirmPasswordError, setConfirmPasswordError] = useState<string>();

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);
    const password = formData.get("password");
    const confirmPassword = formData.get("confirmPassword");

    if (typeof password !== "string" || password.length < PASSWORD_MIN_LENGTH) {
      setPasswordError(`密码至少需要 ${PASSWORD_MIN_LENGTH} 个字符。`);
      return;
    }

    if (password !== confirmPassword) {
      setConfirmPasswordError("两次输入的密码不一致，请重新确认。");
      return;
    }

    setPasswordError(undefined);
    setConfirmPasswordError(undefined);
    setPhase({ phase: "submitting" });

    const result = resolveMockReset(token);
    const isFailure = result.status !== "success";
    window.setTimeout(() => {
      if (isFailure) {
        setPhase({ phase: "error", result });
      } else {
        setPhase({ phase: "success" });
      }
    }, 700);
  }

  if (phase.phase === "success") {
    return (
      <div className={styles.panel}>
        <div className={styles.statusCard} role="status" aria-live="polite">
          <div className={styles.statusCard}>
            <IconTick size="extra-large" style={{ color: "var(--up-success)" }} />
            <h1>密码已重置</h1>
            <p>你的账户密码已成功更新。请使用新密码登录。</p>
          </div>
          <div className={styles.actions}>
            <Link href="/login">
              <Button theme="solid" type="primary" size="large" block>返回登录</Button>
            </Link>
          </div>
        </div>
        <p className={styles.notice}>当前为界面 mock，不会修改任何真实账户凭据。</p>
      </div>
    );
  }

  if (phase.phase === "error") {
    const { result } = phase;
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          <span className={styles.mockBadge}>MOCK PREVIEW</span>
          <h1>无法重置密码</h1>
          <p>密码重置链接存在问题，请根据以下提示处理。</p>
        </div>
        {result.status === "expired_token" && (
          <div role="alert">
            <Banner
              type="warning"
              icon={<IconHourglass />}
              description="该密码重置链接已过期。请重新申请重置密码以获取新的链接。"
            />
          </div>
        )}
        {result.status === "invalid_token" && (
          <div role="alert">
            <Banner
              type="danger"
              icon={<IconAlertTriangle />}
              description="该密码重置链接无效或已被使用。请确认链接完整，或重新申请重置密码。"
            />
          </div>
        )}
        {result.status === "rate_limited" && (
          <div role="alert">
            <Banner
              type="warning"
              icon={<IconHourglass />}
              description={`操作过于频繁，请在 ${result.retryAfter} 秒后再试。`}
            />
          </div>
        )}
        <div className={styles.actions}>
          <Link href="/forgot-password">
            <Button theme="solid" type="primary" size="large" block>重新申请重置密码</Button>
          </Link>
        </div>
        <p className={styles.notice}>当前为界面 mock，不会修改任何真实账户凭据。</p>
        <ResetDemoLinks currentToken={token} />
      </div>
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <span className={styles.mockBadge}>MOCK PREVIEW</span>
        <h1>设置新密码</h1>
        <p>为你的统一门户账户设置一个新的登录密码。</p>
      </div>

      <form className={styles.form} onSubmit={handleSubmit}>
        <label className={styles.field}>
          <span>新密码</span>
          <Input
            name="password"
            mode="password"
            size="large"
            prefix={<IconKey />}
            placeholder="至少 12 个字符"
            autoComplete="new-password"
            minLength={PASSWORD_MIN_LENGTH}
            validateStatus={passwordError ? "error" : "default"}
            aria-invalid={Boolean(passwordError)}
            aria-errormessage={passwordError ? "reset-password-error" : undefined}
            onChange={() => setPasswordError(undefined)}
            disabled={phase.phase === "submitting"}
            required
          />
          <small>至少 {PASSWORD_MIN_LENGTH} 个字符，请勿使用其他服务的密码。</small>
          {passwordError && (
            <small id="reset-password-error" className={styles.fieldError} role="alert">
              {passwordError}
            </small>
          )}
        </label>
        <label className={styles.field}>
          <span>确认新密码</span>
          <Input
            name="confirmPassword"
            mode="password"
            size="large"
            prefix={<IconKey />}
            placeholder="再次输入新密码"
            autoComplete="new-password"
            minLength={PASSWORD_MIN_LENGTH}
            validateStatus={confirmPasswordError ? "error" : "default"}
            aria-invalid={Boolean(confirmPasswordError)}
            aria-errormessage={confirmPasswordError ? "reset-confirm-password-error" : undefined}
            onChange={() => setConfirmPasswordError(undefined)}
            disabled={phase.phase === "submitting"}
            required
          />
          {confirmPasswordError && (
            <small id="reset-confirm-password-error" className={styles.fieldError} role="alert">
              {confirmPasswordError}
            </small>
          )}
        </label>

        <Button
          htmlType="submit"
          type="primary"
          theme="solid"
          size="large"
          block
          disabled={phase.phase === "submitting"}
          loading={phase.phase === "submitting"}
        >
          {phase.phase === "submitting" ? "正在重置…" : "重置密码（Mock）"}
        </Button>
      </form>

      {phase.phase === "submitting" && (
        <div className={styles.loadingBlock} aria-hidden="true">
          <Spin />
          <span>正在校验重置链接并更新密码…</span>
        </div>
      )}

      <p className={styles.notice}>当前为界面 mock，不会提交密码或修改任何账户凭据。</p>
      <p className={styles.switchMode}>
        已想起密码？<Link href="/login">返回登录</Link>
      </p>
      <ResetDemoLinks currentToken={token} />
    </div>
  );
}

function ResetDemoLinks({ currentToken }: { currentToken: string }) {
  return (
    <div className={styles.demoLinks}>
      <p>Mock 状态演示（点击切换 token）</p>
      <ul>
        {TOKEN_HINTS.map((hint) => (
          <li key={hint.token}>
            {hint.token === currentToken ? "→ " : ""}
            <Link href={`/reset-password?token=${encodeURIComponent(hint.token)}`}>
              <code>{hint.token}</code> — {hint.label}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
