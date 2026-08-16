//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-16
// Description: Real one-time password reset panel
//

"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import Link from "next/link";
import { Banner, Button, Input, Spin } from "@douyinfe/semi-ui";
import { IconKey, IconTick, IconAlertTriangle, IconHourglass } from "@douyinfe/semi-icons";
import { isApiError } from "@/lib/api/api-error";
import { resetAccountPassword } from "@/lib/api/browser/auth-commands";
import styles from "./credential-panel.module.css";

type ResetPasswordPanelProps = {
  token: string;
  code: string;
};

type ResetFailure = "invalid" | "expired" | "rate_limited" | "rejected" | "unavailable";

type ResetPhase =
  | { phase: "form" }
  | { phase: "submitting" }
  | { phase: "success" }
  | { phase: "error"; failure: ResetFailure; message?: string; retryAfter?: number };

const PASSWORD_MIN_LENGTH = 12;

export function ResetPasswordPanel({ token, code }: ResetPasswordPanelProps) {
  const [phase, setPhase] = useState<ResetPhase>({ phase: "form" });
  const [passwordError, setPasswordError] = useState<string>();
  const [confirmPasswordError, setConfirmPasswordError] = useState<string>();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
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
    try {
      await resetAccountPassword({ token, code, newPassword: password });
      setPhase({ phase: "success" });
    } catch (error) {
      if (isApiError(error)) {
        if (error.code === "auth.lifecycle_token_expired") {
          setPhase({ phase: "error", failure: "expired" });
        } else if (error.code === "auth.lifecycle_token_invalid") {
          setPhase({ phase: "error", failure: "invalid" });
        } else if (error.code === "auth.lifecycle_rejected" || error.kind === "validation") {
          setPhase({ phase: "error", failure: "rejected", message: error.message });
        } else if (error.kind === "rate_limited") {
          setPhase({ phase: "error", failure: "rate_limited", retryAfter: error.retryAfter });
        } else {
          setPhase({ phase: "error", failure: "unavailable" });
        }
      } else {
        setPhase({ phase: "error", failure: "unavailable" });
      }
    }
  }

  if (phase.phase === "success") {
    return (
      <div className={styles.panel}>
        <div className={styles.statusCard} role="status" aria-live="polite">
          <IconTick size="extra-large" style={{ color: "var(--up-success)" }} />
          <h1>密码已重置</h1>
          <p>密码已更新，所有旧登录会话均已失效。请使用新密码重新登录。</p>
        </div>
        <div className={styles.actions}>
          <Link href="/login">
            <Button theme="solid" type="primary" size="large" block>返回登录</Button>
          </Link>
        </div>
      </div>
    );
  }

  if (phase.phase === "error") {
    const descriptions: Record<ResetFailure, string> = {
      expired: "该密码重置链接已过期。请重新申请重置密码以获取新的链接。",
      invalid: "该密码重置链接无效或已被使用。请确认链接完整，或重新申请。",
      rejected: phase.message ?? "新密码不符合安全策略，或重置链接已经失效。",
      rate_limited: phase.retryAfter
        ? `操作过于频繁，请在 ${phase.retryAfter} 秒后再试。`
        : "操作过于频繁，请稍后再试。",
      unavailable: "服务暂时无法完成密码重置。若密码可能已经更新，请先尝试使用新密码登录。",
    };
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          <h1>无法重置密码</h1>
          <p>密码重置链接或服务状态存在问题，请根据提示处理。</p>
        </div>
        <div role="alert">
          <Banner
            type={phase.failure === "invalid" || phase.failure === "rejected" ? "danger" : "warning"}
            icon={phase.failure === "expired" || phase.failure === "rate_limited" ? <IconHourglass /> : <IconAlertTriangle />}
            description={descriptions[phase.failure]}
          />
        </div>
        <div className={styles.actions}>
          <Link href="/forgot-password">
            <Button theme="solid" type="primary" size="large" block>重新申请重置密码</Button>
          </Link>
          <Link href="/login">
            <Button theme="outline" size="large" block>尝试登录</Button>
          </Link>
        </div>
      </div>
    );
  }

  const submitting = phase.phase === "submitting";
  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <h1>设置新密码</h1>
        <p>为你的统一门户账户设置一个新的登录密码。</p>
      </div>

      <form className={styles.form} method="post" onSubmit={handleSubmit}>
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
            disabled={submitting}
            required
          />
          <small>至少 {PASSWORD_MIN_LENGTH} 个字符，请勿使用其他服务的密码。</small>
          {passwordError && <small id="reset-password-error" className={styles.fieldError} role="alert">{passwordError}</small>}
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
            disabled={submitting}
            required
          />
          {confirmPasswordError && <small id="reset-confirm-password-error" className={styles.fieldError} role="alert">{confirmPasswordError}</small>}
        </label>
        <Button htmlType="submit" type="primary" theme="solid" size="large" block disabled={submitting} loading={submitting}>
          {submitting ? "正在重置…" : "重置密码"}
        </Button>
      </form>

      {submitting && (
        <div className={styles.loadingBlock} role="status" aria-live="polite">
          <Spin />
          <span>正在校验一次性链接、更新密码并撤销旧会话…</span>
        </div>
      )}
      <p className={styles.switchMode}>已想起密码？<Link href="/login">返回登录</Link></p>
    </div>
  );
}
