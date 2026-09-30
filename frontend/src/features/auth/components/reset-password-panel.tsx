"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import Link from "next/link";
import { Banner, Button, Input } from "@douyinfe/semi-ui";
import { IconAlertTriangle, IconHourglass, IconKey, IconTick } from "@douyinfe/semi-icons";
import { isApiError } from "@/lib/api/api-error";
import { confirmPasswordReset } from "@/lib/api/browser/password-reset-commands";
import styles from "./credential-panel.module.css";

const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_MAX_LENGTH = 128;

type ResetPhase =
  | { phase: "form" }
  | { phase: "submitting" }
  | { phase: "success" }
  | { phase: "invalid_token" }
  | { phase: "rate_limited" };

type ResetPasswordPanelProps = {
  token: string;
};

function validatePassword(password: string): string | undefined {
  const length = [...password].length;
  if (length < PASSWORD_MIN_LENGTH) {
    return `密码至少需要 ${PASSWORD_MIN_LENGTH} 个字符。`;
  }
  if (length > PASSWORD_MAX_LENGTH) {
    return `密码最多 ${PASSWORD_MAX_LENGTH} 个字符。`;
  }
  if (!/\p{Lu}/u.test(password) || !/\p{Ll}/u.test(password) || !/\p{Nd}/u.test(password) || !/[^\p{L}\p{N}]/u.test(password)) {
    return "密码需同时包含大写字母、小写字母、数字和符号。";
  }
  return undefined;
}

export function ResetPasswordPanel({ token }: ResetPasswordPanelProps) {
  const [phase, setPhase] = useState<ResetPhase>({ phase: "form" });
  const [passwordError, setPasswordError] = useState<string>();
  const [confirmPasswordError, setConfirmPasswordError] = useState<string>();
  const [errorMessage, setErrorMessage] = useState<string>();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const password = formData.get("password");
    const confirmPassword = formData.get("confirmPassword");

    if (typeof password !== "string") {
      setPasswordError("请输入新密码。");
      return;
    }
    const strengthError = validatePassword(password);
    if (strengthError) {
      setPasswordError(strengthError);
      return;
    }
    if (password !== confirmPassword) {
      setConfirmPasswordError("两次输入的密码不一致，请重新确认。");
      return;
    }

    setPasswordError(undefined);
    setConfirmPasswordError(undefined);
    setErrorMessage(undefined);
    setPhase({ phase: "submitting" });

    try {
      await confirmPasswordReset({ token, newPassword: password });
      setPhase({ phase: "success" });
    } catch (error) {
      setPhase({ phase: "form" });
      if (isApiError(error)) {
        if (error.code === "password.reset_token_invalid") {
          setPhase({ phase: "invalid_token" });
          return;
        }
        if (error.kind === "rate_limited") {
          setPhase({ phase: "rate_limited" });
          return;
        }
        if (error.kind === "validation") {
          setPasswordError(error.fieldErrors?.[0]?.message ?? "新密码不符合要求。");
          return;
        }
        setErrorMessage(error.kind === "network" ? "网络异常，请检查连接后重试。" : error.message);
        return;
      }
      setErrorMessage("重置失败，请稍后重试。");
    }
  }

  if (phase.phase === "success") {
    return (
      <div className={styles.panel}>
        <div className={styles.statusCard} role="status" aria-live="polite">
          <IconTick size="extra-large" style={{ color: "var(--up-success)" }} />
          <h1>密码已重置</h1>
          <p>你的账户密码已成功更新，其他设备上的登录状态已全部退出。请使用新密码登录。</p>
        </div>
        <div className={styles.actions}>
          <Link href="/login">
            <Button theme="solid" type="primary" size="large" block>
              返回登录
            </Button>
          </Link>
        </div>
      </div>
    );
  }

  if (phase.phase === "invalid_token") {
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          <h1>无法重置密码</h1>
          <p>这个重置链接无效或已被使用。</p>
        </div>
        <div role="alert">
          <Banner
            type="danger"
            icon={<IconAlertTriangle />}
            description="重置链接无效、已过期或已被使用。请重新申请一次重置密码。"
          />
        </div>
        <div className={styles.actions}>
          <Link href="/forgot-password">
            <Button theme="solid" type="primary" size="large" block>
              重新申请重置密码
            </Button>
          </Link>
        </div>
        <p className={styles.switchMode}>
          已想起密码？<Link href="/login">返回登录</Link>
        </p>
      </div>
    );
  }

  if (phase.phase === "rate_limited") {
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          <h1>操作过于频繁</h1>
          <p>请稍后再试。</p>
        </div>
        <div role="alert">
          <Banner type="warning" icon={<IconHourglass />} description="操作过于频繁，请等待几分钟后重新打开重置链接。" />
        </div>
        <div className={styles.actions}>
          <Link href="/forgot-password">
            <Button theme="solid" type="primary" size="large" block>
              重新申请重置密码
            </Button>
          </Link>
        </div>
        <p className={styles.switchMode}>
          已想起密码？<Link href="/login">返回登录</Link>
        </p>
      </div>
    );
  }

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
            placeholder={`至少 ${PASSWORD_MIN_LENGTH} 个字符`}
            autoComplete="new-password"
            minLength={PASSWORD_MIN_LENGTH}
            validateStatus={passwordError ? "error" : "default"}
            aria-invalid={Boolean(passwordError)}
            aria-errormessage={passwordError ? "reset-password-error" : undefined}
            onChange={() => setPasswordError(undefined)}
            disabled={phase.phase === "submitting"}
            required
          />
          <small>至少 {PASSWORD_MIN_LENGTH} 个字符，需包含大写字母、小写字母、数字和符号。</small>
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
          {phase.phase === "submitting" ? "正在重置…" : "重置密码"}
        </Button>
      </form>

      {errorMessage && (
        <div role="alert">
          <Banner type="danger" icon={<IconAlertTriangle />} description={errorMessage} />
        </div>
      )}

      <p className={styles.switchMode}>
        已想起密码？<Link href="/login">返回登录</Link>
      </p>
    </div>
  );
}
