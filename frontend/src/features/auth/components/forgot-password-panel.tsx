"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import Link from "next/link";
import { Banner, Button, Input } from "@douyinfe/semi-ui";
import { IconAlertTriangle, IconMail, IconTick } from "@douyinfe/semi-icons";
import { isApiError } from "@/lib/api/api-error";
import { requestPasswordReset } from "@/lib/api/browser/password-reset-commands";
import styles from "./credential-panel.module.css";

function resolveErrorMessage(error: unknown): string {
  if (isApiError(error)) {
    if (error.kind === "rate_limited") {
      return error.retryAfter
        ? `请求过于频繁，请在 ${error.retryAfter} 秒后重试。`
        : "请求过于频繁，请稍后重试。";
    }
    if (error.kind === "validation") {
      return "请输入有效的邮箱地址。";
    }
    if (error.kind === "network") {
      return "网络异常，请检查连接后重试。";
    }
    return error.message;
  }
  return "提交失败，请稍后重试。";
}

export function ForgotPasswordPanel() {
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const identifier = String(formData.get("identifier") ?? "").trim();

    if (identifier === "") {
      setErrorMessage("请输入你注册时使用的邮箱地址。");
      return;
    }

    setErrorMessage(undefined);
    setSubmitting(true);
    try {
      await requestPasswordReset({ identifier });
      setSubmitted(true);
    } catch (error) {
      setErrorMessage(resolveErrorMessage(error));
    } finally {
      setSubmitting(false);
    }
  }

  if (submitted) {
    return (
      <div className={styles.panel}>
        <div className={styles.statusCard} role="status" aria-live="polite">
          <IconTick size="extra-large" style={{ color: "var(--up-success)" }} />
          <h1>重置说明已发送</h1>
          <p>如果该邮箱对应一个已验证的账户，我们已向它发送密码重置链接。链接 30 分钟内有效，且只能使用一次。</p>
        </div>
        <p className={styles.notice}>没有收到邮件？请检查垃圾邮件目录，或稍后重新提交。</p>
        <p className={styles.switchMode}>
          已想起密码？<Link href="/login">返回登录</Link>
        </p>
      </div>
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <h1>找回账户密码</h1>
        <p>输入你注册时使用的邮箱，我们会发送密码重置链接。</p>
      </div>

      <form className={styles.form} method="post" onSubmit={handleSubmit}>
        <label className={styles.field}>
          <span>注册邮箱</span>
          <Input
            name="identifier"
            type="text"
            size="large"
            prefix={<IconMail />}
            placeholder="name@example.com"
            autoComplete="username"
            validateStatus={errorMessage ? "error" : "default"}
            onChange={() => setErrorMessage(undefined)}
            disabled={submitting}
            required
          />
        </label>

        <Button
          htmlType="submit"
          type="primary"
          theme="solid"
          size="large"
          block
          disabled={submitting}
          loading={submitting}
        >
          {submitting ? "正在发送…" : "发送重置链接"}
        </Button>
      </form>

      {errorMessage && (
        <div role="alert">
          <Banner type="danger" icon={<IconAlertTriangle />} description={errorMessage} />
        </div>
      )}

      <p className={styles.notice}>重置链接只会发送到已验证的邮箱，我们不会透露该邮箱是否已注册。</p>
      <p className={styles.switchMode}>
        已想起密码？<Link href="/login">返回登录</Link>
      </p>
    </div>
  );
}
