//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Forgot password form panel
//

"use client";

import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Button, Input } from "@douyinfe/semi-ui";
import { IconMail } from "@douyinfe/semi-icons";
import { browserFetch } from "@/lib/api/browser/browser-http-client";
import { preloadAliyunCaptcha, verifyAliyunCaptcha } from "@/lib/security/aliyun-captcha";
import styles from "./credential-panel.module.css";

export function ForgotPasswordPanel() {
  useEffect(() => {
    void preloadAliyunCaptcha();
  }, []);

  const [requestSubmitted, setRequestSubmitted] = useState(false);
  const [identifier, setIdentifier] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalized = identifier.trim();
    if (!normalized) return;

    setIsSubmitting(true);
    setErrorMessage(undefined);

    let captchaVerifyParam: string;
    try {
      captchaVerifyParam = await verifyAliyunCaptcha();
    } catch {
      setIsSubmitting(false);
      setErrorMessage("人机验证未通过，请重试。");
      return;
    }

    try {
      // The endpoint answers 202 for any well-formed identifier (anti-
      // enumeration); the reset link is only emailed when an account exists.
      await browserFetch<{ status: string }>("/auth/password-reset", {
        method: "POST",
        body: { identifier: normalized },
        captchaVerifyParam,
      });
      setRequestSubmitted(true);
    } catch {
      setErrorMessage("发送失败，请稍后重试。");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <h1>找回账户密码</h1>
        <p>输入账户名或邮箱，我们将发送密码重置说明。</p>
      </div>

      <form className={styles.form} method="post" onSubmit={handleSubmit}>
        <label className={styles.field}>
          <span>账户名或邮箱</span>
          <Input
            name="identifier"
            type="text"
            size="large"
            prefix={<IconMail />}
            placeholder="账户名或 name@example.com"
            autoComplete="username"
            value={identifier}
            onChange={(nextValue) => setIdentifier(nextValue)}
            disabled={isSubmitting}
            required
          />
        </label>

        <Button
          htmlType="submit"
          type="primary"
          theme="solid"
          size="large"
          block
          loading={isSubmitting}
          disabled={isSubmitting}
        >
          发送重置说明
        </Button>
      </form>

      {errorMessage && (
        <p className={styles.notice} role="alert">
          {errorMessage}
        </p>
      )}

      {requestSubmitted && (
        <p className={styles.mockResult} role="status">
          如果该账户存在，我们会向已验证的联系方式发送重置说明。
        </p>
      )}

      <p className={styles.switchMode}>
        已想起密码？<Link href="/login">返回登录</Link>
      </p>
    </div>
  );
}
