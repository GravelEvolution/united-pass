//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Forgot password form panel
//

"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import Link from "next/link";
import { Button, Input } from "@douyinfe/semi-ui";
import { IconMail } from "@douyinfe/semi-icons";
import { isApiError } from "@/lib/api/api-error";
import { requestPasswordReset } from "@/lib/api/browser/auth-commands";
import styles from "./credential-panel.module.css";

export function ForgotPasswordPanel() {
  const [requestSubmitted, setRequestSubmitted] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const identifier = new FormData(event.currentTarget).get("identifier");
    if (typeof identifier !== "string") return;
    setIsSubmitting(true);
    setErrorMessage(undefined);
    try {
      await requestPasswordReset(identifier);
      setRequestSubmitted(true);
    } catch (error) {
      if (isApiError(error) && error.kind === "rate_limited") {
        setErrorMessage(error.message);
      } else if (isApiError(error) && error.kind === "network") {
        setErrorMessage("网络异常，请检查连接后重试。");
      } else {
        setErrorMessage("暂时无法提交请求，请稍后重试。");
      }
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
          disabled={isSubmitting || requestSubmitted}
        >
          {isSubmitting ? "正在提交…" : requestSubmitted ? "重置说明已请求" : "发送重置说明"}
        </Button>
      </form>

      {errorMessage && <p className={styles.fieldError} role="alert">{errorMessage}</p>}

      {requestSubmitted && (
        <p className={styles.statusResult} role="status">
          如果该账户存在，我们会向已验证的联系方式发送重置说明。
        </p>
      )}

      <p className={styles.notice}>为保护账户隐私，无论账户是否存在，页面都会显示相同结果。</p>
      <p className={styles.switchMode}>
        已想起密码？<Link href="/login">返回登录</Link>
      </p>
    </div>
  );
}
