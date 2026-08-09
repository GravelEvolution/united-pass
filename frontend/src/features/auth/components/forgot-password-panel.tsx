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
import styles from "./credential-panel.module.css";

export function ForgotPasswordPanel() {
  const [requestSubmitted, setRequestSubmitted] = useState(false);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRequestSubmitted(true);
  }

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <span className={styles.mockBadge}>MOCK PREVIEW</span>
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

        <Button htmlType="submit" type="primary" theme="solid" size="large" block>
          发送重置说明（Mock）
        </Button>
      </form>

      {requestSubmitted && (
        <p className={styles.mockResult} role="status">
          如果该账户存在，我们会向已验证的联系方式发送重置说明。
        </p>
      )}

      <p className={styles.notice}>当前不会发送邮件或短信，也不会修改任何账户凭据。</p>
      <p className={styles.switchMode}>
        已想起密码？<Link href="/login">返回登录</Link>
      </p>
    </div>
  );
}
