"use client";

import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Banner, Button, Checkbox, Input } from "@douyinfe/semi-ui";
import { IconKey, IconMail, IconUser } from "@douyinfe/semi-icons";
import { isApiError } from "@/lib/api/api-error";
import {
  createRegistration,
  resendRegistrationEmail,
} from "@/lib/api/browser/registration-commands";
import { preloadAliyunCaptcha, verifyAliyunCaptcha } from "@/lib/security/aliyun-captcha";
import styles from "./credential-panel.module.css";

type RegistrationPanelProps = { requestId?: string };

type WaitingState = {
  email: string;
  registrationToken: string;
};

export function RegistrationPanel({ requestId }: RegistrationPanelProps) {
  useEffect(() => {
    void preloadAliyunCaptcha();
  }, []);

  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string>();
  const [waiting, setWaiting] = useState<WaitingState>();
  const [isResending, setIsResending] = useState(false);
  const [resendMessage, setResendMessage] = useState<string>();

  const loginHref = requestId
    ? `/login?requestId=${encodeURIComponent(requestId)}`
    : "/login";

  function messageFor(errorValue: unknown): string {
    if (isApiError(errorValue)) {
      if (errorValue.kind === "rate_limited") {
        return errorValue.retryAfter
          ? `请求过于频繁，请在 ${errorValue.retryAfter} 秒后重试。`
          : "请求过于频繁，请稍后重试。";
      }
      if (errorValue.code === "registration.closed") return "注册暂未开放。";
      if (errorValue.kind === "network") return "网络连接异常，请检查网络后重试。";
      return errorValue.message;
    }
    return "暂时无法完成注册，请稍后重试。";
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(undefined);
    const data = new FormData(event.currentTarget);
    const username = data.get("username");
    const displayName = data.get("displayName");
    const email = data.get("email");
    const password = data.get("password");
    const confirmation = data.get("passwordConfirmation");
    if (typeof username !== "string"
      || typeof displayName !== "string"
      || typeof email !== "string"
      || typeof password !== "string"
      || typeof confirmation !== "string") {
      setError("请完整填写注册信息。");
      return;
    }
    if (password !== confirmation) {
      setError("两次输入的密码不一致。");
      return;
    }
    if (!acceptedTerms) {
      setError("请先阅读并同意服务条款与隐私政策。");
      return;
    }

    setIsSubmitting(true);

    let captchaVerifyParam: string;
    try {
      captchaVerifyParam = await verifyAliyunCaptcha();
    } catch {
      setIsSubmitting(false);
      setError("人机验证未通过，请重试。");
      return;
    }

    try {
      const result = await createRegistration({
        username, displayName, email, password,
        acceptedTerms: true,
        requestId,
        captchaVerifyParam,
      });
      setWaiting({ email, registrationToken: result.registrationToken });
    } catch (submitError) {
      setError(messageFor(submitError));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function resend() {
    if (!waiting) return;
    setIsResending(true);
    setResendMessage(undefined);
    try {
      await resendRegistrationEmail(waiting.registrationToken);
      setResendMessage("验证邮件已重新发送，请检查收件箱和垃圾邮件目录。");
    } catch (resendError) {
      setResendMessage(messageFor(resendError));
    } finally {
      setIsResending(false);
    }
  }

  if (waiting) {
    return (
      <div className={styles.panel}>
        <div className={styles.heading}>
          <h1>检查你的邮箱</h1>
          <p>验证邮件已发送至 {waiting.email}。点击邮件中的链接后，账户才会启用。</p>
        </div>
        <div className={styles.statusCard} role="status" aria-live="polite">
          <IconMail size="extra-large" style={{ color: "var(--up-brand)" }} />
          <p>验证链接为一次性链接。如果没有收到邮件，可以在下方重新发送。</p>
        </div>
        {resendMessage && <Banner type="info" description={resendMessage} />}
        <div className={styles.actions}>
          <Button
            type="primary"
            theme="solid"
            size="large"
            block
            loading={isResending}
            disabled={isResending}
            onClick={() => void resend()}
          >
            重新发送验证邮件
          </Button>
        </div>
        <p className={styles.switchMode}>已经验证？<Link href={loginHref}>返回登录</Link></p>
      </div>
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <h1>创建统一账户</h1>
        <p>注册后请先完成邮箱验证，再使用账户登录。</p>
      </div>
      <form className={styles.form} onSubmit={(event) => void handleSubmit(event)}>
        <label className={styles.field}>
          <span>账户名</span>
          <Input
            name="username"
            prefix={<IconUser />}
            size="large"
            autoComplete="username"
            placeholder="3–64 位字母、数字、点、横线或下划线"
            pattern="[A-Za-z0-9][A-Za-z0-9._-]{2,63}"
            maxLength={64}
            required
          />
        </label>
        <label className={styles.field}>
          <span>称呼</span>
          <Input name="displayName" size="large" autoComplete="name" maxLength={100} placeholder="希望我们如何称呼你" required />
        </label>
        <label className={styles.field}>
          <span>邮箱</span>
          <Input name="email" type="email" prefix={<IconMail />} size="large" autoComplete="email" maxLength={254} placeholder="name@example.com" required />
        </label>
        <label className={styles.field}>
          <span>密码</span>
          <Input name="password" mode="password" prefix={<IconKey />} size="large" autoComplete="new-password" minLength={12} maxLength={128} placeholder="至少 12 个字符" required />
        </label>
        <label className={styles.field}>
          <span>确认密码</span>
          <Input name="passwordConfirmation" mode="password" prefix={<IconKey />} size="large" autoComplete="new-password" minLength={12} maxLength={128} placeholder="再次输入密码" required />
        </label>
        <div className={styles.formMetaBlock}>
          <Checkbox checked={acceptedTerms} onChange={(event) => setAcceptedTerms(Boolean(event.target.checked))}>
            我已阅读并同意<Link href="/terms">服务条款</Link>与<Link href="/privacy">隐私政策</Link>
          </Checkbox>
          {error && <small className={styles.fieldError} role="alert">{error}</small>}
        </div>
        <Button htmlType="submit" type="primary" theme="solid" size="large" block loading={isSubmitting} disabled={isSubmitting}>
          {isSubmitting ? "正在创建账户…" : "创建账户"}
        </Button>
      </form>
      <p className={styles.switchMode}>已经有账户？<Link href={loginHref}>返回登录</Link></p>
    </div>
  );
}
