//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Username and password credential form panel
//

"use client";

import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Checkbox, Input } from "@douyinfe/semi-ui";
import { IconKey, IconUser } from "@douyinfe/semi-icons";
import { isApiError } from "@/lib/api/api-error";
import { completeLoginMfa, submitLogin } from "@/lib/api/browser/auth-commands";
import { preloadAliyunCaptcha, verifyAliyunCaptcha } from "@/lib/security/aliyun-captcha";
import type {
  LoginMfaMethod,
  LoginMfaVerification,
} from "@/features/auth/types";
import { MfaChallengePanel } from "@/features/auth/components/mfa-challenge-panel";
import styles from "./credential-panel.module.css";

type CredentialPanelProps = {
  /**
   * Authorization transaction ID to resume after successful login.
   * When present, login redirects to /authorize?requestId=... instead
   * of the default account/admin destination. Only an opaque server-issued
   * transaction ID is accepted — never a raw returnTo URL.
   */
  resumeRequestId?: string;
  feishuLoginEnabled?: boolean;
  providerError?: string;
  registrationEnabled?: boolean;
};

/**
 * MFA methods the login seam can actually complete end-to-end today.
 * The passkey assertion seam is not migrated yet (ADR-0004), and the P1
 * backend explicitly rejects recovery codes ("Recovery codes are not
 * implemented"), so only TOTP is offered in real mode; anything else is
 * filtered out before rendering the challenge panel.
 */
const COMPLETABLE_MFA_METHODS: ReadonlySet<LoginMfaMethod> = new Set([
  "totp",
  "passkey",
]);

export function CredentialPanel({
  resumeRequestId,
  feishuLoginEnabled = false,
  providerError,
  registrationEnabled = false,
}: CredentialPanelProps) {
  const router = useRouter();

  useEffect(() => {
    void preloadAliyunCaptcha();
  }, []);
  const [loginError, setLoginError] = useState<string | undefined>(() => {
    if (providerError === "identity_unlinked") {
      return "该飞书身份尚未关联统一门户账户，请联系管理员完成显式身份绑定。";
    }
    if (providerError) return "飞书登录未完成，请重试或使用统一账户登录。";
    return undefined;
  });
  const [remember, setRemember] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [mfaChallenge, setMfaChallenge] = useState<{
    mfaToken: string;
    availableMethods: LoginMfaMethod[];
    passkeyRequestOptions?: unknown;
    expiresAt: string;
  }>();

  function loginDestination(): string {
    if (resumeRequestId) {
      return `/authorize?requestId=${encodeURIComponent(resumeRequestId)}`;
    }
    return "/account";
  }

  function loginFailureMessage(error: unknown): string {
    if (isApiError(error)) {
      if (error.kind === "rate_limited") {
        const wait = error.retryAfter !== undefined ? `请在 ${error.retryAfter} 秒后再试。` : "请稍后再试。";
        return `尝试次数过多，${wait}`;
      }
      if (error.kind === "network") {
        return "网络异常，请检查连接后重试。";
      }
      return error.message;
    }
    return "登录失败，请稍后重试。";
  }

  async function handleRealLogin(identifier: string, password: string) {
    setIsSubmitting(true);
    setLoginError(undefined);

    let captchaVerifyParam: string;
    try {
      captchaVerifyParam = await verifyAliyunCaptcha();
    } catch {
      setIsSubmitting(false);
      setLoginError("人机验证未通过，请重试。");
      return;
    }

    try {
      const outcome = await submitLogin({
        identifier,
        password,
        remember,
        resumeRequestId,
        captchaVerifyParam,
      });
      if (outcome.status === "mfa_required") {
        const completable = outcome.availableMethods.filter((method): method is LoginMfaMethod =>
          method !== "recovery_code"
          && COMPLETABLE_MFA_METHODS.has(method)
          && (method !== "passkey" || outcome.passkeyRequestOptions !== undefined),
        );
        if (completable.length === 0) {
          setLoginError("当前账户要求二次验证，但可用的验证方式暂不支持在此完成。请联系管理员。");
          return;
        }
        setMfaChallenge({
          mfaToken: outcome.mfaToken,
          availableMethods: completable,
          passkeyRequestOptions: outcome.passkeyRequestOptions,
          expiresAt: outcome.expiresAt,
        });
        return;
      }
      router.push(loginDestination());
    } catch (error) {
      setLoginError(loginFailureMessage(error));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleRealMfaVerify(input: LoginMfaVerification) {
    if (!mfaChallenge) return;
    await completeLoginMfa({ mfaToken: mfaChallenge.mfaToken, ...input });
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);
    const identifier = formData.get("identifier");
    const password = formData.get("password");
    if (typeof identifier !== "string" || typeof password !== "string") {
      return;
    }

    void handleRealLogin(identifier, password);
  }

  if (mfaChallenge) {
    return (
      <MfaChallengePanel
        availableMethods={mfaChallenge.availableMethods}
        passkeyRequestOptions={mfaChallenge.passkeyRequestOptions}
        expiresAt={mfaChallenge.expiresAt}
        onVerify={handleRealMfaVerify}
        onSuccess={() => router.push(loginDestination())}
        onCancel={() => {
          setMfaChallenge(undefined);
          setLoginError(undefined);
        }}
      />
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <h1>欢迎回来</h1>
        <p>使用你的统一账户继续访问。</p>
      </div>

      <form className={styles.form} method="post" onSubmit={handleSubmit}>
        <label className={styles.field}>
          <span>账户名或邮箱</span>
          <Input
            name="identifier"
            type="text"
            size="large"
            prefix={<IconUser />}
            placeholder="账户名或 name@example.com"
            autoComplete="username"
            validateStatus={loginError ? "error" : "default"}
            aria-invalid={Boolean(loginError)}
            aria-errormessage={loginError ? "login-error" : undefined}
            onChange={() => setLoginError(undefined)}
            required
          />
        </label>
        <label className={styles.field}>
          <span>密码</span>
          <Input
            name="password"
            mode="password"
            size="large"
            prefix={<IconKey />}
            placeholder="输入密码"
            autoComplete="current-password"
            minLength={12}
            validateStatus={loginError ? "error" : "default"}
            aria-invalid={Boolean(loginError)}
            aria-errormessage={loginError ? "login-error" : undefined}
            onChange={() => setLoginError(undefined)}
            required
          />
          {loginError && (
            <small id="login-error" className={styles.fieldError} role="alert">
              {loginError}
            </small>
          )}
        </label>

        <div className={styles.formMetaBlock}>
          <div className={styles.formMeta}>
            <Checkbox
              checked={remember}
              onChange={(event) => setRemember(Boolean(event.target.checked))}
            >
              保持登录
            </Checkbox>
            <Link href="/forgot-password">忘记密码？</Link>
          </div>
        </div>

        <Button
          htmlType="submit"
          type="primary"
          theme="solid"
          size="large"
          block
          loading={isSubmitting}
          disabled={isSubmitting}
        >
          {isSubmitting ? "正在登录…" : "登录"}
        </Button>
      </form>

      {feishuLoginEnabled && (
        <div className={styles.providerLogin}>
          <span>或使用企业身份</span>
          <a
            href={`/api/v1/auth/providers/feishu/authorize?remember=${remember ? "true" : "false"}${resumeRequestId ? `&resumeRequestId=${encodeURIComponent(resumeRequestId)}` : ""}`}
          >
            使用飞书登录
          </a>
          <small>飞书仅证明外部身份，不会自动授予员工或管理权限。</small>
        </div>
      )}

      <p className={styles.notice}>
        登录即表示你已阅读并同意<Link href="/terms">服务条款</Link>与<Link href="/privacy">隐私政策</Link>。
      </p>
      <p className={styles.switchMode}>
        还没有账户？
        <Link href={resumeRequestId ? `/register?requestId=${encodeURIComponent(resumeRequestId)}` : "/register"}>
          {registrationEnabled ? "立即注册" : "查看注册状态"}
        </Link>
      </p>
    </div>
  );
}
