//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Username and password credential form panel
//

"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Checkbox, Input } from "@douyinfe/semi-ui";
import { IconKey, IconMail, IconUser } from "@douyinfe/semi-icons";
import { authenticateMockAccount, MOCK_LOGIN_ACCOUNTS } from "@/lib/mock/mock-auth";
import { USE_MOCK_DATA_SOURCE } from "@/lib/api/data-source-mode";
import { isApiError } from "@/lib/api/api-error";
import { completeLoginMfa, submitLogin } from "@/lib/api/browser/auth-commands";
import type { MfaMethod } from "@/features/auth/types";
import { MfaChallengePanel } from "@/features/auth/components/mfa-challenge-panel";
import styles from "./credential-panel.module.css";

type CredentialPanelProps = {
  mode: "login" | "register";
  /**
   * Authorization transaction ID to resume after successful login.
   * When present, login redirects to /authorize?requestId=... instead
   * of the default account/admin destination. Only an opaque server-issued
   * transaction ID is accepted — never a raw returnTo URL.
   */
  resumeRequestId?: string;
};

/**
 * MFA methods the login seam can actually complete end-to-end today.
 * The passkey assertion seam is not migrated yet (ADR-0004), and the P1
 * backend explicitly rejects recovery codes ("Recovery codes are not
 * implemented"), so only TOTP is offered in real mode; anything else is
 * filtered out before rendering the challenge panel.
 */
const COMPLETABLE_MFA_METHODS: ReadonlySet<MfaMethod> = new Set([
  "totp",
]);

export function CredentialPanel({ mode, resumeRequestId }: CredentialPanelProps) {
  const router = useRouter();
  const isLogin = mode === "login";
  const [confirmPasswordError, setConfirmPasswordError] = useState<string>();
  const [loginError, setLoginError] = useState<string>();
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [termsError, setTermsError] = useState<string>();
  const [remember, setRemember] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [mfaChallenge, setMfaChallenge] = useState<{
    mfaToken: string;
    availableMethods: MfaMethod[];
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
    try {
      const outcome = await submitLogin({
        identifier,
        password,
        remember,
        resumeRequestId,
      });
      if (outcome.status === "mfa_required") {
        const completable = outcome.availableMethods.filter((method) =>
          COMPLETABLE_MFA_METHODS.has(method),
        );
        if (completable.length === 0) {
          setLoginError("当前账户要求二次验证，但可用的验证方式暂不支持在此完成。请联系管理员。");
          return;
        }
        setMfaChallenge({ mfaToken: outcome.mfaToken, availableMethods: completable });
        return;
      }
      router.push(loginDestination());
    } catch (error) {
      setLoginError(loginFailureMessage(error));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleRealMfaVerify(method: MfaMethod, code: string) {
    if (!mfaChallenge) return;
    await completeLoginMfa({ mfaToken: mfaChallenge.mfaToken, method, code });
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);

    if (isLogin) {
      const identifier = formData.get("identifier");
      const password = formData.get("password");
      if (typeof identifier !== "string" || typeof password !== "string") {
        return;
      }

      if (!USE_MOCK_DATA_SOURCE) {
        void handleRealLogin(identifier, password);
        return;
      }

      const destination = authenticateMockAccount(identifier, password);

      if (!destination) {
        setLoginError("账户名、邮箱或密码错误，请使用页面提供的 Mock 凭据。");
        return;
      }

      setLoginError(undefined);

      if (resumeRequestId) {
        router.push(`/authorize?requestId=${encodeURIComponent(resumeRequestId)}`);
      } else {
        router.push(destination);
      }
      return;
    }

    if (!isLogin) {
      const password = formData.get("password");
      const confirmPassword = formData.get("confirmPassword");

      if (typeof password !== "string" || password !== confirmPassword) {
        setConfirmPasswordError("两次输入的密码不一致，请重新确认。");
        return;
      }

      if (!termsAccepted) {
        setTermsError("请阅读并同意服务条款。");
        return;
      }
    }

    setConfirmPasswordError(undefined);
    setTermsError(undefined);
    router.push("/account");
  }

  if (isLogin && mfaChallenge) {
    return (
      <MfaChallengePanel
        mfaToken={mfaChallenge.mfaToken}
        availableMethods={mfaChallenge.availableMethods}
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
        {USE_MOCK_DATA_SOURCE && <span className={styles.mockBadge}>MOCK PREVIEW</span>}
        <h1>{isLogin ? "欢迎回来" : "创建你的统一门户账号"}</h1>
        <p>{isLogin ? "使用你的统一账户继续访问。" : "一站式登陆砾石进化服务"}</p>
      </div>

      <form className={styles.form} onSubmit={handleSubmit}>
        {isLogin ? (
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
              aria-errormessage={loginError ? "mock-login-error" : undefined}
              onChange={() => setLoginError(undefined)}
              required
            />
          </label>
        ) : (
          <>
            <label className={styles.field}>
              <span>账户名</span>
              <Input
                name="username"
                type="text"
                size="large"
                prefix={<IconUser />}
                placeholder="例如 zhixing.lin"
                autoComplete="username"
                minLength={3}
                maxLength={32}
                required
              />
              <small>用于登录和识别账户，长度为 3–32 个字符。</small>
            </label>
            <label className={styles.field}>
              <span>邮箱地址</span>
              <Input
                name="email"
                type="email"
                size="large"
                prefix={<IconMail />}
                placeholder="name@example.com"
                autoComplete="email"
                required
              />
            </label>
          </>
        )}
        <label className={styles.field}>
          <span>密码</span>
          <Input
            name="password"
            mode="password"
            size="large"
            prefix={<IconKey />}
            placeholder={isLogin ? "输入密码" : "至少 12 个字符"}
            autoComplete={isLogin ? "current-password" : "new-password"}
            minLength={12}
            validateStatus={isLogin && loginError ? "error" : "default"}
            aria-invalid={isLogin && Boolean(loginError)}
            aria-errormessage={isLogin && loginError ? "mock-login-error" : undefined}
            onChange={isLogin ? () => setLoginError(undefined) : undefined}
            required
          />
          {!isLogin && <small>至少 12 个字符，请勿使用其他服务的密码。</small>}
          {isLogin && loginError && (
            <small id="mock-login-error" className={styles.fieldError} role="alert">
              {loginError}
            </small>
          )}
        </label>
        {!isLogin && (
          <label className={styles.field}>
            <span>确认密码</span>
            <Input
              name="confirmPassword"
              mode="password"
              size="large"
              prefix={<IconKey />}
              placeholder="再次输入密码"
              autoComplete="new-password"
              minLength={12}
              validateStatus={confirmPasswordError ? "error" : "default"}
              aria-invalid={Boolean(confirmPasswordError)}
              aria-errormessage={confirmPasswordError ? "confirm-password-error" : undefined}
              onChange={() => setConfirmPasswordError(undefined)}
              required
            />
            {confirmPasswordError && (
              <small id="confirm-password-error" className={styles.fieldError} role="alert">
                {confirmPasswordError}
              </small>
            )}
          </label>
        )}

        <div className={styles.formMetaBlock}>
          <div className={styles.formMeta}>
            {isLogin ? (
              <Checkbox
                checked={remember}
                onChange={(event) => setRemember(Boolean(event.target.checked))}
              >
                保持登录
              </Checkbox>
            ) : (
              <Checkbox
                checked={termsAccepted}
                onChange={(event) => {
                  const isAccepted = Boolean(event.target.checked);
                  setTermsAccepted(isAccepted);
                  if (isAccepted) setTermsError(undefined);
                }}
                aria-required="true"
                aria-invalid={Boolean(termsError)}
                aria-errormessage={termsError ? "terms-acceptance-error" : undefined}
              >
                我已阅读并同意服务条款
              </Checkbox>
            )}
            {isLogin ? <Link href="/forgot-password">忘记密码？</Link> : <Link href="/terms">查看服务条款</Link>}
          </div>
          {termsError && (
            <small id="terms-acceptance-error" className={styles.fieldError} role="alert">
              {termsError}
            </small>
          )}
        </div>

        <Button
          htmlType="submit"
          type="primary"
          theme="solid"
          size="large"
          block
          loading={isLogin && !USE_MOCK_DATA_SOURCE && isSubmitting}
          disabled={isLogin && !USE_MOCK_DATA_SOURCE && isSubmitting}
        >
          {isLogin
            ? USE_MOCK_DATA_SOURCE
              ? "登录（Mock）"
              : isSubmitting
                ? "正在登录…"
                : "登录"
            : "创建演示账户（Mock）"}
        </Button>
      </form>

      {isLogin && USE_MOCK_DATA_SOURCE && (
        <div className={styles.demoCredential}>
          <strong>普通用户演示凭据</strong>
          <span>账户名</span>
          <code>{MOCK_LOGIN_ACCOUNTS.externalUser.username}</code>
          <span>邮箱</span>
          <code>{MOCK_LOGIN_ACCOUNTS.externalUser.email}</code>
          <span>密码</span>
          <code>{MOCK_LOGIN_ACCOUNTS.externalUser.password}</code>
        </div>
      )}

      {USE_MOCK_DATA_SOURCE && (
        <p className={styles.notice}>当前为界面 mock，不会提交密码或创建真实账户。</p>
      )}
      {!USE_MOCK_DATA_SOURCE && (
        <p className={styles.notice}>
          登录即表示你已阅读并同意<Link href="/terms">服务条款</Link>与<Link href="/privacy">隐私政策</Link>。
        </p>
      )}
      <p className={styles.switchMode}>
        {isLogin ? "还没有账户？" : "已有账户？"}
        <Link href={isLogin ? "/register" : "/login"}>{isLogin ? "立即注册" : "返回登录"}</Link>
      </p>
    </div>
  );
}
