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

export function CredentialPanel({ mode, resumeRequestId }: CredentialPanelProps) {
  const router = useRouter();
  const isLogin = mode === "login";
  const [confirmPasswordError, setConfirmPasswordError] = useState<string>();
  const [loginError, setLoginError] = useState<string>();
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [termsError, setTermsError] = useState<string>();

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const formData = new FormData(event.currentTarget);

    if (isLogin) {
      const identifier = formData.get("identifier");
      const password = formData.get("password");
      const destination =
        typeof identifier === "string" && typeof password === "string"
          ? authenticateMockAccount(identifier, password)
          : undefined;

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

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <span className={styles.mockBadge}>MOCK PREVIEW</span>
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
              <Checkbox defaultChecked>保持登录</Checkbox>
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

        <Button htmlType="submit" type="primary" theme="solid" size="large" block>
          {isLogin ? "登录（Mock）" : "创建演示账户（Mock）"}
        </Button>
      </form>

      {isLogin && (
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

      <p className={styles.notice}>当前为界面 mock，不会提交密码或创建真实账户。</p>
      <p className={styles.switchMode}>
        {isLogin ? "还没有账户？" : "已有账户？"}
        <Link href={isLogin ? "/register" : "/login"}>{isLogin ? "立即注册" : "返回登录"}</Link>
      </p>
    </div>
  );
}
