"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Checkbox, Input } from "@douyinfe/semi-ui";
import { IconKey, IconMail, IconUser } from "@douyinfe/semi-icons";
import styles from "./credential-panel.module.css";

type CredentialPanelProps = {
  mode: "login" | "register";
};

export function CredentialPanel({ mode }: CredentialPanelProps) {
  const router = useRouter();
  const isLogin = mode === "login";
  const [confirmPasswordError, setConfirmPasswordError] = useState<string>();

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!isLogin) {
      const formData = new FormData(event.currentTarget);
      const password = formData.get("password");
      const confirmPassword = formData.get("confirmPassword");

      if (typeof password !== "string" || password !== confirmPassword) {
        setConfirmPasswordError("两次输入的密码不一致，请重新确认。");
        return;
      }
    }

    setConfirmPasswordError(undefined);
    router.push("/account");
  }

  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <span className={styles.mockBadge}>MOCK PREVIEW</span>
        <h1>{isLogin ? "欢迎回来" : "创建 United Pass"}</h1>
        <p>{isLogin ? "使用你的统一账户继续访问。" : "创建后，你的稳定用户身份可关联员工档案。"}</p>
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
            required
          />
          {!isLogin && <small>至少 12 个字符，请勿使用其他服务的密码。</small>}
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

        <div className={styles.formMeta}>
          <Checkbox defaultChecked={isLogin}>{isLogin ? "保持登录" : "我已阅读并同意服务条款"}</Checkbox>
          {isLogin && <Link href="/login">忘记密码？</Link>}
        </div>

        <Button htmlType="submit" type="primary" theme="solid" size="large" block>
          {isLogin ? "进入账户中心（Mock）" : "创建演示账户（Mock）"}
        </Button>
      </form>

      <p className={styles.notice}>当前为界面 mock，不会提交密码或创建真实账户。</p>
      <p className={styles.switchMode}>
        {isLogin ? "还没有账户？" : "已有账户？"}
        <Link href={isLogin ? "/register" : "/login"}>{isLogin ? "立即注册" : "返回登录"}</Link>
      </p>
    </div>
  );
}
