"use client";

import type { FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button, Checkbox, Input } from "@douyinfe/semi-ui";
import { IconKey, IconMail } from "@douyinfe/semi-icons";
import styles from "./credential-panel.module.css";

type CredentialPanelProps = {
  mode: "login" | "register";
};

export function CredentialPanel({ mode }: CredentialPanelProps) {
  const router = useRouter();
  const isLogin = mode === "login";

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
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
        {!isLogin && (
          <label className={styles.field}>
            <span>姓名</span>
            <Input name="displayName" size="large" placeholder="你的姓名" required />
          </label>
        )}
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
        </label>

        <div className={styles.formMeta}>
          <Checkbox defaultChecked={!isLogin}>{isLogin ? "保持登录" : "我已阅读并同意服务条款"}</Checkbox>
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
