//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Registration page
//

import type { Metadata } from "next";
import Link from "next/link";
import styles from "@/features/auth/components/credential-panel.module.css";

export const metadata: Metadata = { title: "注册" };

export const dynamic = "force-dynamic";

export default async function RegisterPage({
  searchParams,
}: {
  searchParams: Promise<{ requestId?: string }>;
}) {
  const { requestId } = await searchParams;
  if (process.env.UP_PUBLIC_REGISTRATION_ENABLED === "true") {
    const { RegistrationPanel } = await import("@/features/auth/components/registration-panel");
    return <RegistrationPanel requestId={requestId} />;
  }

  const loginHref = requestId ? `/login?requestId=${encodeURIComponent(requestId)}` : "/login";
  return (
    <div className={styles.panel}>
      <div className={styles.heading}>
        <span className={styles.mockBadge}>REGISTRATION CLOSED</span>
        <h1>注册暂未开放</h1>
        <p>砾石进化统一登陆门户平台目前仅向已有账户开放登录。公开注册启用后，我们会在 MoonStone 官方渠道说明。</p>
      </div>
      <div className={styles.statusCard} role="status">
        <p>如果你已经拥有账户，可以直接返回登录；此页面不会收集姓名、邮箱或密码。</p>
      </div>
      <div className={styles.actions}>
        <Link className={styles.primaryAction} href={loginHref}>返回登录</Link>
      </div>
      <p className={styles.notice}>DreamUP 报名资格与统一门户账户注册是两个独立流程。</p>
    </div>
  );
}
