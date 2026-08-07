//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Email verification page
//

import type { Metadata } from "next";
import { VerifyEmailPanel } from "@/features/auth/components/verify-email-panel";
import { InvalidLinkNotice } from "@/features/auth/components/invalid-link-notice";

export const metadata: Metadata = { title: "验证邮箱" };

export const dynamic = "force-dynamic";

export default async function VerifyEmailPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const { token } = await searchParams;

  if (!token || token.trim().length === 0) {
    return (
      <InvalidLinkNotice
        title="链接无效"
        description="邮箱验证链接缺少必要的令牌参数。请确认你打开的是邮件中完整的验证链接。"
        actionHref="/login"
        actionLabel="返回登录"
      />
    );
  }

  return <VerifyEmailPanel token={token} />;
}
