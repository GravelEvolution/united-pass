import type { Metadata } from "next";
import { ResetPasswordPanel } from "@/features/auth/components/reset-password-panel";
import { InvalidLinkNotice } from "@/features/auth/components/invalid-link-notice";

export const metadata: Metadata = { title: "重置密码" };

export const dynamic = "force-dynamic";

export default async function ResetPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const { token } = await searchParams;

  if (!token || token.trim().length === 0) {
    return (
      <InvalidLinkNotice
        title="链接无效"
        description="密码重置链接缺少必要的令牌参数。请确认你打开的是邮件中完整的重置链接。"
        actionHref="/forgot-password"
        actionLabel="重新申请重置密码"
      />
    );
  }

  return <ResetPasswordPanel token={token} />;
}
