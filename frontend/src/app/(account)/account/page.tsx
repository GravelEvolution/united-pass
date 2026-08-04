import type { Metadata } from "next";
import { AccountOverview } from "@/features/account/components/account-overview";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "账户概览" };

export default async function AccountPage() {
  const currentUser = await serverQueries.getCurrentUser();
  return <AccountOverview currentUser={currentUser} />;
}
