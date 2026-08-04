import type { Metadata } from "next";
import { AccountOverview } from "@/features/account/components/account-overview";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "账户概览" };

export default async function AccountPage() {
  const currentUser = await mockUnitedPassDataSource.getCurrentUser();
  return <AccountOverview currentUser={currentUser} />;
}
