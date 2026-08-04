import type { Metadata } from "next";
import { SessionList } from "@/features/account/components/session-list";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "活跃会话" };

export default async function SessionsPage() {
  const sessions = await mockUnitedPassDataSource.getSessions();
  return <SessionList sessions={sessions} />;
}
