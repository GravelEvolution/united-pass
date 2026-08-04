import type { Metadata } from "next";
import { ApplicationCreateForm } from "@/features/applications/components/application-create-form";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "注册 OAuth 应用" };

export default async function NewApplicationPage() {
  const availableScopes = await mockUnitedPassDataSource.getAvailableScopes();
  return <ApplicationCreateForm availableScopes={availableScopes} />;
}
