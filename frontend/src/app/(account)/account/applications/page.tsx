import type { Metadata } from "next";
import { AuthorizedApplicationList } from "@/features/account/components/authorized-application-list";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "授权应用" };

export default async function AccountApplicationsPage() {
  const applications = await mockUnitedPassDataSource.getAuthorizedApplications();
  return <AuthorizedApplicationList applications={applications} />;
}
