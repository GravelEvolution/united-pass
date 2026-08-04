import type { Metadata } from "next";
import { ManagementDirectory } from "@/features/admin/components/management-directory";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "OAuth 应用" };
export default async function ApplicationsPage() { return <ManagementDirectory kind="applications" records={await mockUnitedPassDataSource.getApplications()} />; }
