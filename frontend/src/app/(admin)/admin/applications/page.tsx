import type { Metadata } from "next";
import { ApplicationsTable } from "@/features/admin/components/tables/applications-table";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "OAuth 应用" };
export default async function ApplicationsPage() { return <ApplicationsTable records={await mockUnitedPassDataSource.getApplications()} />; }
