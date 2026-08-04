import type { Metadata } from "next";
import { ApplicationsTable } from "@/features/admin/components/tables/applications-table";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "OAuth 应用" };
export default async function ApplicationsPage() { return <ApplicationsTable records={await serverQueries.getApplications()} />; }
