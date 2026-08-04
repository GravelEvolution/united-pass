import type { Metadata } from "next";
import { PoliciesTable } from "@/features/admin/components/tables/policies-table";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "授权策略" };
export default async function PoliciesPage() { return <PoliciesTable records={await serverQueries.getPolicies()} />; }
