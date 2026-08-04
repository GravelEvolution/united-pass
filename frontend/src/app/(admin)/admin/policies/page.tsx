import type { Metadata } from "next";
import { PoliciesTable } from "@/features/admin/components/tables/policies-table";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "授权策略" };
export default async function PoliciesPage() { return <PoliciesTable records={await mockUnitedPassDataSource.getPolicies()} />; }
