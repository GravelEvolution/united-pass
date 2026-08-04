import type { Metadata } from "next";
import { ManagementDirectory } from "@/features/admin/components/management-directory";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "授权策略" };
export default async function PoliciesPage() { return <ManagementDirectory kind="policies" records={await mockUnitedPassDataSource.getPolicies()} />; }
