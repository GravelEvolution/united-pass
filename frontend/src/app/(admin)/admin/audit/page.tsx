import type { Metadata } from "next";
import { AuditTable } from "@/features/admin/components/tables/audit-table";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "审计事件" };
export default async function AuditPage() { return <AuditTable records={await mockUnitedPassDataSource.getAuditEvents()} />; }
