import type { Metadata } from "next";
import { AuditTable } from "@/features/admin/components/tables/audit-table";
import { serverQueries } from "@/lib/api/server/server-queries";

export const metadata: Metadata = { title: "审计事件" };
export default async function AuditPage() { return <AuditTable records={await serverQueries.getAuditEvents()} />; }
