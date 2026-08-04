import type { Metadata } from "next";
import { ManagementDirectory } from "@/features/admin/components/management-directory";
import { mockUnitedPassDataSource } from "@/lib/mock/united-pass-data-source";

export const metadata: Metadata = { title: "审计事件" };
export default async function AuditPage() { return <ManagementDirectory kind="audit" records={await mockUnitedPassDataSource.getAuditEvents()} />; }
