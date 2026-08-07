//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Admin page: policy detail and editor
//

import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { PolicyEditor } from "@/features/policies/components/policy-editor";
import { PolicySimulationPanel } from "@/features/policies/components/policy-simulation-panel";
import { serverQueries } from "@/lib/api/server/server-queries";

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ policyId: string }>;
}): Promise<Metadata> {
  const { policyId } = await params;
  const detail = await serverQueries.getPolicyDetail(policyId);
  return {
    title: detail ? `策略 · ${detail.name}` : "策略",
  };
}

export default async function PolicyDetailPage({
  params,
}: {
  params: Promise<{ policyId: string }>;
}) {
  const { policyId } = await params;
  const detail = await serverQueries.getPolicyDetail(policyId);

  if (!detail) {
    notFound();
  }

  return (
    <>
      <PolicyEditor detail={detail} />
      <div style={{ marginTop: 24 }}>
        <PolicySimulationPanel />
      </div>
    </>
  );
}
