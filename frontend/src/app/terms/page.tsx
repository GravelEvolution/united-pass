//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Terms of service document page
//

import type { Metadata } from "next";
import { LegalDocument } from "@/features/legal/components/legal-document";
import { termsSections } from "@/features/legal/data/terms-sections";
import { getLegalPublication, legalEffectiveDate } from "@/lib/api/server/legal-queries";

export const metadata: Metadata = { title: "服务条款" };
export const dynamic = "force-dynamic";

export default async function TermsPage() {
  const publication = await getLegalPublication("terms");
  return (
    <LegalDocument
      eyebrow="Terms"
      title="服务条款"
      summary="请您在注册或使用本服务前仔细阅读并充分理解本服务条款。您一旦注册或使用本服务，即视为您已同意接受本条款的全部约束。本条款与《隐私政策》共同构成您与我们之间关于本服务的完整协议。"
      version="1.1"
      effectiveDate={legalEffectiveDate(publication)}
      sections={termsSections}
      relatedHref="/privacy"
      relatedLabel="查看隐私政策"
    />
  );
}
