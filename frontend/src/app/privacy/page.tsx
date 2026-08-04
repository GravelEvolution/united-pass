import type { Metadata } from "next";
import { LegalDocument } from "@/features/legal/components/legal-document";
import { privacySections } from "@/features/legal/data/privacy-sections";

export const metadata: Metadata = { title: "隐私政策" };

export default function PrivacyPage() {
  return (
    <LegalDocument
      eyebrow="Privacy"
      title="隐私政策"
      summary="我们以最小必要、目的明确和安全可控为原则处理您的个人信息。本政策详细说明我们收集的信息类型、使用目的、共享与保护措施，以及您依法享有的权利。"
      version="1.2"
      effectiveDate="2026年8月5日"
      sections={privacySections}
      relatedHref="/terms"
      relatedLabel="查看服务条款"
    />
  );
}
