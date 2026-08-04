import type { Metadata } from "next";
import { PolicyEditor } from "@/features/policies/components/policy-editor";

export const metadata: Metadata = { title: "新建策略" };
export const dynamic = "force-dynamic";

export default function NewPolicyPage() {
  return <PolicyEditor />;
}
