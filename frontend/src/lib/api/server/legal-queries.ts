//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
// Date: 2026-08-11
// Description: Public legal-publication status query with manifest verification
//

import "server-only";

import {
  legalManifest,
  type LegalDocumentKind,
  type PublicLegalPublication,
} from "@/features/legal/data/legal-manifest";
import { SERVER_API_BASE_URL } from "@/lib/api/constants";

export async function getLegalPublication(
  kind: LegalDocumentKind,
): Promise<PublicLegalPublication | null> {
  try {
    const response = await fetch(`${SERVER_API_BASE_URL}/legal-documents`, {
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return null;
    const value: unknown = await response.json();
    if (!isRecord(value) || !Array.isArray(value.items)) return null;
    const publication = value.items.find((item) => isRecord(item) && item.documentKind === kind);
    if (!isRecord(publication)) return null;
    const manifest = legalManifest[kind];
    if (
      publication.version !== manifest.version ||
      publication.contentSha256 !== manifest.contentSha256 ||
      (publication.status !== "scheduled" && publication.status !== "effective") ||
      typeof publication.effectiveAt !== "string" ||
      typeof publication.publishedAt !== "string"
    ) {
      return null;
    }
    return {
      documentKind: kind,
      version: manifest.version,
      contentSha256: manifest.contentSha256,
      effectiveAt: publication.effectiveAt,
      publishedAt: publication.publishedAt,
      status: publication.status,
    };
  } catch {
    return null;
  }
}

export function legalEffectiveDate(publication: PublicLegalPublication | null): string {
  if (publication === null) return "暂未生效（等待法务批准与受控发布）";
  const formatted = new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "Asia/Shanghai",
  }).format(new Date(publication.effectiveAt));
  return publication.status === "effective" ? formatted : `计划于 ${formatted} 生效`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
