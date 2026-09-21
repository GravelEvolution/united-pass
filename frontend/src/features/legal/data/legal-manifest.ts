//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
// Phase 8 immutable legal-document release manifest
//

export const legalManifest = {
  privacy: {
    version: "1.2",
    contentSha256: "7049fcf671c7de0774bd0a167be5ea98b5ec2c6a399483792f5534b23b3093a7",
  },
  terms: {
    version: "1.1",
    contentSha256: "2f9ef24f40273f95c2ac06aa0dae23f0c967bb5db23d232fa0f46e69015dab95",
  },
} as const;

export type LegalDocumentKind = keyof typeof legalManifest;

export type PublicLegalPublication = {
  documentKind: LegalDocumentKind;
  version: string;
  contentSha256: string;
  effectiveAt: string;
  publishedAt: string;
  status: "scheduled" | "effective";
};
