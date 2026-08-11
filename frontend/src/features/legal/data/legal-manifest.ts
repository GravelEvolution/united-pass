//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
// Phase 8 immutable legal-document release manifest
//

export const legalManifest = {
  privacy: {
    version: "1.2",
    contentSha256: "4cda76af14c0eba4324feb26d45f9e39a8f44e0567f56034d3f97c9b34283703",
  },
  terms: {
    version: "1.1",
    contentSha256: "d277370701594a556be7d53a965c9d87ef7825296e7f647af2d46451dc3e24fb",
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
