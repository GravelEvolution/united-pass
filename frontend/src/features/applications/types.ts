export type OAuthApplication = {
  applicationId: string;
  name: string;
  clientType: "public" | "confidential";
  ownerName: string;
  status: "active" | "disabled";
  redirectUriCount: number;
  updatedAt: string;
};

export type ApplicationKind = "internal" | "public-app" | "hybrid";

export type ApplicationKindLabel = {
  value: ApplicationKind;
  label: string;
  description: string;
};

export type RedirectUriEntry = {
  uri: string;
  isLoopback: boolean;
  addedAt: string;
};

export type AllowedScope = {
  scope: string;
  label: string;
  description: string;
  required: boolean;
};

export type ClientSecretRecord = {
  secretId: string;
  label: string;
  createdAt: string;
  lastRotatedAt: string | null;
};

export type ApplicationGrantSummary = {
  grantId: string;
  userLabel: string;
  scopes: string[];
  grantedAt: string;
  lastUsedAt: string | null;
  status: "active" | "revoked";
};

export type ApplicationAuditEntry = {
  eventId: string;
  eventType: string;
  actorName: string;
  occurredAt: string;
  result: "success" | "denied";
};

export type OAuthApplicationDetail = {
  applicationId: string;
  name: string;
  description: string;
  logoUrl: string | null;
  kind: ApplicationKind;
  clientType: "public" | "confidential";
  clientId: string;
  status: "active" | "disabled";
  ownerName: string;
  redirectUris: RedirectUriEntry[];
  logoutUri: string | null;
  allowedScopes: AllowedScope[];
  consentRequired: boolean;
  clientSecrets: ClientSecretRecord[];
  grants: ApplicationGrantSummary[];
  auditEntries: ApplicationAuditEntry[];
  createdAt: string;
  updatedAt: string;
};

export type ApplicationCreateInput = {
  name: string;
  description: string;
  kind: ApplicationKind;
  clientType: "public" | "confidential";
  redirectUris: string[];
  logoutUri: string;
  allowedScopes: string[];
  ownerName: string;
  consentRequired: boolean;
};

export type ApplicationCreationResult = {
  applicationId: string;
  clientId: string;
  clientSecret?: string;
};
