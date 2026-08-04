export type SecurityFactor = {
  factorId: string;
  kind: "password" | "totp" | "passkey";
  label: string;
  status: "active" | "recommended";
  updatedAt?: string;
};

export type UserSession = {
  sessionId: string;
  deviceName: string;
  clientName: string;
  approximateLocation: string;
  ipAddressMasked: string;
  lastActiveAt: string;
  isCurrent: boolean;
};

export type AuthorizedApplication = {
  grantId: string;
  applicationId: string;
  applicationName: string;
  applicationOwner: string;
  clientType: "public" | "confidential";
  grantedAt: string;
  lastUsedAt: string | null;
  scopes: string[];
  hasOfflineAccess: boolean;
  status: "active" | "revoked";
};
