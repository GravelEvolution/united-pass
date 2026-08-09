//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Account feature contract types
//

export type AccountProfile = {
  displayName: string;
  nickname?: string;
  avatarUrl?: string;
  email: string;
  phoneMasked: string;
};

export type SecurityPasskey = {
  passkeyId: string;
  createdAt: string | null;
  state: "active" | "pending";
};

export type SecuritySummary = {
  password: { set: boolean };
  totp: { enabled: boolean };
  passkeys: SecurityPasskey[];
  recoveryCodes: {
    available: false;
    deferredReason: "provider_unsupported";
  };
};

export type PasskeyReauthenticationAction =
  | "account.passkey.enroll"
  | "account.passkey.remove";

export type ReauthenticationInput = {
  action: PasskeyReauthenticationAction;
  target: string;
  password: string;
};

export type ReauthenticationGrant = {
  status: "granted";
  reauthToken: string;
  expiresAt: string;
};

export type ReauthenticationChallenge = {
  status: "mfa_required";
  reauthToken: string;
  availableMethods: Array<"totp" | "passkey">;
  passkeyRequestOptions?: unknown;
  expiresAt: string;
};

export type ReauthenticationOutcome =
  | ReauthenticationGrant
  | ReauthenticationChallenge;

export type SerializedAttestationCredential = {
  id: string;
  rawId: string;
  type: "public-key";
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: AuthenticatorTransport[];
  };
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment?: "platform" | "cross-platform" | null;
};

export type SerializedAssertionCredential = {
  id: string;
  rawId: string;
  type: "public-key";
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment?: "platform" | "cross-platform" | null;
};

export type PasskeyEnrollment = {
  enrollmentToken: string;
  passkeyId: string;
  publicKeyCredentialCreationOptions: unknown;
};

export type PasskeyEnrollmentConfirmation = {
  status: "confirmed";
  passkeyId: string;
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
