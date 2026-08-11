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

export type AccountReauthenticationAction =
  | "account.password.change"
  | "account.totp.enroll"
  | "account.totp.remove"
  | "account.passkey.enroll"
  | "account.passkey.remove";

export type AdminReauthenticationAction =
  | "user.disable"
  | "user.sessions.revoke"
  | "employee.offboard"
  | "provider.enable"
  | "provider.disable"
  | "provider.identity.link"
  | "policy.publish"
  | "audit.export";

export type ReauthenticationAction =
  | AccountReauthenticationAction
  | AdminReauthenticationAction;

export type ReauthenticationInput = {
  action: ReauthenticationAction;
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

export type TotpEnrollment = {
  enrollmentToken: string;
  secret: string;
  otpauthUri: string;
};

export type UserSession = {
  sessionId: string;
  deviceName: string;
  clientName: string;
  approximateLocation: string | null;
  ipAddressMasked: string;
  lastActiveAt: string;
  createdAt: string;
  authenticationMethods: string[];
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
