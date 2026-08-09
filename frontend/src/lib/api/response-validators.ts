//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Runtime narrowing of untrusted HTTP response bodies onto the
//              frozen frontend contract types
//

import type {
  ConsentRequest,
  ConsentResolution,
  ConsentScope,
} from "@/features/authorization/types";
import type {
  AuthorizedApplication,
  PasskeyEnrollment,
  PasskeyEnrollmentConfirmation,
  ReauthenticationGrant,
  ReauthenticationOutcome,
  SecurityPasskey,
  SecuritySummary,
} from "@/features/account/types";
import type { MfaMethod } from "@/features/auth/types";
import type { CurrentUser, EmployeeProfile, UserPersona } from "@/types/identity";

/**
 * Response body validators for the real HTTP seams.
 *
 * Backend responses are untrusted runtime data (AGENTS.md §16): every seam
 * narrows the parsed JSON onto the frozen contract types before it reaches
 * a page or component. A malformed body is a contract violation and throws
 * instead of rendering partial or fabricated facts; server queries surface
 * it through the route error boundary, browser commands through their error
 * states.
 *
 * The ConsentResolution union is frozen (frontend-freeze-v1.md, ADR-0005
 * §12): these parsers accept exactly its members and nothing else.
 */

export class ApiResponseShapeError extends Error {
  constructor(contract: string) {
    super(`API response does not match the ${contract} contract`);
    this.name = "ApiResponseShapeError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string") {
    throw new ApiResponseShapeError(field);
  }
  return value;
}

function requireNonEmptyString(record: Record<string, unknown>, field: string): string {
  const value = requireString(record, field);
  if (value.length === 0) throw new ApiResponseShapeError(field);
  return value;
}

function optionalString(record: Record<string, unknown>, field: string): string | undefined {
  const value = record[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new ApiResponseShapeError(field);
  }
  return value;
}

function requireBoolean(record: Record<string, unknown>, field: string): boolean {
  const value = record[field];
  if (typeof value !== "boolean") {
    throw new ApiResponseShapeError(field);
  }
  return value;
}

function requireStringArray(record: Record<string, unknown>, field: string): string[] {
  const value = record[field];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new ApiResponseShapeError(field);
  }
  return value as string[];
}

// --- ConsentResolution ---

function parseConsentScope(value: unknown): ConsentScope {
  if (!isRecord(value)) throw new ApiResponseShapeError("ConsentScope");
  return {
    scope: requireString(value, "scope"),
    label: requireString(value, "label"),
    description: requireString(value, "description"),
  };
}

function parseConsentRequest(value: unknown): ConsentRequest {
  if (!isRecord(value)) throw new ApiResponseShapeError("ConsentRequest");
  const scopesValue = value.scopes;
  if (!Array.isArray(scopesValue)) throw new ApiResponseShapeError("ConsentRequest.scopes");
  return {
    requestId: requireString(value, "requestId"),
    applicationName: requireString(value, "applicationName"),
    applicationDescription: requireString(value, "applicationDescription"),
    applicationOwner: requireString(value, "applicationOwner"),
    redirectHost: requireString(value, "redirectHost"),
    scopes: scopesValue.map(parseConsentScope),
  };
}

/**
 * Narrows an untrusted resolution body onto the frozen ConsentResolution
 * union. Unknown statuses are rejected: the page must never render a union
 * member the contract does not define.
 */
export function parseConsentResolution(value: unknown): ConsentResolution {
  if (!isRecord(value)) throw new ApiResponseShapeError("ConsentResolution");
  const status = value.status;

  switch (status) {
    case "valid":
      return { status, request: parseConsentRequest(value.request) };
    case "expired":
      return {
        status,
        requestId: requireString(value, "requestId"),
        expiredAt: requireString(value, "expiredAt"),
      };
    case "client_not_found":
    case "unauthenticated":
      return { status, requestId: requireString(value, "requestId") };
    case "redirect_mismatch":
      return {
        status,
        requestId: requireString(value, "requestId"),
        attemptedRedirect: requireString(value, "attemptedRedirect"),
      };
    case "scope_not_allowed":
      return {
        status,
        requestId: requireString(value, "requestId"),
        disallowedScopes: requireStringArray(value, "disallowedScopes"),
      };
    case "already_authorized":
      return {
        status,
        requestId: requireString(value, "requestId"),
        applicationName: requireString(value, "applicationName"),
        redirectHost: requireString(value, "redirectHost"),
      };
    default:
      throw new ApiResponseShapeError("ConsentResolution.status");
  }
}

/** Narrows the decision response: the provider-verified callback URL. */
export function parseDecisionResponse(value: unknown): { redirectUrl: string } {
  if (!isRecord(value)) throw new ApiResponseShapeError("ConsentDecisionResponse");
  const redirectUrl = value.redirectUrl;
  if (typeof redirectUrl !== "string" || redirectUrl.length === 0) {
    throw new ApiResponseShapeError("ConsentDecisionResponse.redirectUrl");
  }
  return { redirectUrl };
}

// --- Account security / P4.5 passkeys ---

function parseSecurityPasskey(value: unknown): SecurityPasskey {
  if (!isRecord(value)) throw new ApiResponseShapeError("SecurityPasskey");
  const state = value.state;
  if (state !== "active" && state !== "pending") {
    throw new ApiResponseShapeError("SecurityPasskey.state");
  }
  const createdAt = value.createdAt;
  if (createdAt !== null && typeof createdAt !== "string") {
    throw new ApiResponseShapeError("SecurityPasskey.createdAt");
  }
  return {
    passkeyId: requireNonEmptyString(value, "passkeyId"),
    createdAt,
    state,
  };
}

export function parseSecuritySummary(value: unknown): SecuritySummary {
  if (!isRecord(value)) throw new ApiResponseShapeError("SecuritySummary");
  if (!isRecord(value.password) || !isRecord(value.totp)) {
    throw new ApiResponseShapeError("SecuritySummary.factorState");
  }
  if (!Array.isArray(value.passkeys)) {
    throw new ApiResponseShapeError("SecuritySummary.passkeys");
  }
  if (!isRecord(value.recoveryCodes)) {
    throw new ApiResponseShapeError("SecuritySummary.recoveryCodes");
  }
  if (
    value.recoveryCodes.available !== false ||
    value.recoveryCodes.deferredReason !== "provider_unsupported"
  ) {
    throw new ApiResponseShapeError("SecuritySummary.recoveryCodes");
  }
  return {
    password: { set: requireBoolean(value.password, "set") },
    totp: { enabled: requireBoolean(value.totp, "enabled") },
    passkeys: value.passkeys.map(parseSecurityPasskey),
    recoveryCodes: {
      available: false,
      deferredReason: "provider_unsupported",
    },
  };
}

function parseReauthenticationGrantRecord(
  value: Record<string, unknown>,
): ReauthenticationGrant {
  if (value.status !== "granted") {
    throw new ApiResponseShapeError("ReauthenticationGrant.status");
  }
  return {
    status: "granted",
    reauthToken: requireNonEmptyString(value, "reauthToken"),
    expiresAt: requireNonEmptyString(value, "expiresAt"),
  };
}

export function parseReauthenticationGrant(value: unknown): ReauthenticationGrant {
  if (!isRecord(value)) throw new ApiResponseShapeError("ReauthenticationGrant");
  return parseReauthenticationGrantRecord(value);
}

export function parseReauthenticationOutcome(value: unknown): ReauthenticationOutcome {
  if (!isRecord(value)) throw new ApiResponseShapeError("ReauthenticationOutcome");
  if (value.status === "granted") return parseReauthenticationGrantRecord(value);
  if (value.status !== "mfa_required") {
    throw new ApiResponseShapeError("ReauthenticationOutcome.status");
  }
  if (!Array.isArray(value.availableMethods) || value.availableMethods.length === 0) {
    throw new ApiResponseShapeError("ReauthenticationChallenge.availableMethods");
  }
  const availableMethods = value.availableMethods.map((method) => {
    if (method !== "totp" && method !== "passkey") {
      throw new ApiResponseShapeError("ReauthenticationChallenge.availableMethods");
    }
    return method;
  });
  const passkeyRequestOptions = value.passkeyRequestOptions;
  if (availableMethods.includes("passkey") && !isRecord(passkeyRequestOptions)) {
    throw new ApiResponseShapeError("ReauthenticationChallenge.passkeyRequestOptions");
  }
  return {
    status: "mfa_required",
    reauthToken: requireNonEmptyString(value, "reauthToken"),
    availableMethods,
    ...(passkeyRequestOptions !== undefined && { passkeyRequestOptions }),
    expiresAt: requireNonEmptyString(value, "expiresAt"),
  };
}

export function parsePasskeyEnrollment(value: unknown): PasskeyEnrollment {
  if (!isRecord(value)) throw new ApiResponseShapeError("PasskeyEnrollment");
  if (!isRecord(value.publicKeyCredentialCreationOptions)) {
    throw new ApiResponseShapeError("PasskeyEnrollment.publicKeyCredentialCreationOptions");
  }
  return {
    enrollmentToken: requireNonEmptyString(value, "enrollmentToken"),
    passkeyId: requireNonEmptyString(value, "passkeyId"),
    publicKeyCredentialCreationOptions: value.publicKeyCredentialCreationOptions,
  };
}

export function parsePasskeyEnrollmentConfirmation(
  value: unknown,
  expectedPasskeyId: string,
): PasskeyEnrollmentConfirmation {
  if (!isRecord(value) || value.status !== "confirmed") {
    throw new ApiResponseShapeError("PasskeyEnrollmentConfirmation");
  }
  const passkeyId = requireNonEmptyString(value, "passkeyId");
  if (passkeyId !== expectedPasskeyId) {
    throw new ApiResponseShapeError("PasskeyEnrollmentConfirmation.passkeyId");
  }
  return { status: "confirmed", passkeyId };
}

// --- MFARequiredResponse ---

function parseMfaMethod(value: unknown): MfaMethod {
  if (value !== "totp" && value !== "passkey" && value !== "recovery_code") {
    throw new ApiResponseShapeError("MfaMethod");
  }
  return value;
}

/**
 * Narrows the 202 login response onto the frozen MFA challenge shape.
 * Unknown method values are rejected: the challenge UI must never render a
 * verification method the contract does not define.
 */
export function parseMfaRequiredResponse(value: unknown): {
  mfaToken: string;
  availableMethods: MfaMethod[];
} {
  if (!isRecord(value)) throw new ApiResponseShapeError("MFARequiredResponse");
  if (value.status !== "mfa_required") {
    throw new ApiResponseShapeError("MFARequiredResponse.status");
  }
  const methodsValue = value.availableMethods;
  if (!Array.isArray(methodsValue) || methodsValue.length === 0) {
    throw new ApiResponseShapeError("MFARequiredResponse.availableMethods");
  }
  return {
    mfaToken: requireString(value, "mfaToken"),
    availableMethods: methodsValue.map(parseMfaMethod),
  };
}

// --- AuthorizedApplication ---

function parseAuthorizedApplication(value: unknown): AuthorizedApplication {
  if (!isRecord(value)) throw new ApiResponseShapeError("AuthorizedApplication");

  const clientType = value.clientType;
  if (clientType !== "public" && clientType !== "confidential") {
    throw new ApiResponseShapeError("AuthorizedApplication.clientType");
  }
  const status = value.status;
  if (status !== "active" && status !== "revoked") {
    throw new ApiResponseShapeError("AuthorizedApplication.status");
  }
  const lastUsedAt = value.lastUsedAt;
  if (lastUsedAt !== null && typeof lastUsedAt !== "string") {
    throw new ApiResponseShapeError("AuthorizedApplication.lastUsedAt");
  }

  return {
    grantId: requireString(value, "grantId"),
    applicationId: requireString(value, "applicationId"),
    applicationName: requireString(value, "applicationName"),
    applicationOwner: requireString(value, "applicationOwner"),
    clientType,
    grantedAt: requireString(value, "grantedAt"),
    lastUsedAt,
    scopes: requireStringArray(value, "scopes"),
    hasOfflineAccess: requireBoolean(value, "hasOfflineAccess"),
    status,
  };
}

/** Narrows the authorized application listing body. */
export function parseAuthorizedApplications(value: unknown): AuthorizedApplication[] {
  if (!Array.isArray(value)) throw new ApiResponseShapeError("AuthorizedApplication[]");
  return value.map(parseAuthorizedApplication);
}

// --- CurrentUser ---

function parseUserPersona(value: unknown): UserPersona {
  if (value !== "consumer" && value !== "employee") {
    throw new ApiResponseShapeError("UserPersona");
  }
  return value;
}

function parseEmployeeProfile(value: unknown): EmployeeProfile | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value)) throw new ApiResponseShapeError("EmployeeProfile");
  return {
    employeeId: requireString(value, "employeeId"),
    departmentName: requireString(value, "departmentName"),
    title: requireString(value, "title"),
  };
}

/** Narrows the GET /api/v1/me body onto the frozen CurrentUser type. */
export function parseCurrentUser(value: unknown): CurrentUser {
  if (!isRecord(value)) throw new ApiResponseShapeError("CurrentUser");
  const personasValue = value.personas;
  if (!Array.isArray(personasValue)) throw new ApiResponseShapeError("CurrentUser.personas");

  const user: CurrentUser = {
    userId: requireString(value, "userId"),
    displayName: requireString(value, "displayName"),
    email: requireString(value, "email"),
    phoneMasked: requireString(value, "phoneMasked"),
    personas: personasValue.map(parseUserPersona),
  };

  const nickname = optionalString(value, "nickname");
  if (nickname !== undefined) user.nickname = nickname;
  const avatarUrl = optionalString(value, "avatarUrl");
  if (avatarUrl !== undefined) user.avatarUrl = avatarUrl;
  const employeeProfile = parseEmployeeProfile(value.employeeProfile);
  if (employeeProfile !== undefined) user.employeeProfile = employeeProfile;

  return user;
}
