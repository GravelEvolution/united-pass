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
  AccountDeletion,
  AuthorizedApplication,
  PasskeyEnrollment,
  PasskeyEnrollmentConfirmation,
  PersonalDataExport,
  ReauthenticationGrant,
  ReauthenticationOutcome,
  SecurityPasskey,
  SecuritySummary,
  TotpEnrollment,
  UserSession,
} from "@/features/account/types";
import type { MfaMethod } from "@/features/auth/types";
import type { CurrentUser, EmployeeProfile, UserPersona } from "@/types/identity";
import type {
  AuditEvent,
  AuditExportResult,
  DashboardMetric,
  DepartmentDetail,
  DepartmentRecord,
  DirectorySyncHistoryEntry,
  DirectorySyncResult,
  EmployeeDetail,
  EmployeeRecord,
  IdentityProviderRecord,
  ManagedUser,
  ProviderDetail,
  SyncConflict,
  UserDetail,
} from "@/features/admin/types";
import type { AdminDashboard } from "@/lib/api/united-pass-data-source";
import type {
  AuthorizationPolicy,
  PolicyCondition,
  PolicyDetail,
  PolicyPrincipal,
  PolicySimulationResult,
} from "@/features/policies/types";
import type { CursorPage } from "@/types/pagination";
import type { PermissionCapabilities } from "@/types/permissions";
import type {
  AllowedScope,
  ApplicationAuditEntry,
  ApplicationAudience,
  ApplicationGrantSummary,
  ApplicationStatus,
  ApplicationWithInitialClientResult,
  ConsentMode,
  OAuthApplication,
  OAuthApplicationDetail,
  OAuthClient,
  OAuthClientCreationResult,
  OAuthGrantType,
  SecretRotationResult,
  TokenEndpointAuthMethod,
} from "@/features/applications/types";

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

function parseDashboardMetric(value: unknown): DashboardMetric {
  if (!isRecord(value)) throw new ApiResponseShapeError("DashboardMetric");
  const tone = value.tone;
  if (tone !== "neutral" && tone !== "positive" && tone !== "attention") {
    throw new ApiResponseShapeError("DashboardMetric.tone");
  }
  return {
    label: requireNonEmptyString(value, "label"),
    value: requireString(value, "value"),
    change: requireString(value, "change"),
    tone,
  };
}

export function parseAdminDashboard(value: unknown): AdminDashboard {
  if (!isRecord(value)) throw new ApiResponseShapeError("AdminDashboard");
  return {
    metrics: requireArray(value, "metrics").map(parseDashboardMetric),
    recentEvents: requireArray(value, "recentEvents").map(parseAuditEvent),
  };
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

function requireNonNegativeInteger(record: Record<string, unknown>, field: string): number {
  const value = record[field];
  if (!Number.isInteger(value) || (value as number) < 0) {
    throw new ApiResponseShapeError(field);
  }
  return value as number;
}

function requirePositiveInteger(record: Record<string, unknown>, field: string): number {
  const value = requireNonNegativeInteger(record, field);
  if (value < 1) throw new ApiResponseShapeError(field);
  return value;
}

function requireNullableString(record: Record<string, unknown>, field: string): string | null {
  const value = record[field];
  if (value !== null && typeof value !== "string") {
    throw new ApiResponseShapeError(field);
  }
  return value;
}

function requireArray(record: Record<string, unknown>, field: string): unknown[] {
  const value = record[field];
  if (!Array.isArray(value)) throw new ApiResponseShapeError(field);
  return value;
}

function parseCursorPage<T>(
  value: unknown,
  contract: string,
  parseItem: (item: unknown) => T,
): CursorPage<T> {
  if (!isRecord(value) || !isRecord(value.page)) {
    throw new ApiResponseShapeError(contract);
  }
  const nextCursor = value.page.nextCursor;
  if (nextCursor !== null && typeof nextCursor !== "string") {
    throw new ApiResponseShapeError(`${contract}.page.nextCursor`);
  }
  return {
    items: requireArray(value, "items").map(parseItem),
    page: {
      nextCursor,
      hasMore: requireBoolean(value.page, "hasMore"),
    },
  };
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

export function parseTotpEnrollment(value: unknown): TotpEnrollment {
  if (!isRecord(value)) throw new ApiResponseShapeError("TotpEnrollment");
  const otpauthUri = requireNonEmptyString(value, "otpauthUri");
  if (!otpauthUri.startsWith("otpauth://")) {
    throw new ApiResponseShapeError("TotpEnrollment.otpauthUri");
  }
  return {
    enrollmentToken: requireNonEmptyString(value, "enrollmentToken"),
    secret: requireNonEmptyString(value, "secret"),
    otpauthUri,
  };
}

export function parseTotpEnrollmentConfirmation(value: unknown): void {
  if (!isRecord(value) || value.status !== "confirmed") {
    throw new ApiResponseShapeError("TotpEnrollmentConfirmation");
  }
}

function parseUserSession(value: unknown): UserSession {
  if (!isRecord(value)) throw new ApiResponseShapeError("UserSession");
  const approximateLocation = value.approximateLocation;
  if (approximateLocation !== null && typeof approximateLocation !== "string") {
    throw new ApiResponseShapeError("UserSession.approximateLocation");
  }
  return {
    sessionId: requireNonEmptyString(value, "sessionId"),
    deviceName: requireString(value, "deviceName"),
    clientName: requireString(value, "clientName"),
    approximateLocation,
    ipAddressMasked: requireString(value, "ipAddressMasked"),
    lastActiveAt: requireNonEmptyString(value, "lastActiveAt"),
    createdAt: requireNonEmptyString(value, "createdAt"),
    authenticationMethods: requireStringArray(value, "authenticationMethods"),
    isCurrent: requireBoolean(value, "isCurrent"),
  };
}

export function parseUserSessions(value: unknown): UserSession[] {
  if (!Array.isArray(value)) throw new ApiResponseShapeError("UserSession[]");
  return value.map(parseUserSession);
}

export function parseRevokedSessionCount(value: unknown): { revoked: number } {
  if (!isRecord(value)) throw new ApiResponseShapeError("RevokedSessionCount");
  return { revoked: requireNonNegativeInteger(value, "revoked") };
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
  passkeyRequestOptions?: unknown;
  expiresAt: string;
} {
  if (!isRecord(value)) throw new ApiResponseShapeError("MFARequiredResponse");
  if (value.status !== "mfa_required") {
    throw new ApiResponseShapeError("MFARequiredResponse.status");
  }
  const methodsValue = value.availableMethods;
  if (!Array.isArray(methodsValue) || methodsValue.length === 0) {
    throw new ApiResponseShapeError("MFARequiredResponse.availableMethods");
  }
  const availableMethods = methodsValue.map(parseMfaMethod);
  const passkeyRequestOptions = value.passkeyRequestOptions;
  if (availableMethods.includes("passkey") && !isRecord(passkeyRequestOptions)) {
    throw new ApiResponseShapeError("MFARequiredResponse.passkeyRequestOptions");
  }
  return {
    mfaToken: requireString(value, "mfaToken"),
    availableMethods,
    ...(passkeyRequestOptions !== undefined && { passkeyRequestOptions }),
    expiresAt: requireNonEmptyString(value, "expiresAt"),
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

// --- Phase 8 privacy rights ---

export function parsePersonalDataExport(value: unknown): PersonalDataExport {
  if (!isRecord(value)) throw new ApiResponseShapeError("PersonalDataExport");
  const status = value.status;
  if (status !== "pending" && status !== "processing" && status !== "completed" && status !== "failed") {
    throw new ApiResponseShapeError("PersonalDataExport.status");
  }
  return {
    exportId: requireNonEmptyString(value, "exportId"),
    status,
    requestedAt: requireNonEmptyString(value, "requestedAt"),
    completedAt: requireNullableString(value, "completedAt"),
    expiresAt: requireNullableString(value, "expiresAt"),
    downloadUrl: requireNullableString(value, "downloadUrl"),
    totalSections: requireNonNegativeInteger(value, "totalSections"),
  };
}

export function parseAccountDeletion(value: unknown): AccountDeletion {
  if (!isRecord(value)) throw new ApiResponseShapeError("AccountDeletion");
  if (value.status === "none") return { status: "none" };
  const status = value.status;
  if (
    status !== "pending" &&
    status !== "processing" &&
    status !== "provider_deleted" &&
    status !== "completed" &&
    status !== "cancelled" &&
    status !== "failed"
  ) {
    throw new ApiResponseShapeError("AccountDeletion.status");
  }
  return {
    deletionId: requireNonEmptyString(value, "deletionId"),
    status,
    requestedAt: requireNonEmptyString(value, "requestedAt"),
    executeAfter: requireNonEmptyString(value, "executeAfter"),
    cancelledAt: requireNullableString(value, "cancelledAt"),
    completedAt: requireNullableString(value, "completedAt"),
  };
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

// --- OAuth application and client management ---

function parseApplicationAudience(value: unknown): ApplicationAudience {
  if (value === "internal" || value === "external" || value === "hybrid") return value;
  throw new ApiResponseShapeError("Application.audience");
}

function parseApplicationStatus(value: unknown): ApplicationStatus {
  if (value === "active" || value === "disabled") return value;
  throw new ApiResponseShapeError("Application.status");
}

function parseOAuthGrantType(value: unknown): OAuthGrantType {
  if (
    value === "authorization_code" ||
    value === "refresh_token" ||
    value === "client_credentials"
  ) return value;
  throw new ApiResponseShapeError("OAuthClient.grantTypes");
}

function parseTokenEndpointAuthMethod(value: unknown): TokenEndpointAuthMethod {
  if (
    value === "client_secret_post" ||
    value === "client_secret_basic" ||
    value === "none" ||
    value === "private_key_jwt"
  ) return value;
  throw new ApiResponseShapeError("OAuthClient.tokenEndpointAuthMethod");
}

function parseConsentMode(value: unknown): ConsentMode {
  if (value === "always" || value === "first_authorization") return value;
  throw new ApiResponseShapeError("OAuthClient.consentMode");
}

function parseAllowedScope(value: unknown): AllowedScope {
  if (!isRecord(value)) throw new ApiResponseShapeError("AllowedScope");
  return {
    scope: requireNonEmptyString(value, "scope"),
    label: requireString(value, "label"),
    description: requireString(value, "description"),
    required: requireBoolean(value, "required"),
  };
}

export function parseAvailableScopes(value: unknown): AllowedScope[] {
  if (!Array.isArray(value)) throw new ApiResponseShapeError("AllowedScope[]");
  return value.map(parseAllowedScope);
}

export function parseOAuthClient(value: unknown): OAuthClient {
  if (!isRecord(value)) throw new ApiResponseShapeError("OAuthClient");
  const clientType = value.clientType;
  if (clientType !== "public" && clientType !== "confidential") {
    throw new ApiResponseShapeError("OAuthClient.clientType");
  }

  return {
    clientId: requireNonEmptyString(value, "clientId"),
    applicationId: requireNonEmptyString(value, "applicationId"),
    name: requireString(value, "name"),
    clientType,
    grantTypes: requireArray(value, "grantTypes").map(parseOAuthGrantType),
    tokenEndpointAuthMethod: parseTokenEndpointAuthMethod(value.tokenEndpointAuthMethod),
    redirectUris: requireArray(value, "redirectUris").map((item) => {
      if (!isRecord(item)) throw new ApiResponseShapeError("OAuthClient.redirectUris");
      return {
        uri: requireNonEmptyString(item, "uri"),
        isLoopback: requireBoolean(item, "isLoopback"),
        addedAt: requireNonEmptyString(item, "addedAt"),
      };
    }),
    logoutUri: requireNullableString(value, "logoutUri"),
    allowedScopes: requireArray(value, "allowedScopes").map(parseAllowedScope),
    consentMode: parseConsentMode(value.consentMode),
    status: parseApplicationStatus(value.status),
    clientSecrets: requireArray(value, "clientSecrets").map((item) => {
      if (!isRecord(item)) throw new ApiResponseShapeError("OAuthClient.clientSecrets");
      return {
        secretId: requireNonEmptyString(item, "secretId"),
        label: requireString(item, "label"),
        createdAt: requireNonEmptyString(item, "createdAt"),
        lastRotatedAt: requireNullableString(item, "lastRotatedAt"),
      };
    }),
    createdAt: requireNonEmptyString(value, "createdAt"),
    updatedAt: requireNonEmptyString(value, "updatedAt"),
  };
}

function parseOAuthApplication(value: unknown): OAuthApplication {
  if (!isRecord(value)) throw new ApiResponseShapeError("OAuthApplication");
  return {
    applicationId: requireNonEmptyString(value, "applicationId"),
    name: requireString(value, "name"),
    audience: parseApplicationAudience(value.audience),
    ownerId: requireNonEmptyString(value, "ownerId"),
    ownerName: requireString(value, "ownerName"),
    status: parseApplicationStatus(value.status),
    clientCount: requireNonNegativeInteger(value, "clientCount"),
    updatedAt: requireNonEmptyString(value, "updatedAt"),
  };
}

export function parseApplications(value: unknown): CursorPage<OAuthApplication> {
  return parseCursorPage(value, "OAuthApplicationListResponse", parseOAuthApplication);
}

function parseApplicationGrant(value: unknown): ApplicationGrantSummary {
  if (!isRecord(value)) throw new ApiResponseShapeError("ApplicationGrantSummary");
  const status = value.status;
  if (status !== "active" && status !== "revoked") {
    throw new ApiResponseShapeError("ApplicationGrantSummary.status");
  }
  return {
    grantId: requireNonEmptyString(value, "grantId"),
    userLabel: requireString(value, "userLabel"),
    scopes: requireStringArray(value, "scopes"),
    grantedAt: requireNonEmptyString(value, "grantedAt"),
    lastUsedAt: requireNullableString(value, "lastUsedAt"),
    status,
  };
}

function parseApplicationAuditEntry(value: unknown): ApplicationAuditEntry {
  if (!isRecord(value)) throw new ApiResponseShapeError("ApplicationAuditEntry");
  const result = value.result;
  if (result !== "success" && result !== "denied") {
    throw new ApiResponseShapeError("ApplicationAuditEntry.result");
  }
  return {
    eventId: requireNonEmptyString(value, "eventId"),
    eventType: requireString(value, "eventType"),
    actorName: requireString(value, "actorName"),
    occurredAt: requireNonEmptyString(value, "occurredAt"),
    result,
  };
}

export function parseApplicationDetail(value: unknown): OAuthApplicationDetail {
  if (!isRecord(value)) throw new ApiResponseShapeError("OAuthApplicationDetail");
  return {
    applicationId: requireNonEmptyString(value, "applicationId"),
    name: requireString(value, "name"),
    description: requireString(value, "description"),
    logoUrl: requireNullableString(value, "logoUrl"),
    audience: parseApplicationAudience(value.audience),
    ownerId: requireNonEmptyString(value, "ownerId"),
    ownerName: requireString(value, "ownerName"),
    status: parseApplicationStatus(value.status),
    clients: requireArray(value, "clients").map(parseOAuthClient),
    grants: requireArray(value, "grants").map(parseApplicationGrant),
    auditEntries: requireArray(value, "auditEntries").map(parseApplicationAuditEntry),
    createdAt: requireNonEmptyString(value, "createdAt"),
    updatedAt: requireNonEmptyString(value, "updatedAt"),
  };
}

export function parseOAuthClientCreation(value: unknown): OAuthClientCreationResult {
  if (!isRecord(value)) throw new ApiResponseShapeError("OAuthClientCreationResult");
  const clientSecret = optionalString(value, "clientSecret");
  return {
    clientId: requireNonEmptyString(value, "clientId"),
    ...(clientSecret !== undefined && { clientSecret }),
  };
}

export function parseApplicationWithInitialClientCreation(
  value: unknown,
): ApplicationWithInitialClientResult {
  if (!isRecord(value)) {
    throw new ApiResponseShapeError("ApplicationWithInitialClientResult");
  }
  const clientSecret = optionalString(value, "clientSecret");
  return {
    applicationId: requireNonEmptyString(value, "applicationId"),
    clientId: requireNonEmptyString(value, "clientId"),
    ...(clientSecret !== undefined && { clientSecret }),
  };
}

export function parseSecretRotation(value: unknown): SecretRotationResult {
  if (!isRecord(value)) throw new ApiResponseShapeError("SecretRotationResult");
  return {
    secretId: requireNonEmptyString(value, "secretId"),
    clientSecret: requireNonEmptyString(value, "clientSecret"),
    previousSecretExpiresAt: requireNonEmptyString(value, "previousSecretExpiresAt"),
  };
}

export function parseAvatarUpload(value: unknown): { avatarUrl: string } {
  if (!isRecord(value)) throw new ApiResponseShapeError("AvatarUploadResponse");
  const avatarUrl = requireNonEmptyString(value, "avatarUrl");
  if (!avatarUrl.startsWith("/api/v1/media/avatars/")) {
    throw new ApiResponseShapeError("AvatarUploadResponse.avatarUrl");
  }
  return { avatarUrl };
}

export function parseContactChangeRequest(value: unknown): { requestId: string } {
  if (!isRecord(value)) throw new ApiResponseShapeError("ContactChangeRequestResponse");
  return { requestId: requireNonEmptyString(value, "requestId") };
}

// --- Phase 5 identity and workforce management ---

export function parsePermissionCapabilities(value: unknown): PermissionCapabilities {
  if (!isRecord(value)) throw new ApiResponseShapeError("PermissionCapabilities");
  return {
    userRead: requireBoolean(value, "userRead"),
    userDisable: requireBoolean(value, "userDisable"),
    employeeManage: requireBoolean(value, "employeeManage"),
    employeeOffboard: requireBoolean(value, "employeeOffboard"),
    departmentManage: requireBoolean(value, "departmentManage"),
    applicationRead: requireBoolean(value, "applicationRead"),
    applicationManage: requireBoolean(value, "applicationManage"),
    applicationSecretRotate: requireBoolean(value, "applicationSecretRotate"),
    policyRead: requireBoolean(value, "policyRead"),
    policyManage: requireBoolean(value, "policyManage"),
    policyPublish: requireBoolean(value, "policyPublish"),
    auditRead: requireBoolean(value, "auditRead"),
    auditExport: requireBoolean(value, "auditExport"),
    providerRead: requireBoolean(value, "providerRead"),
    providerManage: requireBoolean(value, "providerManage"),
  };
}

function parseManagedUser(value: unknown): ManagedUser {
  if (!isRecord(value)) throw new ApiResponseShapeError("ManagedUser");
  const status = value.status;
  if (status !== "active" && status !== "disabled" && status !== "pending") {
    throw new ApiResponseShapeError("ManagedUser.status");
  }
  return {
    userId: requireNonEmptyString(value, "userId"),
    displayName: requireString(value, "displayName"),
    email: requireString(value, "email"),
    personaLabel: requireString(value, "personaLabel"),
    status,
    lastActiveAt: requireNonEmptyString(value, "lastActiveAt"),
  };
}

export function parseManagedUsers(value: unknown): CursorPage<ManagedUser> {
  return parseCursorPage(value, "ManagedUserListResponse", parseManagedUser);
}

function parseAuditEvent(value: unknown): AuditEvent {
  if (!isRecord(value)) throw new ApiResponseShapeError("AuditEvent");
  const result = value.result;
  if (result !== "success" && result !== "denied") {
    throw new ApiResponseShapeError("AuditEvent.result");
  }
  return {
    eventId: requireString(value, "eventId"),
    eventType: requireString(value, "eventType"),
    actorName: requireString(value, "actorName"),
    actorId: requireString(value, "actorId"),
    targetLabel: requireString(value, "targetLabel"),
    targetId: requireString(value, "targetId"),
    occurredAt: requireNonEmptyString(value, "occurredAt"),
    result,
    requestId: requireString(value, "requestId"),
    details: requireString(value, "details"),
  };
}

export function parseUserDetail(value: unknown): UserDetail {
  if (!isRecord(value)) throw new ApiResponseShapeError("UserDetail");
  const status = value.status;
  if (status !== "active" && status !== "disabled" && status !== "pending") {
    throw new ApiResponseShapeError("UserDetail.status");
  }
  const employeeProfile = parseEmployeeProfile(value.employeeProfile);
  const personas = requireArray(value, "personas").map(parseUserPersona);
  return {
    userId: requireNonEmptyString(value, "userId"),
    displayName: requireString(value, "displayName"),
    email: requireString(value, "email"),
    phoneMasked: requireString(value, "phoneMasked"),
    personaLabel: requireString(value, "personaLabel"),
    status,
    lastActiveAt: requireNonEmptyString(value, "lastActiveAt"),
    personas,
    ...(employeeProfile !== undefined && { employeeProfile }),
    linkedIdentities: requireArray(value, "linkedIdentities").map((item) => {
      if (!isRecord(item)) throw new ApiResponseShapeError("UserDetail.linkedIdentities");
      return {
        providerId: requireString(item, "providerId"),
        providerName: requireString(item, "providerName"),
        externalSubject: requireString(item, "externalSubject"),
        linkedAt: requireNonEmptyString(item, "linkedAt"),
      };
    }),
    activeSessions: requireArray(value, "activeSessions").map((item) => {
      if (!isRecord(item)) throw new ApiResponseShapeError("UserDetail.activeSessions");
      return {
        sessionId: requireNonEmptyString(item, "sessionId"),
        deviceName: requireString(item, "deviceName"),
        lastActiveAt: requireNonEmptyString(item, "lastActiveAt"),
        isCurrent: requireBoolean(item, "isCurrent"),
      };
    }),
    authorizedApplications: requireArray(value, "authorizedApplications").map((item) => {
      if (!isRecord(item)) throw new ApiResponseShapeError("UserDetail.authorizedApplications");
      const authorizationStatus = item.status;
      if (authorizationStatus !== "active" && authorizationStatus !== "revoked") {
        throw new ApiResponseShapeError("UserDetail.authorizedApplications.status");
      }
      return {
        applicationName: requireString(item, "applicationName"),
        scopes: requireStringArray(item, "scopes"),
        grantedAt: requireNonEmptyString(item, "grantedAt"),
        status: authorizationStatus,
      };
    }),
    recentAuditEvents: requireArray(value, "recentAuditEvents").map(parseAuditEvent),
  };
}

function parseEmployeeRecord(value: unknown): EmployeeRecord {
  if (!isRecord(value)) throw new ApiResponseShapeError("EmployeeRecord");
  const status = value.status;
  if (status !== "active" && status !== "offboarding") {
    throw new ApiResponseShapeError("EmployeeRecord.status");
  }
  return {
    userId: requireNonEmptyString(value, "userId"),
    displayName: requireString(value, "displayName"),
    employeeId: requireNonEmptyString(value, "employeeId"),
    departmentName: requireString(value, "departmentName"),
    title: requireString(value, "title"),
    status,
  };
}

export function parseEmployees(value: unknown): CursorPage<EmployeeRecord> {
  return parseCursorPage(value, "EmployeeListResponse", parseEmployeeRecord);
}

export function parseEmployeeDetail(value: unknown): EmployeeDetail {
  if (!isRecord(value)) throw new ApiResponseShapeError("EmployeeDetail");
  const status = value.status;
  if (status !== "active" && status !== "offboarding") {
    throw new ApiResponseShapeError("EmployeeDetail.status");
  }
  return {
    userId: requireNonEmptyString(value, "userId"),
    displayName: requireString(value, "displayName"),
    email: requireString(value, "email"),
    employeeId: requireNonEmptyString(value, "employeeId"),
    departmentName: requireString(value, "departmentName"),
    departmentId: requireNonEmptyString(value, "departmentId"),
    title: requireString(value, "title"),
    status,
    supervisorUserId: requireNullableString(value, "supervisorUserId"),
    supervisorName: requireNullableString(value, "supervisorName"),
    onboardedAt: requireNonEmptyString(value, "onboardedAt"),
    linkedConsumerAccount: requireBoolean(value, "linkedConsumerAccount"),
  };
}

function parseDepartmentRecord(value: unknown): DepartmentRecord {
  if (!isRecord(value)) throw new ApiResponseShapeError("DepartmentRecord");
  return {
    departmentId: requireNonEmptyString(value, "departmentId"),
    name: requireString(value, "name"),
    parentName: requireString(value, "parentName"),
    memberCount: requireNonNegativeInteger(value, "memberCount"),
    ownerName: requireString(value, "ownerName"),
  };
}

export function parseDepartments(value: unknown): DepartmentRecord[] {
  if (!Array.isArray(value)) throw new ApiResponseShapeError("DepartmentRecord[]");
  return value.map(parseDepartmentRecord);
}

export function parseDepartmentDetail(value: unknown): DepartmentDetail {
  if (!isRecord(value)) throw new ApiResponseShapeError("DepartmentDetail");
  return {
    departmentId: requireNonEmptyString(value, "departmentId"),
    name: requireString(value, "name"),
    parentDepartmentId: requireNullableString(value, "parentDepartmentId"),
    parentName: requireNullableString(value, "parentName"),
    ownerUserId: requireNullableString(value, "ownerUserId"),
    ownerName: requireString(value, "ownerName"),
    memberCount: requireNonNegativeInteger(value, "memberCount"),
    childDepartments: requireArray(value, "childDepartments").map((item) => {
      if (!isRecord(item)) throw new ApiResponseShapeError("DepartmentDetail.childDepartments");
      return {
        departmentId: requireNonEmptyString(item, "departmentId"),
        name: requireString(item, "name"),
        memberCount: requireNonNegativeInteger(item, "memberCount"),
      };
    }),
    members: requireArray(value, "members").map((item) => {
      if (!isRecord(item)) throw new ApiResponseShapeError("DepartmentDetail.members");
      return {
        userId: requireNonEmptyString(item, "userId"),
        displayName: requireString(item, "displayName"),
        title: requireString(item, "title"),
        employeeId: requireNonEmptyString(item, "employeeId"),
      };
    }),
  };
}

// --- Phase 6 identity Providers ---

function parseProviderStatus(value: unknown): "planned" | "active" | "disabled" {
  if (value === "planned" || value === "active" || value === "disabled") return value;
  throw new ApiResponseShapeError("Provider.status");
}

function parseProviderVendor(value: unknown): "feishu" | "generic" {
  if (value === "feishu" || value === "generic") return value;
  throw new ApiResponseShapeError("Provider.vendor");
}

function parseIdentityProvider(value: unknown): IdentityProviderRecord {
  if (!isRecord(value)) throw new ApiResponseShapeError("IdentityProviderRecord");
  return {
    providerId: requireNonEmptyString(value, "providerId"),
    displayName: requireString(value, "displayName"),
    vendor: parseProviderVendor(value.vendor),
    integrationLabel: requireString(value, "integrationLabel"),
    status: parseProviderStatus(value.status),
    loginEnabled: requireBoolean(value, "loginEnabled"),
    linkedUserCount: requireNonNegativeInteger(value, "linkedUserCount"),
    updatedAt: requireNonEmptyString(value, "updatedAt"),
  };
}

export function parseIdentityProviders(value: unknown): CursorPage<IdentityProviderRecord> {
  return parseCursorPage(value, "IdentityProviderPage", parseIdentityProvider);
}

function parseDirectorySyncStatus(value: unknown): DirectorySyncResult["status"] {
  if (value === "pending" || value === "running" || value === "success" || value === "partial" || value === "failed") return value;
  throw new ApiResponseShapeError("DirectorySyncResult.status");
}

export function parseDirectorySyncResult(value: unknown): DirectorySyncResult {
  if (!isRecord(value)) throw new ApiResponseShapeError("DirectorySyncResult");
  return {
    syncId: requireNonEmptyString(value, "syncId"),
    startedAt: requireNonEmptyString(value, "startedAt"),
    completedAt: requireNullableString(value, "completedAt"),
    status: parseDirectorySyncStatus(value.status),
    departmentsAdded: requireNonNegativeInteger(value, "departmentsAdded"),
    departmentsUpdated: requireNonNegativeInteger(value, "departmentsUpdated"),
    employeesAdded: requireNonNegativeInteger(value, "employeesAdded"),
    employeesUpdated: requireNonNegativeInteger(value, "employeesUpdated"),
    employeesOffboarded: requireNonNegativeInteger(value, "employeesOffboarded"),
    conflictsDetected: requireNonNegativeInteger(value, "conflictsDetected"),
  };
}

export function parseProviderDetail(value: unknown): ProviderDetail {
  const summary = parseIdentityProvider(value);
  if (!isRecord(value)) throw new ApiResponseShapeError("ProviderDetail");
  const lastSync = value.lastSyncResult;
  if (lastSync !== null && !isRecord(lastSync)) {
    throw new ApiResponseShapeError("ProviderDetail.lastSyncResult");
  }
  return {
    ...summary,
    appId: requireString(value, "appId"),
    secretConfigured: requireBoolean(value, "secretConfigured"),
    callbackUrl: requireString(value, "callbackUrl"),
    contactScope: requireString(value, "contactScope"),
    lastValidatedAt: requireNullableString(value, "lastValidatedAt"),
    lastSyncAt: requireNullableString(value, "lastSyncAt"),
    lastSyncResult: lastSync === null ? null : parseDirectorySyncResult(lastSync),
  };
}

export function parseDirectorySyncHistory(value: unknown): DirectorySyncHistoryEntry[] {
  if (!Array.isArray(value)) throw new ApiResponseShapeError("DirectorySyncHistory");
  return value.map((item) => {
    if (!isRecord(item)) throw new ApiResponseShapeError("DirectorySyncHistoryEntry");
    const result = parseDirectorySyncResult(item);
    return {
      syncId: result.syncId,
      providerId: requireNonEmptyString(item, "providerId"),
      startedAt: result.startedAt,
      completedAt: result.completedAt,
      status: result.status,
      summary: requireString(item, "summary"),
    };
  });
}

export function parseSyncConflicts(value: unknown): SyncConflict[] {
  if (!Array.isArray(value)) throw new ApiResponseShapeError("SyncConflictList");
  return value.map((item) => {
    if (!isRecord(item)) throw new ApiResponseShapeError("SyncConflict");
    const reason = item.matchReason;
    const status = item.status;
    if (reason !== "email" && reason !== "name" && reason !== "manual") {
      throw new ApiResponseShapeError("SyncConflict.matchReason");
    }
    if (status !== "pending" && status !== "resolved" && status !== "ignored") {
      throw new ApiResponseShapeError("SyncConflict.status");
    }
    return {
      conflictId: requireNonEmptyString(item, "conflictId"),
      providerId: requireNonEmptyString(item, "providerId"),
      externalSubject: requireNonEmptyString(item, "externalSubject"),
      externalName: requireString(item, "externalName"),
      externalEmail: requireString(item, "externalEmail"),
      matchedUserId: requireNullableString(item, "matchedUserId"),
      matchedUserName: requireNullableString(item, "matchedUserName"),
      matchReason: reason,
      status,
      detectedAt: requireNonEmptyString(item, "detectedAt"),
    };
  });
}

export type PublicLoginProvider = {
  providerId: string;
  displayName: string;
  loginEnabled: boolean;
};

export function parsePublicLoginProviders(value: unknown): PublicLoginProvider[] {
  if (!isRecord(value)) throw new ApiResponseShapeError("PublicLoginProviders");
  return requireArray(value, "items").map((item) => {
    if (!isRecord(item)) throw new ApiResponseShapeError("PublicLoginProvider");
    return {
      providerId: requireNonEmptyString(item, "providerId"),
      displayName: requireString(item, "displayName"),
      loginEnabled: requireBoolean(item, "loginEnabled"),
    };
  });
}

// --- Phase 7 policies and audit ---

function parsePolicyStatus(value: unknown): "draft" | "published" {
  if (value !== "draft" && value !== "published") {
    throw new ApiResponseShapeError("Policy.status");
  }
  return value;
}

function parsePolicyEffect(value: unknown): "allow" | "deny" {
  if (value !== "allow" && value !== "deny") {
    throw new ApiResponseShapeError("Policy.effect");
  }
  return value;
}

function parsePolicyClause(value: unknown, principal: true): PolicyPrincipal;
function parsePolicyClause(value: unknown, principal: false): PolicyCondition;
function parsePolicyClause(value: unknown, principal: boolean): PolicyPrincipal | PolicyCondition {
  if (!isRecord(value)) throw new ApiResponseShapeError("PolicyClause");
  const operator = requireNonEmptyString(value, "operator");
  const allowed = principal
    ? ["eq", "neq", "in", "not_in", "contains"]
    : ["eq", "neq", "in", "not_in", "gt", "lt", "contains"];
  if (!allowed.includes(operator)) throw new ApiResponseShapeError("PolicyClause.operator");
  return {
    attribute: requireNonEmptyString(value, "attribute"),
    operator: operator as PolicyCondition["operator"],
    value: requireString(value, "value"),
  } as PolicyCondition;
}

function parsePolicySummary(value: unknown): AuthorizationPolicy {
  if (!isRecord(value)) throw new ApiResponseShapeError("AuthorizationPolicy");
  return {
    policyId: requireNonEmptyString(value, "policyId"),
    name: requireNonEmptyString(value, "name"),
    resource: requireNonEmptyString(value, "resource"),
    version: requirePositiveInteger(value, "version"),
    status: parsePolicyStatus(value.status),
    updatedBy: requireString(value, "updatedBy"),
    updatedAt: requireNonEmptyString(value, "updatedAt"),
  };
}

export function parsePolicies(value: unknown): CursorPage<AuthorizationPolicy> {
  return parseCursorPage(value, "AuthorizationPolicyPage", parsePolicySummary);
}

export function parsePolicyDetail(value: unknown): PolicyDetail {
  if (!isRecord(value)) throw new ApiResponseShapeError("PolicyDetail");
  return {
    ...parsePolicySummary(value),
    description: requireString(value, "description"),
    action: requireNonEmptyString(value, "action"),
    effect: parsePolicyEffect(value.effect),
    principals: requireArray(value, "principals").map((item) => parsePolicyClause(item, true)),
    conditions: requireArray(value, "conditions").map((item) => parsePolicyClause(item, false)),
    versionHistory: requireArray(value, "versionHistory").map((item) => {
      if (!isRecord(item)) throw new ApiResponseShapeError("PolicyVersionSummary");
      return {
        version: requirePositiveInteger(item, "version"),
        status: parsePolicyStatus(item.status),
        updatedBy: requireString(item, "updatedBy"),
        updatedAt: requireNonEmptyString(item, "updatedAt"),
        changeSummary: requireString(item, "changeSummary"),
      };
    }),
  };
}

export function parsePolicyMutation(value: unknown): { policyId?: string; version: number } {
  if (!isRecord(value)) throw new ApiResponseShapeError("PolicyMutation");
  const policyId = optionalString(value, "policyId");
  return { ...(policyId !== undefined && { policyId }), version: requirePositiveInteger(value, "version") };
}

export function parsePolicySimulation(value: unknown): PolicySimulationResult {
  if (!isRecord(value)) throw new ApiResponseShapeError("PolicySimulationResult");
  const decision = value.decision;
  if (decision !== "allow" && decision !== "deny" && decision !== "no_match") {
    throw new ApiResponseShapeError("PolicySimulationResult.decision");
  }
  return {
    decision,
    matchedPolicyId: requireNullableString(value, "matchedPolicyId"),
    matchedPolicyName: requireNullableString(value, "matchedPolicyName"),
    evaluatedAt: requireNonEmptyString(value, "evaluatedAt"),
    reasons: requireStringArray(value, "reasons"),
  };
}

export function parseAuditEvents(value: unknown): CursorPage<AuditEvent> {
  return parseCursorPage(value, "AuditEventPage", parseAuditEvent);
}

export function parseAuditExport(value: unknown): AuditExportResult {
  if (!isRecord(value)) throw new ApiResponseShapeError("AuditExportResult");
  const status = value.status;
  if (status !== "pending" && status !== "processing" && status !== "completed" && status !== "failed") {
    throw new ApiResponseShapeError("AuditExportResult.status");
  }
  return {
    exportId: requireNonEmptyString(value, "exportId"),
    status,
    downloadUrl: requireNullableString(value, "downloadUrl"),
    requestedAt: requireNonEmptyString(value, "requestedAt"),
    completedAt: requireNullableString(value, "completedAt"),
    totalEvents: requireNonNegativeInteger(value, "totalEvents"),
  };
}
