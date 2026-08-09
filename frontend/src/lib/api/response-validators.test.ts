//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: Unit tests for the HTTP response body validators
//

import { describe, it, expect } from "vitest";
import {
  ApiResponseShapeError,
  parseAuthorizedApplications,
  parseConsentResolution,
  parseCurrentUser,
  parseDecisionResponse,
  parseMfaRequiredResponse,
  parsePasskeyEnrollment,
  parsePasskeyEnrollmentConfirmation,
  parseReauthenticationOutcome,
  parseRevokedSessionCount,
  parseSecuritySummary,
  parseTotpEnrollment,
  parseTotpEnrollmentConfirmation,
  parseUserSessions,
} from "./response-validators";

describe("P4.7 account security validators", () => {
  const session = {
    sessionId: "session-1",
    deviceName: "",
    clientName: "Chrome",
    approximateLocation: null,
    ipAddressMasked: "127.0.0.*",
    lastActiveAt: "2026-08-09T10:00:00Z",
    createdAt: "2026-08-09T09:00:00Z",
    authenticationMethods: ["password", "totp"],
    isCurrent: true,
  };

  it("parses the complete nullable session wire shape", () => {
    expect(parseUserSessions([session])).toEqual([session]);
  });

  it("rejects malformed session fields", () => {
    expect(() => parseUserSessions({ sessions: [] })).toThrow(ApiResponseShapeError);
    expect(() => parseUserSessions([{ ...session, approximateLocation: 1 }])).toThrow(ApiResponseShapeError);
    expect(() => parseUserSessions([{ ...session, authenticationMethods: "password" }])).toThrow(ApiResponseShapeError);
    expect(() => parseUserSessions([{ ...session, createdAt: null }])).toThrow(ApiResponseShapeError);
  });

  it("parses TOTP enrollment only with non-empty secret material and otpauth scheme", () => {
    expect(parseTotpEnrollment({
      enrollmentToken: "enrollment",
      secret: "SECRET",
      otpauthUri: "otpauth://totp/United?secret=SECRET",
    })).toEqual({
      enrollmentToken: "enrollment",
      secret: "SECRET",
      otpauthUri: "otpauth://totp/United?secret=SECRET",
    });
    expect(() => parseTotpEnrollment({
      enrollmentToken: "enrollment",
      secret: "SECRET",
      otpauthUri: "https://example.com/secret",
    })).toThrow(ApiResponseShapeError);
  });

  it("validates TOTP confirmation and non-negative integer revoke counts", () => {
    expect(parseTotpEnrollmentConfirmation({ status: "confirmed" })).toBeUndefined();
    expect(() => parseTotpEnrollmentConfirmation({ status: "pending" })).toThrow(ApiResponseShapeError);
    expect(parseRevokedSessionCount({ revoked: 2 })).toEqual({ revoked: 2 });
    expect(() => parseRevokedSessionCount({ revoked: -1 })).toThrow(ApiResponseShapeError);
    expect(() => parseRevokedSessionCount({ revoked: 1.5 })).toThrow(ApiResponseShapeError);
  });
});

describe("parseConsentResolution", () => {
  it("parses the valid member with the full request", () => {
    const resolution = parseConsentResolution({
      status: "valid",
      request: {
        requestId: "req_01",
        applicationName: "United Workspace",
        applicationDescription: "协作平台",
        applicationOwner: "United",
        redirectHost: "workspace.united.example",
        scopes: [{ scope: "openid", label: "身份", description: "读取基本身份" }],
      },
    });

    expect(resolution).toEqual({
      status: "valid",
      request: {
        requestId: "req_01",
        applicationName: "United Workspace",
        applicationDescription: "协作平台",
        applicationOwner: "United",
        redirectHost: "workspace.united.example",
        scopes: [{ scope: "openid", label: "身份", description: "读取基本身份" }],
      },
    });
  });

  it("parses expired, client_not_found, unauthenticated, redirect_mismatch, scope_not_allowed and already_authorized", () => {
    expect(
      parseConsentResolution({ status: "expired", requestId: "req_01", expiredAt: "2026-08-07T00:00:00Z" }),
    ).toEqual({ status: "expired", requestId: "req_01", expiredAt: "2026-08-07T00:00:00Z" });

    expect(parseConsentResolution({ status: "client_not_found", requestId: "req_02" })).toEqual({
      status: "client_not_found",
      requestId: "req_02",
    });

    expect(parseConsentResolution({ status: "unauthenticated", requestId: "req_03" })).toEqual({
      status: "unauthenticated",
      requestId: "req_03",
    });

    expect(
      parseConsentResolution({
        status: "redirect_mismatch",
        requestId: "req_04",
        attemptedRedirect: "evil.example",
      }),
    ).toEqual({ status: "redirect_mismatch", requestId: "req_04", attemptedRedirect: "evil.example" });

    expect(
      parseConsentResolution({
        status: "scope_not_allowed",
        requestId: "req_05",
        disallowedScopes: ["admin:read"],
      }),
    ).toEqual({ status: "scope_not_allowed", requestId: "req_05", disallowedScopes: ["admin:read"] });

    expect(
      parseConsentResolution({
        status: "already_authorized",
        requestId: "req_06",
        applicationName: "United Workspace",
        redirectHost: "workspace.united.example",
      }),
    ).toEqual({
      status: "already_authorized",
      requestId: "req_06",
      applicationName: "United Workspace",
      redirectHost: "workspace.united.example",
    });
  });

  it("rejects statuses outside the frozen union", () => {
    expect(() => parseConsentResolution({ status: "approved", requestId: "req_01" })).toThrow(
      ApiResponseShapeError,
    );
  });

  it("rejects members with missing or wrongly typed fields", () => {
    expect(() => parseConsentResolution({ status: "expired", requestId: 123 })).toThrow(
      ApiResponseShapeError,
    );
    expect(() =>
      parseConsentResolution({
        status: "scope_not_allowed",
        requestId: "req_05",
        disallowedScopes: "admin:read",
      }),
    ).toThrow(ApiResponseShapeError);
    expect(() => parseConsentResolution({ status: "valid" })).toThrow(ApiResponseShapeError);
    expect(() =>
      parseConsentResolution({
        status: "valid",
        request: { requestId: "req_01", applicationName: "App" },
      }),
    ).toThrow(ApiResponseShapeError);
  });

  it("rejects non-object bodies", () => {
    expect(() => parseConsentResolution(null)).toThrow(ApiResponseShapeError);
    expect(() => parseConsentResolution("valid")).toThrow(ApiResponseShapeError);
    expect(() => parseConsentResolution([])).toThrow(ApiResponseShapeError);
  });
});

describe("parseDecisionResponse", () => {
  it("returns the validated redirect URL", () => {
    expect(parseDecisionResponse({ redirectUrl: "https://client.example/cb?code=x" })).toEqual({
      redirectUrl: "https://client.example/cb?code=x",
    });
  });

  it("rejects a missing or empty redirectUrl", () => {
    expect(() => parseDecisionResponse({})).toThrow(ApiResponseShapeError);
    expect(() => parseDecisionResponse({ redirectUrl: "" })).toThrow(ApiResponseShapeError);
    expect(() => parseDecisionResponse(null)).toThrow(ApiResponseShapeError);
  });
});

describe("parseAuthorizedApplications", () => {
  const row = {
    grantId: "grant_001",
    applicationId: "app_001",
    applicationName: "United Workspace",
    applicationOwner: "United",
    clientType: "confidential",
    grantedAt: "2026-08-01T00:00:00Z",
    lastUsedAt: null,
    scopes: ["openid", "profile"],
    hasOfflineAccess: false,
    status: "active",
  };

  it("parses a well-formed row with null lastUsedAt", () => {
    expect(parseAuthorizedApplications([row])).toEqual([row]);
  });

  it("rejects non-array bodies and malformed rows", () => {
    expect(() => parseAuthorizedApplications({ rows: [] })).toThrow(ApiResponseShapeError);
    expect(() => parseAuthorizedApplications([{ ...row, clientType: "native" }])).toThrow(
      ApiResponseShapeError,
    );
    expect(() => parseAuthorizedApplications([{ ...row, status: "disabled" }])).toThrow(
      ApiResponseShapeError,
    );
    expect(() => parseAuthorizedApplications([{ ...row, lastUsedAt: 123 }])).toThrow(
      ApiResponseShapeError,
    );
    expect(() => parseAuthorizedApplications([{ ...row, scopes: "openid" }])).toThrow(
      ApiResponseShapeError,
    );
  });
});

describe("parseCurrentUser", () => {
  it("parses a minimal consumer user", () => {
    expect(
      parseCurrentUser({
        userId: "usr_01",
        displayName: "林知行",
        nickname: null,
        avatarUrl: null,
        email: "zhixing.lin@example.com",
        phoneMasked: "+86 138****0000",
        personas: ["consumer"],
        employeeProfile: null,
      }),
    ).toEqual({
      userId: "usr_01",
      displayName: "林知行",
      email: "zhixing.lin@example.com",
      phoneMasked: "+86 138****0000",
      personas: ["consumer"],
    });
  });

  it("parses an employee user with optional fields", () => {
    expect(
      parseCurrentUser({
        userId: "usr_02",
        displayName: "周予安",
        nickname: "予安",
        avatarUrl: "/media/avatar.png",
        email: "yuan.zhou@example.com",
        phoneMasked: "+86 139****0000",
        personas: ["consumer", "employee"],
        employeeProfile: { employeeId: "emp_01", departmentName: "平台组", title: "工程师" },
      }),
    ).toEqual({
      userId: "usr_02",
      displayName: "周予安",
      nickname: "予安",
      avatarUrl: "/media/avatar.png",
      email: "yuan.zhou@example.com",
      phoneMasked: "+86 139****0000",
      personas: ["consumer", "employee"],
      employeeProfile: { employeeId: "emp_01", departmentName: "平台组", title: "工程师" },
    });
  });

  it("rejects unknown personas and malformed profiles", () => {
    expect(() =>
      parseCurrentUser({
        userId: "usr_03",
        displayName: "X",
        email: "x@example.com",
        phoneMasked: "",
        personas: ["admin"],
      }),
    ).toThrow(ApiResponseShapeError);
    expect(() =>
      parseCurrentUser({
        userId: "usr_04",
        displayName: "X",
        email: "x@example.com",
        phoneMasked: "",
        personas: [],
        employeeProfile: { employeeId: "emp_01" },
      }),
    ).toThrow(ApiResponseShapeError);
    expect(() => parseCurrentUser({ displayName: "X" })).toThrow(ApiResponseShapeError);
  });
});

describe("parseMfaRequiredResponse", () => {
  it("narrows the 202 login body onto the frozen challenge shape", () => {
    expect(
      parseMfaRequiredResponse({
        status: "mfa_required",
        mfaToken: "opaque-token",
        availableMethods: ["totp", "recovery_code"],
        expiresAt: "2026-08-07T12:05:30Z",
      }),
    ).toEqual({ mfaToken: "opaque-token", availableMethods: ["totp", "recovery_code"] });
  });

  it("rejects unknown verification methods", () => {
    expect(() =>
      parseMfaRequiredResponse({
        status: "mfa_required",
        mfaToken: "t",
        availableMethods: ["sms"],
      }),
    ).toThrow(ApiResponseShapeError);
  });

  it("rejects wrong status, missing token and empty method lists", () => {
    expect(() =>
      parseMfaRequiredResponse({ status: "ok", mfaToken: "t", availableMethods: ["totp"] }),
    ).toThrow(ApiResponseShapeError);
    expect(() =>
      parseMfaRequiredResponse({ status: "mfa_required", availableMethods: ["totp"] }),
    ).toThrow(ApiResponseShapeError);
    expect(() =>
      parseMfaRequiredResponse({ status: "mfa_required", mfaToken: "t", availableMethods: [] }),
    ).toThrow(ApiResponseShapeError);
    expect(() => parseMfaRequiredResponse(null)).toThrow(ApiResponseShapeError);
  });
});

describe("P4.5 account security validators", () => {
  const summary = {
    password: { set: true },
    totp: { enabled: false },
    passkeys: [
      { passkeyId: "pk-active", createdAt: null, state: "active" },
      { passkeyId: "pk-pending", createdAt: "2026-08-09T10:00:00Z", state: "pending" },
    ],
    recoveryCodes: { available: false, deferredReason: "provider_unsupported" },
  };

  it("preserves multiple passkeys, pending state and nullable creation time", () => {
    expect(parseSecuritySummary(summary)).toEqual(summary);
  });

  it("fails closed on unknown passkey state or real recovery-code availability", () => {
    expect(() => parseSecuritySummary({ ...summary, passkeys: [{ ...summary.passkeys[0], state: "ready" }] })).toThrow(
      ApiResponseShapeError,
    );
    expect(() => parseSecuritySummary({
      ...summary,
      recoveryCodes: { available: true, deferredReason: "provider_unsupported" },
    })).toThrow(ApiResponseShapeError);
  });

  it("narrows granted and MFA-required reauthentication outcomes", () => {
    expect(parseReauthenticationOutcome({
      status: "granted",
      reauthToken: "grant",
      expiresAt: "2026-08-09T10:00:00Z",
    })).toEqual({ status: "granted", reauthToken: "grant", expiresAt: "2026-08-09T10:00:00Z" });

    expect(parseReauthenticationOutcome({
      status: "mfa_required",
      reauthToken: "challenge",
      availableMethods: ["totp", "passkey"],
      passkeyRequestOptions: { challenge: "Y2hhbGxlbmdl" },
      expiresAt: "2026-08-09T10:00:00Z",
    })).toEqual({
      status: "mfa_required",
      reauthToken: "challenge",
      availableMethods: ["totp", "passkey"],
      passkeyRequestOptions: { challenge: "Y2hhbGxlbmdl" },
      expiresAt: "2026-08-09T10:00:00Z",
    });
  });

  it("rejects unknown MFA methods and passkey challenges without request options", () => {
    expect(() => parseReauthenticationOutcome({
      status: "mfa_required",
      reauthToken: "challenge",
      availableMethods: ["sms"],
      expiresAt: "x",
    })).toThrow(ApiResponseShapeError);
    expect(() => parseReauthenticationOutcome({
      status: "mfa_required",
      reauthToken: "challenge",
      availableMethods: ["passkey"],
      expiresAt: "x",
    })).toThrow(ApiResponseShapeError);
  });

  it("keeps the enrollment capability available while narrowing options", () => {
    expect(parsePasskeyEnrollment({
      enrollmentToken: "enrollment",
      passkeyId: "pk-new",
      publicKeyCredentialCreationOptions: { challenge: "Y2hhbGxlbmdl" },
    })).toEqual({
      enrollmentToken: "enrollment",
      passkeyId: "pk-new",
      publicKeyCredentialCreationOptions: { challenge: "Y2hhbGxlbmdl" },
    });
    expect(() => parsePasskeyEnrollment({
      enrollmentToken: "enrollment",
      passkeyId: "pk-new",
      publicKeyCredentialCreationOptions: "escaped-json",
    })).toThrow(ApiResponseShapeError);
  });

  it("rejects a confirmation whose provider passkey ID changed", () => {
    expect(parsePasskeyEnrollmentConfirmation(
      { status: "confirmed", passkeyId: "pk-new" },
      "pk-new",
    )).toEqual({ status: "confirmed", passkeyId: "pk-new" });
    expect(() => parsePasskeyEnrollmentConfirmation(
      { status: "confirmed", passkeyId: "pk-other" },
      "pk-new",
    )).toThrow(ApiResponseShapeError);
  });
});
