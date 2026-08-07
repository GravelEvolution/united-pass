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
} from "./response-validators";

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
