//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the API error helpers
//

import { describe, it, expect } from "vitest";
import { isApiError, getFieldError, type ApiError } from "./api-error";

describe("isApiError", () => {
  it("returns true for a valid ApiError object", () => {
    const error: ApiError = { kind: "validation", message: "Invalid input" };
    expect(isApiError(error)).toBe(true);
  });

  it("returns true for a complete ApiError with all optional fields", () => {
    const error: ApiError = {
      kind: "reauthentication_required",
      message: "Reauthentication required",
      requestId: "req_001",
      fieldErrors: [{ field: "email", message: "邮箱已被占用。" }],
      retryAfter: 30,
      challenge: { methods: ["password", "totp"], requestId: "ch_001" },
    };
    expect(isApiError(error)).toBe(true);
  });

  it("returns false for null", () => {
    expect(isApiError(null)).toBe(false);
  });

  it("returns false for undefined", () => {
    expect(isApiError(undefined)).toBe(false);
  });

  it("returns false for string", () => {
    expect(isApiError("error")).toBe(false);
  });

  it("returns false for object without kind", () => {
    expect(isApiError({ message: "error" })).toBe(false);
  });

  it("returns false for object without message", () => {
    expect(isApiError({ kind: "network" })).toBe(false);
  });

  it("returns false when kind is not a string", () => {
    expect(isApiError({ kind: 123, message: "error" })).toBe(false);
  });

  it("returns false when message is not a string", () => {
    expect(isApiError({ kind: "network", message: null })).toBe(false);
  });

  it("returns false when kind is not a valid ApiErrorKind", () => {
    expect(isApiError({ kind: "whatever", message: "error" })).toBe(false);
  });

  it("returns false when fieldErrors is not an array", () => {
    expect(isApiError({ kind: "validation", message: "error", fieldErrors: "not array" })).toBe(false);
  });

  it("returns false when fieldErrors contains non-object items", () => {
    expect(isApiError({ kind: "validation", message: "error", fieldErrors: ["string"] })).toBe(false);
  });

  it("returns false when fieldErrors has wrong field type", () => {
    expect(
      isApiError({ kind: "validation", message: "error", fieldErrors: [{ field: 123, message: "x" }] }),
    ).toBe(false);
  });

  it("returns false when retryAfter is not a number", () => {
    expect(isApiError({ kind: "rate_limited", message: "error", retryAfter: "30" })).toBe(false);
  });

  it("returns false when challenge has invalid methods", () => {
    expect(
      isApiError({
        kind: "reauthentication_required",
        message: "error",
        challenge: { methods: ["sms"], requestId: "ch_001" },
      }),
    ).toBe(false);
  });

  it("returns false when challenge is missing requestId", () => {
    expect(
      isApiError({
        kind: "reauthentication_required",
        message: "error",
        challenge: { methods: ["password"] },
      }),
    ).toBe(false);
  });

  it("returns true when requestId is a string", () => {
    expect(isApiError({ kind: "not_found", message: "error", requestId: "req_123" })).toBe(true);
  });

  it("returns false when requestId is not a string", () => {
    expect(isApiError({ kind: "not_found", message: "error", requestId: 123 })).toBe(false);
  });
});

describe("getFieldError", () => {
  it("returns the message for a matching field", () => {
    const error: ApiError = {
      kind: "validation",
      message: "Validation failed",
      fieldErrors: [
        { field: "email", message: "邮箱已被占用。" },
        { field: "username", message: "用户名已存在。" },
      ],
    };
    expect(getFieldError(error, "email")).toBe("邮箱已被占用。");
    expect(getFieldError(error, "username")).toBe("用户名已存在。");
  });

  it("returns undefined when field is not in fieldErrors", () => {
    const error: ApiError = {
      kind: "validation",
      message: "Validation failed",
      fieldErrors: [{ field: "email", message: "邮箱已被占用。" }],
    };
    expect(getFieldError(error, "phone")).toBeUndefined();
  });

  it("returns undefined when fieldErrors is absent", () => {
    const error: ApiError = { kind: "server_error", message: "Internal error" };
    expect(getFieldError(error, "email")).toBeUndefined();
  });

  it("returns the first matching field error", () => {
    const error: ApiError = {
      kind: "validation",
      message: "Validation failed",
      fieldErrors: [
        { field: "redirectUri", message: "地址未登记。" },
        { field: "redirectUri", message: "地址格式无效。" },
      ],
    };
    expect(getFieldError(error, "redirectUri")).toBe("地址未登记。");
  });
});
