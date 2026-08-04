import { describe, it, expect } from "vitest";
import { isApiError, getFieldError, type ApiError } from "./api-error";

describe("isApiError", () => {
  it("returns true for a valid ApiError object", () => {
    const error: ApiError = { kind: "validation", message: "Invalid input" };
    expect(isApiError(error)).toBe(true);
  });

  it("returns false for null", () => {
    expect(isApiError(null)).toBe(false);
  });

  it("returns false for string", () => {
    expect(isApiError("error")).toBe(false);
  });

  it("returns false for object without kind", () => {
    expect(isApiError({ message: "error" })).toBe(false);
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
