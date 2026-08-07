//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the contact validation
//

import { describe, it, expect } from "vitest";
import { validateContactValue } from "./contact-validation";

describe("validateContactValue (email)", () => {
  it("rejects empty email", () => {
    expect(validateContactValue("email", "")).toBe("请输入新邮箱地址。");
  });

  it("rejects email without @", () => {
    expect(validateContactValue("email", "userexample.com")).toBeDefined();
  });

  it("rejects email without local part", () => {
    expect(validateContactValue("email", "@example.com")).toBeDefined();
  });

  it("rejects email without domain", () => {
    expect(validateContactValue("email", "user@")).toBeDefined();
  });

  it("rejects email without TLD", () => {
    expect(validateContactValue("email", "user@example")).toBeDefined();
  });

  it("accepts valid email", () => {
    expect(validateContactValue("email", "user@example.com")).toBeUndefined();
  });

  it("accepts email with subdomain", () => {
    expect(validateContactValue("email", "user@mail.example.com")).toBeUndefined();
  });

  it("rejects email with spaces", () => {
    expect(validateContactValue("email", "user @example.com")).toBeDefined();
  });
});

describe("validateContactValue (phone)", () => {
  it("rejects empty phone", () => {
    expect(validateContactValue("phone", "")).toBe("请输入新手机号码。");
  });

  it("rejects phone without country code", () => {
    expect(validateContactValue("phone", "13800138000")).toBeDefined();
  });

  it("rejects phone with invalid country code", () => {
    expect(validateContactValue("phone", "+013800138000")).toBeDefined();
  });

  it("accepts valid Chinese phone", () => {
    expect(validateContactValue("phone", "+8613800138000")).toBeUndefined();
  });

  it("accepts valid US phone", () => {
    expect(validateContactValue("phone", "+12125550100")).toBeUndefined();
  });

  it("rejects phone that is too short", () => {
    expect(validateContactValue("phone", "+1234")).toBeDefined();
  });

  it("rejects phone with spaces", () => {
    expect(validateContactValue("phone", "+86 138 0013 8000")).toBeDefined();
  });
});
