//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Contact verification-code input contract tests
//

import { describe, expect, it } from "vitest";
import {
  getContactVerificationCodeError,
  normalizeContactVerificationCode,
} from "./contact-verification-code";

describe("email contact verification code", () => {
  it("accepts the provider's six-character uppercase alphanumeric code", () => {
    expect(normalizeContactVerificationCode("email", "A1-B2 C3")).toBe("A1B2C3");
    expect(getContactVerificationCodeError("email", "A1B2C3")).toBeUndefined();
  });

  it("preserves case so a case-sensitive provider proof is never rewritten", () => {
    expect(normalizeContactVerificationCode("email", "a1B2c3")).toBe("a1B2c3");
    expect(getContactVerificationCodeError("email", "a1B2c3")).toContain("原有大小写");
  });

  it("rejects incomplete codes", () => {
    expect(getContactVerificationCodeError("email", "A1B2C")).toContain("6 位");
  });
});

describe("phone contact verification code", () => {
  it("keeps the existing six-digit SMS contract", () => {
    expect(normalizeContactVerificationCode("phone", "12a 34-56")).toBe("123456");
    expect(getContactVerificationCodeError("phone", "123456")).toBeUndefined();
  });
});
