//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the mock authentication helpers
//

import { describe, it, expect } from "vitest";
import { authenticateMockAccount, MOCK_LOGIN_ACCOUNTS } from "./mock-auth";

describe("authenticateMockAccount", () => {
  it("matches by username", () => {
    const destination = authenticateMockAccount("app.user", "MockUser123!");
    expect(destination).toBe("/account");
  });

  it("matches by email", () => {
    const destination = authenticateMockAccount("app.user@example.com", "MockUser123!");
    expect(destination).toBe("/account");
  });

  it("matches employee admin by username", () => {
    const destination = authenticateMockAccount("zhixing.lin", "MockAdmin123!");
    expect(destination).toBe("/admin");
  });

  it("matches employee admin by email", () => {
    const destination = authenticateMockAccount("zhixing.lin@example.com", "MockAdmin123!");
    expect(destination).toBe("/admin");
  });

  it("is case-insensitive for username", () => {
    const destination = authenticateMockAccount("APP.USER", "MockUser123!");
    expect(destination).toBe("/account");
  });

  it("is case-insensitive for email", () => {
    const destination = authenticateMockAccount("APP.USER@EXAMPLE.COM", "MockUser123!");
    expect(destination).toBe("/account");
  });

  it("trims whitespace in identifier", () => {
    const destination = authenticateMockAccount("  app.user  ", "MockUser123!");
    expect(destination).toBe("/account");
  });

  it("returns undefined for wrong password", () => {
    const destination = authenticateMockAccount("app.user", "wrong-password");
    expect(destination).toBeUndefined();
  });

  it("returns undefined for unknown username", () => {
    const destination = authenticateMockAccount("nobody", "MockUser123!");
    expect(destination).toBeUndefined();
  });

  it("returns undefined for empty identifier", () => {
    const destination = authenticateMockAccount("", "MockUser123!");
    expect(destination).toBeUndefined();
  });

  it("does not match external user with admin password", () => {
    const destination = authenticateMockAccount("app.user", "MockAdmin123!");
    expect(destination).toBeUndefined();
  });

  it("demo credentials are non-secret public values", () => {
    expect(MOCK_LOGIN_ACCOUNTS.externalUser.password).toBe("MockUser123!");
    expect(MOCK_LOGIN_ACCOUNTS.employeeAdmin.password).toBe("MockAdmin123!");
  });
});
