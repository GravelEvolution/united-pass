//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-14
// Description: Administration-console permission gate regression tests
//

import { describe, expect, it } from "vitest";
import {
  canAccessAdminConsole,
  FULL_PERMISSIONS,
  isPermissionCapabilities,
  NO_PERMISSIONS,
} from "@/types/permissions";

describe("canAccessAdminConsole", () => {
  it("denies an authenticated external user without management capabilities", () => {
    expect(canAccessAdminConsole(NO_PERMISSIONS)).toBe(false);
  });

  it("allows a caller with at least one management capability", () => {
    expect(
      canAccessAdminConsole({
        ...NO_PERMISSIONS,
        auditRead: true,
      }),
    ).toBe(true);
  });

  it("allows the full-permission development administrator", () => {
    expect(canAccessAdminConsole(FULL_PERMISSIONS)).toBe(true);
  });

  it("rejects malformed permission responses before they control routing", () => {
    expect(isPermissionCapabilities(NO_PERMISSIONS)).toBe(true);
    expect(isPermissionCapabilities({ ...NO_PERMISSIONS, userRead: "yes" })).toBe(false);
    expect(isPermissionCapabilities({ userRead: true })).toBe(false);
  });
});
