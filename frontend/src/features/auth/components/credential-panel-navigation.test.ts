//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-09-03
// Description: Successful credential-login navigation contract
//

import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

describe("CredentialPanel successful navigation", () => {
  it("replaces the login history entry after password and MFA success", async () => {
    const source = await readFile(
      path.join(process.cwd(), "src/features/auth/components/credential-panel.tsx"),
      "utf8",
    );

    expect(source.match(/router\.replace\(loginDestination\(\)\)/gu)).toHaveLength(2);
    expect(source).not.toContain("router.push(loginDestination())");
  });
});
