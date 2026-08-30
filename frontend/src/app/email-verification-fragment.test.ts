import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("email verification secret transport", () => {
  it("reads the code from the fragment and erases it before the API call", () => {
    const source = readFileSync(resolve(
      process.cwd(),
      "src/features/auth/components/verify-email-panel.tsx",
    ), "utf8");
    const fragmentRead = source.indexOf("window.location.hash");
    const historyErase = source.indexOf("window.history.replaceState");
    const apiCall = source.indexOf("verifyRegistrationEmail({ userId, code, requestId })");

    expect(fragmentRead).toBeGreaterThan(-1);
    expect(historyErase).toBeGreaterThan(fragmentRead);
    expect(apiCall).toBeGreaterThan(historyErase);
    expect(source).not.toContain("searchParams.get(\"code\")");
  });
});
