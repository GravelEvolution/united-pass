import { describe, expect, it } from "vitest";
import { hasLeadingZeroBits, solveAutomationCost } from "./automation-cost";

describe("automation cost", () => {
  it("counts leading bits rather than only whole zero bytes", () => {
    expect(hasLeadingZeroBits(new Uint8Array([0x00, 0x0f]), 12)).toBe(true);
    expect(hasLeadingZeroBits(new Uint8Array([0x00, 0x1f]), 12)).toBe(false);
    expect(hasLeadingZeroBits(new Uint8Array([0x7f]), 1)).toBe(true);
    expect(hasLeadingZeroBits(new Uint8Array([0x80]), 1)).toBe(false);
  });

  it("finds a nonce whose SHA-256 digest satisfies the challenge", async () => {
    const challengeToken = "unit-test-challenge";
    const nonce = await solveAutomationCost(challengeToken, 8);
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`${challengeToken}:${nonce}`),
    );
    expect(hasLeadingZeroBits(new Uint8Array(digest), 8)).toBe(true);
  });

  it("rejects an invalid work factor before doing work", async () => {
    await expect(solveAutomationCost("challenge", 31)).rejects.toThrow("difficulty");
  });
});
