import { describe, expect, it } from "vitest";
import { usernameHtmlPattern } from "./registration-username-pattern";

describe("usernameHtmlPattern", () => {
  it("compiles under the HTML pattern v flag", () => {
    expect(() => new RegExp(usernameHtmlPattern, "v")).not.toThrow();
  });

  it("matches the account-name rule used by the API", () => {
    const full = new RegExp(`^(?:${usernameHtmlPattern})$`, "v");
    const accepted = ["abc", "user01", "a_b.c", "user-01", "02zb7w-07pv74"];
    const rejected = ["ab", "-abc", "_abc", "a b", "ab#c"];

    for (const value of accepted) expect(full.test(value)).toBe(true);
    for (const value of rejected) expect(full.test(value)).toBe(false);
  });
});
