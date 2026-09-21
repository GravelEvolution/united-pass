import { describe, expect, it } from "vitest";
import {
  refreshLoginChallengeIfRequired,
  shouldRefreshLoginChallenge,
} from "./login-challenge-refresh";

describe("shouldRefreshLoginChallenge", () => {
  it("refreshes after a consumed login step-up", () => {
    expect(shouldRefreshLoginChallenge({
      kind: "unauthorized",
      message: "密码错误",
      requiresChallengeRefresh: true,
    })).toBe(true);
  });

  it("does not refresh for an ordinary credential failure", () => {
    expect(shouldRefreshLoginChallenge({
      kind: "unauthorized",
      message: "密码错误",
    })).toBe(false);
  });

  it("keeps login recovery as a full-page reload", () => {
    let reloads = 0;
    const handled = refreshLoginChallengeIfRequired({
      kind: "unauthorized",
      message: "密码错误",
      requiresChallengeRefresh: true,
    }, () => { reloads += 1; });
    expect(handled).toBe(true);
    expect(reloads).toBe(1);
  });
});
