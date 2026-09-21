import { describe, expect, it } from "vitest";
import {
  refreshRegistrationIntentIfRequired,
  shouldRefreshRegistrationIntent,
} from "./registration-challenge-refresh";

const interactiveStepUp = {
  challengeToken: "registration-captcha",
  level: "high",
  method: "interactive_captcha",
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  providerReady: true,
  provider: "moonstone_image_digits",
  providerPayload: {
    imageDataUrl: "data:image/png;base64,iVBORw0KGgo=",
    digits: 5,
  },
  completionPath: "/api/v1/auth/step-up",
} as const;

describe("registration challenge recovery", () => {
  it("refreshes the form intent after a failed or consumed proof", () => {
    expect(shouldRefreshRegistrationIntent({
      kind: "unauthorized",
      code: "step_up_invalid",
      message: "验证码错误。",
      requiresChallengeRefresh: true,
    })).toBe(true);
  });

  it("refreshes the form intent when the interactive prompt is cancelled", () => {
    expect(shouldRefreshRegistrationIntent({
      kind: "forbidden",
      code: "step_up_required",
      message: "验证已取消。",
      stepUp: interactiveStepUp,
    })).toBe(true);
  });

  it("keeps the current intent for unrelated validation and rate errors", () => {
    expect(shouldRefreshRegistrationIntent({
      kind: "validation",
      code: "registration.form_invalid",
      message: "表单无效。",
    })).toBe(false);
    expect(shouldRefreshRegistrationIntent({
      kind: "rate_limited",
      code: "rate_limited",
      message: "请求过于频繁。",
    })).toBe(false);
  });

  it("discards a wrong-answer intent, prepares one replacement, and waits for the next manual submit", async () => {
    const fields = {
      username: "moonstone-user",
      displayName: "MoonStone",
      email: "person@example.com",
      password: "preserved-password",
    };
    const snapshot = { ...fields };
    let formIntentToken = "intent-before-wrong-answer";
    const submittedTokens: string[] = [];
    let prepareCalls = 0;
    let discardCalls = 0;

    const submit = async () => {
      submittedTokens.push(formIntentToken);
      if (submittedTokens.length === 1) {
        throw {
          kind: "unauthorized",
          message: "验证码错误。",
          requiresChallengeRefresh: true,
        };
      }
      return "new-challenge-reached";
    };

    try {
      await submit();
    } catch (error) {
      const recovery = await refreshRegistrationIntentIfRequired(
        error,
        () => {
          discardCalls += 1;
          formIntentToken = "";
        },
        async () => {
          prepareCalls += 1;
          formIntentToken = "intent-after-wrong-answer";
          return true;
        },
      );
      expect(recovery).toEqual({ handled: true, ready: true });
    }

    expect(discardCalls).toBe(1);
    expect(prepareCalls).toBe(1);
    expect(submittedTokens).toEqual(["intent-before-wrong-answer"]);
    expect(fields).toEqual(snapshot);
    await expect(submit()).resolves.toBe("new-challenge-reached");
    expect(submittedTokens).toEqual([
      "intent-before-wrong-answer",
      "intent-after-wrong-answer",
    ]);
  });

  it("discards a cancelled interactive intent and prepares exactly one replacement", async () => {
    let discardCalls = 0;
    let prepareCalls = 0;
    const result = await refreshRegistrationIntentIfRequired(
      {
        kind: "forbidden",
        code: "step_up_required",
        message: "验证已取消。",
        stepUp: interactiveStepUp,
      },
      () => { discardCalls += 1; },
      async () => {
        prepareCalls += 1;
        return true;
      },
    );
    expect(result).toEqual({ handled: true, ready: true });
    expect(discardCalls).toBe(1);
    expect(prepareCalls).toBe(1);
  });
});
