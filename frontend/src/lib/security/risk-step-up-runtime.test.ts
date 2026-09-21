import { afterEach, describe, expect, it } from "vitest";
import type { InteractiveCaptchaStepUp } from "@/lib/api/api-error";
import {
  registerRiskStepUpHandler,
  requestRiskStepUp,
  RiskStepUpUnavailableError,
} from "./risk-step-up-runtime";

const futureChallenge: InteractiveCaptchaStepUp = {
  challengeToken: "opaque",
  level: "high",
  method: "interactive_captcha",
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
  providerReady: true,
  provider: "google_recaptcha",
  providerPayload: {
    siteKey: "public-site-key",
    action: "united_pass_login_A1-b2",
  },
  completionPath: "/api/v1/auth/step-up",
};

let cleanup: (() => void) | undefined;

afterEach(() => {
  cleanup?.();
  cleanup = undefined;
});

describe("risk step-up runtime", () => {
  it("forwards an interactive challenge to the installed UI bridge", async () => {
    cleanup = registerRiskStepUpHandler(async (challenge) => ({
      status: "provider_proof",
      providerProof: `proof-for-${challenge.challengeToken}`,
    }));

    await expect(requestRiskStepUp(futureChallenge)).resolves.toEqual({
      status: "provider_proof",
      providerProof: "proof-for-opaque",
    });
  });

  it("fails closed when no UI bridge is mounted", async () => {
    await expect(requestRiskStepUp(futureChallenge)).rejects.toBeInstanceOf(
      RiskStepUpUnavailableError,
    );
  });

  it("does not display an already expired challenge", async () => {
    cleanup = registerRiskStepUpHandler(async () => ({ status: "completed" }));
    await expect(requestRiskStepUp({
      ...futureChallenge,
      expiresAt: new Date(Date.now() - 1_000).toISOString(),
    })).rejects.toThrow("已过期");
  });
});
