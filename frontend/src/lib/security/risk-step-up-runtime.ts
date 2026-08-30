"use client";

import type { StepUpChallenge } from "@/lib/api/api-error";

export type RiskStepUpResolution =
  | { status: "provider_proof"; providerProof: string }
  | { status: "completed" }
  | { status: "reauth_granted"; reauthToken: string };

export type RiskStepUpHandler = (
  challenge: StepUpChallenge,
  signal?: AbortSignal,
) => Promise<RiskStepUpResolution>;

export class RiskStepUpUnavailableError extends Error {
  constructor(message = "当前额外验证服务暂不可用，请稍后再试。") {
    super(message);
    this.name = "RiskStepUpUnavailableError";
  }
}
export class RiskStepUpCancelledError extends Error {
  constructor(message = "额外验证已取消。") {
    super(message);
    this.name = "RiskStepUpCancelledError";
  }
}

let activeHandler: RiskStepUpHandler | undefined;

/**
 * Installs the single application-level step-up UI bridge. The cleanup only
 * removes the handler it installed, so React development remounts cannot
 * accidentally unregister a newer provider.
 */
export function registerRiskStepUpHandler(handler: RiskStepUpHandler): () => void {
  activeHandler = handler;
  return () => {
    if (activeHandler === handler) activeHandler = undefined;
  };
}

export async function requestRiskStepUp(
  challenge: StepUpChallenge,
  signal?: AbortSignal,
): Promise<RiskStepUpResolution> {
  if (signal?.aborted) throw signal.reason;
  if (Date.parse(challenge.expiresAt) <= Date.now()) {
    throw new RiskStepUpUnavailableError("额外验证已过期，请重新提交。")
  }
  if (!activeHandler) throw new RiskStepUpUnavailableError();
  return activeHandler(challenge, signal);
}
