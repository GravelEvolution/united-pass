"use client";

export type InteractiveCaptchaInput = {
  provider?: string;
  providerPayload?: Readonly<Record<string, unknown>>;
  container: HTMLElement;
  signal: AbortSignal;
};

export type InteractiveCaptchaAdapter = {
  /** Stable local adapter identifier; provider choice remains server-owned. */
  id: string;
  /** Resolves only with the provider's server-verifiable proof. */
  execute(input: InteractiveCaptchaInput): Promise<string>;
};

let activeAdapter: InteractiveCaptchaAdapter | undefined;

/**
 * Provider SDK integration lives behind this seam. Registering an adapter is
 * not itself proof; only its result is sent to the backend verifier.
 */
export function registerInteractiveCaptchaAdapter(
  adapter: InteractiveCaptchaAdapter,
): () => void {
  activeAdapter = adapter;
  return () => {
    if (activeAdapter === adapter) activeAdapter = undefined;
  };
}

export function getInteractiveCaptchaAdapter(): InteractiveCaptchaAdapter | undefined {
  return activeAdapter;
}
