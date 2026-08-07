//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-07
// Description: One-shot consent completion flights and failure classification
//

import { isApiError } from "@/lib/api/api-error";

export type ConsentDecisionOutcome = { redirectUrl: string };

// Outcome of a failed one-shot completion. The backend's global single-winner
// completion makes same-request retries unsafe: after any ambiguous failure
// the browser cannot prove the decision was not applied.
export type CompletionFailure =
  | { outcome: "relogin" }
  | { outcome: "terminal"; message: string };

export function classifyCompletionFailure(error: unknown): CompletionFailure {
  // 401 (session credential required) is the only recoverable failure: the
  // session gate rejects before any decision is applied, so logging in and
  // continuing with the same opaque request ID is safe.
  if (isApiError(error) && error.kind === "unauthorized") {
    return { outcome: "relogin" };
  }
  // 409/410 and ambiguous network/provider errors terminate the transaction;
  // the user must restart authorization from the client application.
  return {
    outcome: "terminal",
    message: "此授权请求无法继续，请从发起授权的应用重新开始。",
  };
}

// Single-flight store for the silent already-authorized completion. The
// module-level map survives React StrictMode's unmount/remount: the second
// effect run attaches to the same in-flight Promise instead of issuing a
// second POST that would collide with the backend's single-winner completion.
//
// Retention policy:
// - resolved flights stay forever: a completed transaction must never be
//   re-POSTed within the session.
// - terminal rejections stay forever: the browser cannot prove the decision
//   was not applied, so remounts must not retry the same request.
// - relogin rejections are evicted by the caller: the session gate rejected
//   before applying anything, so after the user logs in and the page
//   remounts, a fresh single-flight POST may proceed.
//
// Capacity (P3.8 review): the map is deliberately unbounded. Keys are only
// the request IDs this tab actually visited /authorize with — a handful in
// practice — and each entry is a single settled Promise. Any LRU/TTL
// eviction would risk breaking the one-shot retention above (an evicted
// terminal flight would re-POST on remount), so a negligible memory cost
// buys the safe semantics; do not add cleanup without re-proving retention.
const completionFlights = new Map<string, Promise<ConsentDecisionOutcome>>();

export function acquireCompletionFlight(
  requestId: string,
  decide: (requestId: string) => Promise<ConsentDecisionOutcome>,
): Promise<ConsentDecisionOutcome> {
  let flight = completionFlights.get(requestId);
  if (!flight) {
    flight = decide(requestId);
    completionFlights.set(requestId, flight);
  }
  return flight;
}

export function evictCompletionFlight(requestId: string): void {
  completionFlights.delete(requestId);
}
