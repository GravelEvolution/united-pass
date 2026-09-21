const QR_CHALLENGE_ID_PATTERN = /^[A-Za-z0-9_-]{20,255}$/u;
const MAX_CHALLENGE_TTL_SECONDS = 600;
const DEFAULT_INTERVAL_MS = 1_500;
const DEFAULT_MAX_INTERVAL_MS = 12_000;
const DEFAULT_MAX_TRANSIENT_FAILURES = 6;
const DEFAULT_JITTER_RATIO = 0.2;

export type QRLoginChallenge = Readonly<{
  challengeId: string;
  expiresInSeconds: number;
}>;

export type QRLoginConsumeResult = Readonly<
  | { status: "pending" }
  | { status: "authenticated"; csrfToken: string }
>;

type TimerHandle = ReturnType<typeof setTimeout>;

type QRLoginPollerOptions = Readonly<{
  challenge: QRLoginChallenge;
  consume: (signal: AbortSignal) => Promise<unknown>;
  onRemainingSeconds: (seconds: number) => void;
  onAuthenticated: () => void;
  onExpired: () => void;
  onError: (reason: unknown) => void;
  onRetry?: (reason: unknown, delayMs: number, consecutiveFailures: number) => void;
  isRetryableError?: (reason: unknown) => boolean;
  intervalMs?: number;
  maxIntervalMs?: number;
  maxTransientFailures?: number;
  jitterRatio?: number;
  random?: () => number;
  now?: () => number;
  schedule?: (callback: () => void, delayMs: number) => TimerHandle;
  clearScheduled?: (handle: TimerHandle) => void;
}>;

function strictRecord(value: unknown, allowedKeys: ReadonlySet<string>, contract: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${contract} must be an object`);
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !allowedKeys.has(key))) {
    throw new TypeError(`${contract} contains an unknown field`);
  }
  return record;
}

export function parseQRLoginChallenge(value: unknown): QRLoginChallenge {
  const challenge = strictRecord(value, new Set(["challengeId", "expiresInSeconds"]), "QR login challenge");
  if (
    typeof challenge.challengeId !== "string"
    || !QR_CHALLENGE_ID_PATTERN.test(challenge.challengeId)
    || !Number.isInteger(challenge.expiresInSeconds)
    || Number(challenge.expiresInSeconds) < 1
    || Number(challenge.expiresInSeconds) > MAX_CHALLENGE_TTL_SECONDS
  ) {
    throw new TypeError("QR login challenge has an invalid shape");
  }
  return { challengeId: challenge.challengeId, expiresInSeconds: Number(challenge.expiresInSeconds) };
}

export function parseQRLoginConsumeResult(value: unknown): QRLoginConsumeResult {
  const envelope = strictRecord(value, new Set(["status", "csrfToken"]), "QR login consume result");
  if (envelope.status === "pending" && Object.keys(envelope).length === 1) return { status: "pending" };
  if (
    envelope.status === "authenticated"
    && typeof envelope.csrfToken === "string"
    && envelope.csrfToken.length > 0
    && Object.keys(envelope).length === 2
  ) {
    return { status: "authenticated", csrfToken: envelope.csrfToken };
  }
  throw new TypeError("QR login consume result has an invalid shape");
}

function requireBoundedInteger(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} is outside the supported range`);
  }
  return value;
}

/** Owns one bounded browser QR challenge polling lifecycle. */
export function createQRLoginPoller(options: QRLoginPollerOptions) {
  const now = options.now ?? Date.now;
  const schedule = options.schedule ?? setTimeout;
  const clearScheduled = options.clearScheduled ?? clearTimeout;
  const random = options.random ?? Math.random;
  const intervalMs = requireBoundedInteger(options.intervalMs ?? DEFAULT_INTERVAL_MS, 250, 60_000, "intervalMs");
  const maxIntervalMs = requireBoundedInteger(options.maxIntervalMs ?? DEFAULT_MAX_INTERVAL_MS, intervalMs, 60_000, "maxIntervalMs");
  const maxTransientFailures = requireBoundedInteger(
    options.maxTransientFailures ?? DEFAULT_MAX_TRANSIENT_FAILURES,
    0,
    20,
    "maxTransientFailures",
  );
  const jitterRatio = options.jitterRatio ?? DEFAULT_JITTER_RATIO;
  if (!Number.isFinite(jitterRatio) || jitterRatio < 0 || jitterRatio > 0.5) {
    throw new TypeError("jitterRatio is outside the supported range");
  }
  const expiresAt = now() + options.challenge.expiresInSeconds * 1_000;
  const controller = new AbortController();
  let timer: TimerHandle | undefined;
  let stopped = false;
  let started = false;
  let consecutiveFailures = 0;

  function stopWithoutAbort(): void {
    stopped = true;
    if (timer !== undefined) clearScheduled(timer);
    timer = undefined;
  }

  function schedulePoll(delayMs: number): void {
    const timeRemaining = Math.max(0, expiresAt - now());
    timer = schedule(() => { void poll(); }, Math.min(delayMs, timeRemaining));
  }

  async function poll(): Promise<void> {
    if (stopped) return;
    const remainingSeconds = Math.max(0, Math.ceil((expiresAt - now()) / 1_000));
    options.onRemainingSeconds(remainingSeconds);
    if (remainingSeconds === 0) {
      stopWithoutAbort();
      options.onExpired();
      return;
    }

    let rawResult: unknown;
    try {
      rawResult = await options.consume(controller.signal);
    } catch (reason) {
      if (stopped || controller.signal.aborted) return;
      consecutiveFailures += 1;
      const retryable = options.isRetryableError?.(reason) ?? true;
      if (!retryable || consecutiveFailures > maxTransientFailures) {
        stopWithoutAbort();
        options.onError(reason);
        return;
      }
      const exponentialDelay = Math.min(maxIntervalMs, intervalMs * 2 ** (consecutiveFailures - 1));
      const randomUnit = Math.min(1, Math.max(0, random()));
      const jitterMultiplier = 1 + (randomUnit * 2 - 1) * jitterRatio;
      const retryDelay = Math.max(250, Math.round(exponentialDelay * jitterMultiplier));
      options.onRetry?.(reason, retryDelay, consecutiveFailures);
      schedulePoll(retryDelay);
      return;
    }

    let result: QRLoginConsumeResult;
    try {
      result = parseQRLoginConsumeResult(rawResult);
    } catch (reason) {
      stopWithoutAbort();
      options.onError(reason);
      return;
    }
    if (stopped) return;
    consecutiveFailures = 0;
    if (result.status === "authenticated") {
      stopWithoutAbort();
      options.onAuthenticated();
      return;
    }
    schedulePoll(intervalMs);
  }

  return {
    start(): Promise<void> {
      if (started) return Promise.resolve();
      started = true;
      return poll();
    },
    stop(): void {
      stopWithoutAbort();
      controller.abort();
    },
  };
}
