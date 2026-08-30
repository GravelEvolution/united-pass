"use client";

const BATCH_SIZE = 128;

type WorkerResponse =
  | { status: "solved"; nonce: string }
  | { status: "failed"; message: string };

export async function solveAutomationCost(
  challengeToken: string,
  difficulty: number,
  signal?: AbortSignal,
): Promise<string> {
  assertChallenge(challengeToken, difficulty);
  if (signal?.aborted) throw signal.reason;

  if (typeof Worker !== "undefined") {
    return solveInWorker(challengeToken, difficulty, signal);
  }

  // Tests and older browser shells may not expose Worker. This cooperative
  // fallback yields between small batches so it never monopolizes the UI.
  return solveCooperatively(challengeToken, difficulty, signal);
}

export function hasLeadingZeroBits(bytes: Uint8Array, difficulty: number): boolean {
  const completeBytes = Math.floor(difficulty / 8);
  for (let index = 0; index < completeBytes; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  const remainingBits = difficulty % 8;
  if (remainingBits === 0) return true;
  const highBitsMask = (0xff << (8 - remainingBits)) & 0xff;
  return (bytes[completeBytes] & highBitsMask) === 0;
}

function solveInWorker(
  challengeToken: string,
  difficulty: number,
  signal?: AbortSignal,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const worker = new Worker("/up-automation-cost-worker.js", {
      name: "up-automation-cost",
    });
    const stop = () => worker.terminate();
    const abort = () => {
      stop();
      reject(signal?.reason);
    };

    signal?.addEventListener("abort", abort, { once: true });
    worker.onerror = () => {
      signal?.removeEventListener("abort", abort);
      stop();
      reject(new Error("额外验证计算未完成，请重试。"));
    };
    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      signal?.removeEventListener("abort", abort);
      stop();
      if (event.data.status === "solved") {
        resolve(event.data.nonce);
        return;
      }
      reject(new Error("额外验证计算未完成，请重试。"));
    };
    worker.postMessage({ challengeToken, difficulty });
  });
}

async function solveCooperatively(
  challengeToken: string,
  difficulty: number,
  signal?: AbortSignal,
): Promise<string> {
  const encoder = new TextEncoder();
  let counter = 0;
  while (counter <= Number.MAX_SAFE_INTEGER - BATCH_SIZE) {
    if (signal?.aborted) throw signal.reason;
    const candidates = Array.from({ length: BATCH_SIZE }, (_, offset) =>
      (counter + offset).toString(36));
    const digests = await Promise.all(candidates.map((nonce) =>
      crypto.subtle.digest("SHA-256", encoder.encode(`${challengeToken}:${nonce}`))));
    const matchIndex = digests.findIndex((digest) =>
      hasLeadingZeroBits(new Uint8Array(digest), difficulty));
    if (matchIndex >= 0) return candidates[matchIndex];
    counter += BATCH_SIZE;
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("额外验证计算未完成，请重试。")
}

function assertChallenge(challengeToken: string, difficulty: number): void {
  if (challengeToken.length === 0 || challengeToken.length > 512) {
    throw new TypeError("challengeToken has an invalid length");
  }
  if (!Number.isSafeInteger(difficulty) || difficulty < 1 || difficulty > 30) {
    throw new TypeError("difficulty must be an integer between 1 and 30");
  }
}
