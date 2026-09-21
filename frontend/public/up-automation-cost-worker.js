// Dedicated worker asset for the bounded automation-cost challenge.
// It intentionally has no access to account data, cookies, or form contents.

const textEncoder = new TextEncoder();
const batchSize = 256;

self.onmessage = (event) => {
  void solve(event.data).then(
    (nonce) => self.postMessage({ status: "solved", nonce }),
    () => self.postMessage({ status: "failed", message: "automation_cost_failed" }),
  );
};

async function solve(request) {
  if (typeof request !== "object"
    || request === null
    || typeof request.challengeToken !== "string"
    || !Number.isSafeInteger(request.difficulty)
    || request.difficulty < 1
    || request.difficulty > 30) {
    throw new TypeError("invalid challenge");
  }

  let counter = 0;
  while (counter <= Number.MAX_SAFE_INTEGER - batchSize) {
    const candidates = Array.from({ length: batchSize }, (_, offset) =>
      (counter + offset).toString(36));
    const digests = await Promise.all(candidates.map((nonce) =>
      crypto.subtle.digest(
        "SHA-256",
        textEncoder.encode(`${request.challengeToken}:${nonce}`),
      )));
    const matchIndex = digests.findIndex((digest) =>
      hasLeadingZeroBits(new Uint8Array(digest), request.difficulty));
    if (matchIndex >= 0) return candidates[matchIndex];
    counter += batchSize;
  }

  throw new Error("nonce space exhausted");
}

function hasLeadingZeroBits(bytes, difficulty) {
  const completeBytes = Math.floor(difficulty / 8);
  for (let index = 0; index < completeBytes; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  const remainingBits = difficulty % 8;
  if (remainingBits === 0) return true;
  const highBitsMask = (0xff << (8 - remainingBits)) & 0xff;
  return (bytes[completeBytes] & highBitsMask) === 0;
}

