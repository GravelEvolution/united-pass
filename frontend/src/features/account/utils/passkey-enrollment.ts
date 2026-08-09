//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-09
// Description: Abort-aware passkey enrollment browser-ceremony orchestration
//

import type {
  PasskeyEnrollment,
  SerializedAttestationCredential,
} from "@/features/account/types";
import type {
  BrowserCommandOptions,
  UnitedPassCommands,
} from "@/lib/api/united-pass-data-source";
import { createPasskeyCredential } from "@/features/account/utils/webauthn";

export type PasskeyCredentialCreator = (
  options: unknown,
  signal: AbortSignal,
) => Promise<SerializedAttestationCredential>;

type PasskeyEnrollmentCommands = Pick<
  UnitedPassCommands,
  | "startPasskeyEnrollment"
  | "completePasskeyEnrollment"
  | "cancelPasskeyEnrollment"
>;

type RunPasskeyEnrollmentCeremonyInput = {
  reauthToken: string;
  signal: AbortSignal;
  commands: PasskeyEnrollmentCommands;
  createCredential: PasskeyCredentialCreator;
};

export const mockPasskeyAttestationCredential: SerializedAttestationCredential = {
  id: "mock-credential",
  rawId: "bW9jay1jcmVkZW50aWFs",
  type: "public-key",
  response: {
    clientDataJSON: "bW9jay1jbGllbnQtZGF0YQ",
    attestationObject: "bW9jay1hdHRlc3RhdGlvbg",
  },
  clientExtensionResults: {},
};

export function passkeyCredentialCreator(useMock: boolean): PasskeyCredentialCreator {
  if (useMock) {
    return async () => mockPasskeyAttestationCredential;
  }
  return createPasskeyCredential;
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) {
    throw new DOMException("The passkey enrollment was aborted.", "AbortError");
  }
}

async function cancelAfterFailure(
  commands: PasskeyEnrollmentCommands,
  enrollment: PasskeyEnrollment | undefined,
): Promise<void> {
  if (enrollment === undefined) return;
  try {
    // Cancellation deliberately does not reuse the aborted ceremony signal:
    // once the browser has received an enrollment capability, provider
    // settlement must still be attempted. The expiry worker is the fallback.
    await commands.cancelPasskeyEnrollment(enrollment.enrollmentToken);
  } catch {
    // The UI reports one generic ceremony failure. Cancellation/provider
    // details are neither exposed nor used as authority; the worker retries.
  }
}

export async function runPasskeyEnrollmentCeremony({
  reauthToken,
  signal,
  commands,
  createCredential,
}: RunPasskeyEnrollmentCeremonyInput): Promise<string> {
  let enrollment: PasskeyEnrollment | undefined;
  const requestOptions: BrowserCommandOptions = { signal };
  try {
    enrollment = await commands.startPasskeyEnrollment(reauthToken, requestOptions);
    throwIfAborted(signal);

    const credential = await createCredential(
      enrollment.publicKeyCredentialCreationOptions,
      signal,
    );
    throwIfAborted(signal);

    await commands.completePasskeyEnrollment({
      enrollmentToken: enrollment.enrollmentToken,
      passkeyId: enrollment.passkeyId,
      publicKeyCredential: credential,
      passkeyName: "",
    }, requestOptions);
    throwIfAborted(signal);
    return enrollment.passkeyId;
  } catch {
    await cancelAfterFailure(commands, enrollment);
    throw new Error("passkey enrollment ceremony failed");
  }
}
