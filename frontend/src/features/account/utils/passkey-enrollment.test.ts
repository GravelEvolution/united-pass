//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-09
// Description: Abort and settlement tests for passkey enrollment orchestration
//

import { describe, expect, it, vi } from "vitest";
import type { UnitedPassCommands } from "@/lib/api/united-pass-data-source";
import {
  mockPasskeyAttestationCredential,
  passkeyCredentialCreator,
  runPasskeyEnrollmentCeremony,
} from "./passkey-enrollment";

type CeremonyCommands = Pick<
  UnitedPassCommands,
  | "startPasskeyEnrollment"
  | "completePasskeyEnrollment"
  | "cancelPasskeyEnrollment"
>;

function commands(): CeremonyCommands {
  return {
    startPasskeyEnrollment: vi.fn(async () => ({
      enrollmentToken: "enrollment-token",
      passkeyId: "pk-new",
      publicKeyCredentialCreationOptions: { challenge: "AQI" },
    })),
    completePasskeyEnrollment: vi.fn(async (input) => ({
      status: "confirmed" as const,
      passkeyId: input.passkeyId,
    })),
    cancelPasskeyEnrollment: vi.fn(async () => undefined),
  };
}

describe("passkey enrollment ceremony", () => {
  it("cancels after a post-begin browser rejection and never confirms", async () => {
    const api = commands();
    const createCredential = vi.fn(async () => {
      throw new DOMException("User cancelled", "NotAllowedError");
    });

    await expect(runPasskeyEnrollmentCeremony({
      reauthToken: "grant",
      signal: new AbortController().signal,
      commands: api,
      createCredential,
    })).rejects.toThrow("passkey enrollment ceremony failed");

    expect(api.cancelPasskeyEnrollment).toHaveBeenCalledWith("enrollment-token");
    expect(api.completePasskeyEnrollment).not.toHaveBeenCalled();
  });

  it("observes modal abort after begin, cancels and does not open WebAuthn", async () => {
    const api = commands();
    const controller = new AbortController();
    vi.mocked(api.startPasskeyEnrollment).mockImplementationOnce(async () => {
      controller.abort();
      return {
        enrollmentToken: "enrollment-token",
        passkeyId: "pk-new",
        publicKeyCredentialCreationOptions: { challenge: "AQI" },
      };
    });
    const createCredential = vi.fn(async () => mockPasskeyAttestationCredential);

    await expect(runPasskeyEnrollmentCeremony({
      reauthToken: "grant",
      signal: controller.signal,
      commands: api,
      createCredential,
    })).rejects.toThrow("passkey enrollment ceremony failed");

    expect(api.cancelPasskeyEnrollment).toHaveBeenCalledWith("enrollment-token");
    expect(createCredential).not.toHaveBeenCalled();
    expect(api.completePasskeyEnrollment).not.toHaveBeenCalled();
  });

  it("passes one signal through begin and confirm on success", async () => {
    const api = commands();
    const controller = new AbortController();

    await expect(runPasskeyEnrollmentCeremony({
      reauthToken: "grant",
      signal: controller.signal,
      commands: api,
      createCredential: async () => mockPasskeyAttestationCredential,
    })).resolves.toBe("pk-new");

    expect(api.startPasskeyEnrollment).toHaveBeenCalledWith(
      "grant",
      { signal: controller.signal },
    );
    expect(api.completePasskeyEnrollment).toHaveBeenCalledWith(
      expect.objectContaining({
        enrollmentToken: "enrollment-token",
        passkeyId: "pk-new",
        passkeyName: "当前设备",
      }),
      { signal: controller.signal },
    );
    expect(api.cancelPasskeyEnrollment).not.toHaveBeenCalled();
  });

  it("uses the mock credential without requiring browser WebAuthn APIs", async () => {
    const createCredential = passkeyCredentialCreator(true);
    await expect(createCredential(
      { malformedForRealWebAuthn: true },
      new AbortController().signal,
    )).resolves.toEqual(mockPasskeyAttestationCredential);
  });
});
