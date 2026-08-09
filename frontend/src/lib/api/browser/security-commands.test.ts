//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-09
// Description: P4.5 real browser command contract tests
//

import { afterEach, describe, expect, it, vi } from "vitest";
import { browserCommands } from "./browser-commands";
import { ApiResponseShapeError } from "@/lib/api/response-validators";
import type { SerializedAttestationCredential } from "@/features/account/types";

type FetchCall = { url: string; init: RequestInit };

function stubFetch(response: Response): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal("document", { cookie: "up_csrf=csrf-value" });
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return response;
  }));
  return calls;
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function bodyOf(call: FetchCall): Record<string, unknown> {
  return JSON.parse(String(call.init.body)) as Record<string, unknown>;
}

function headerOf(call: FetchCall, name: string): string | null {
  return new Headers(call.init.headers as HeadersInit).get(name);
}

afterEach(() => vi.unstubAllGlobals());

describe("P4.5 browserCommands", () => {
  it("requests account-bound reauthentication without fake application bindings", async () => {
    const calls = stubFetch(jsonResponse({
      status: "mfa_required",
      reauthToken: "challenge",
      availableMethods: ["totp"],
      expiresAt: "2026-08-09T12:00:00Z",
    }, 202));

    await browserCommands.requestReauthentication({
      action: "account.passkey.remove",
      target: "pk-A",
      password: "user-password",
    });

    expect(calls[0].url).toBe("/api/v1/auth/reauthentication");
    expect(bodyOf(calls[0])).toEqual({
      action: "account.passkey.remove",
      applicationId: "",
      clientId: "",
      target: "pk-A",
      password: "user-password",
    });
  });

  it("carries the constrained reauthentication header only on passkey begin", async () => {
    const calls = stubFetch(jsonResponse({
      enrollmentToken: "enrollment",
      passkeyId: "pk-new",
      publicKeyCredentialCreationOptions: { challenge: "AQI" },
    }));

    const controller = new AbortController();
    await browserCommands.startPasskeyEnrollment("grant", { signal: controller.signal });

    expect(calls[0].url).toBe("/api/v1/me/security/passkeys/enrollment");
    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBe("grant");
    expect(headerOf(calls[0], "X-CSRF-Token")).toBe("csrf-value");
    expect(calls[0].init.signal).toBe(controller.signal);
  });

  it("submits attestation without leaking the local expected passkey ID field", async () => {
    const calls = stubFetch(jsonResponse({ status: "confirmed", passkeyId: "pk-new" }));
    const credential: SerializedAttestationCredential = {
      id: "credential",
      rawId: "AQI",
      type: "public-key",
      response: { clientDataJSON: "AwQ", attestationObject: "BQY" },
      clientExtensionResults: {},
    };

    const controller = new AbortController();
    await browserCommands.completePasskeyEnrollment({
      enrollmentToken: "enrollment",
      passkeyId: "pk-new",
      publicKeyCredential: credential,
      passkeyName: "",
    }, { signal: controller.signal });

    expect(bodyOf(calls[0])).toEqual({
      enrollmentToken: "enrollment",
      publicKeyCredential: credential,
      passkeyName: "",
    });
    expect(bodyOf(calls[0])).not.toHaveProperty("passkeyId");
    expect(calls[0].init.signal).toBe(controller.signal);
  });

  it("rejects confirmation when provider identity does not match begin", async () => {
    stubFetch(jsonResponse({ status: "confirmed", passkeyId: "pk-other" }));
    const credential: SerializedAttestationCredential = {
      id: "credential",
      rawId: "AQI",
      type: "public-key",
      response: { clientDataJSON: "AwQ", attestationObject: "BQY" },
      clientExtensionResults: {},
    };
    await expect(browserCommands.completePasskeyEnrollment({
      enrollmentToken: "enrollment",
      passkeyId: "pk-new",
      publicKeyCredential: credential,
      passkeyName: "",
    })).rejects.toThrow(ApiResponseShapeError);
  });

  it("cancels with a body capability and removes the exact encoded target", async () => {
    let calls = stubFetch(new Response(null, { status: 204 }));
    await browserCommands.cancelPasskeyEnrollment("enrollment");
    expect(bodyOf(calls[0])).toEqual({ enrollmentToken: "enrollment" });

    vi.unstubAllGlobals();
    calls = stubFetch(jsonResponse({
      password: { set: true },
      totp: { enabled: true },
      passkeys: [],
      recoveryCodes: { available: false, deferredReason: "provider_unsupported" },
    }));
    await browserCommands.removePasskey("pk/target", "remove-grant");
    expect(calls[0].url).toBe("/api/v1/me/security/passkeys/pk%2Ftarget");
    expect(headerOf(calls[0], "X-Reauthentication-Token")).toBe("remove-grant");
  });
});
