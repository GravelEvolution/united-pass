//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-09
// Description: WebAuthn JSON conversion and serialization tests
//

import { describe, expect, it } from "vitest";
import {
  WebAuthnContractError,
  arrayBufferToBase64Url,
  base64UrlToArrayBuffer,
  parseCreationOptions,
  parseRequestOptions,
  serializeAssertionCredential,
  serializeAttestationCredential,
} from "./webauthn";

function bytes(...values: number[]): ArrayBuffer {
  return new Uint8Array(values).buffer;
}

function bufferSourceBytes(value: BufferSource): number[] {
  const view = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return Array.from(view);
}

describe("WebAuthn base64url conversion", () => {
  it("round-trips binary without padding", () => {
    const encoded = arrayBufferToBase64Url(bytes(0xfb, 0xff, 0x00, 0x01));
    expect(encoded).toBe("-_8AAQ");
    expect(Array.from(new Uint8Array(base64UrlToArrayBuffer(encoded)))).toEqual([0xfb, 0xff, 0x00, 0x01]);
  });

  it("rejects non-base64url input", () => {
    expect(() => base64UrlToArrayBuffer("not/base64")).toThrow(WebAuthnContractError);
    expect(() => base64UrlToArrayBuffer("")).toThrow(WebAuthnContractError);
  });
});

describe("WebAuthn option parsing", () => {
  it("decodes creation challenge, user ID and excluded credential IDs", () => {
    const options = parseCreationOptions({
      challenge: "AQI",
      rp: { id: "login.example.com", name: "统一登录门户" },
      user: { id: "AwQ", name: "usr_1", displayName: "用户" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ type: "public-key", id: "BQY", transports: ["internal"] }],
      authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      extensions: { credProps: true },
    });

    expect(bufferSourceBytes(options.challenge)).toEqual([1, 2]);
    expect(bufferSourceBytes(options.user.id)).toEqual([3, 4]);
    expect(bufferSourceBytes(options.excludeCredentials?.[0].id ?? bytes())).toEqual([5, 6]);
    expect(options.pubKeyCredParams).toEqual([{ type: "public-key", alg: -7 }]);
  });

  it("decodes assertion challenge and allow-list IDs", () => {
    const options = parseRequestOptions({
      challenge: "AQI",
      rpId: "login.example.com",
      allowCredentials: [{ type: "public-key", id: "AwQ", transports: ["usb"] }],
      userVerification: "preferred",
    });
    expect(bufferSourceBytes(options.challenge)).toEqual([1, 2]);
    expect(bufferSourceBytes(options.allowCredentials?.[0].id ?? bytes())).toEqual([3, 4]);
  });

  it("unwraps provider publicKey envelopes for creation and assertion options", () => {
    const creation = parseCreationOptions({
      publicKey: {
        challenge: "AQI",
        rp: { id: "login.example.com", name: "统一登录门户" },
        user: { id: "AwQ", name: "usr_1", displayName: "用户" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      },
    });
    const assertion = parseRequestOptions({
      publicKey: {
        challenge: "BQY",
        rpId: "login.example.com",
      },
    });

    expect(bufferSourceBytes(creation.challenge)).toEqual([1, 2]);
    expect(bufferSourceBytes(assertion.challenge)).toEqual([5, 6]);
  });

  it("fails closed on missing required creation fields or unknown extensions", () => {
    expect(() => parseCreationOptions({ challenge: "AQI" })).toThrow(WebAuthnContractError);
    expect(() => parseCreationOptions({
      challenge: "AQI",
      rp: { name: "RP" },
      user: { id: "AwQ", name: "u", displayName: "U" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      extensions: { unknown: true },
    })).toThrow(WebAuthnContractError);
    expect(() => parseCreationOptions({
      publicKey: {
        challenge: "AQI",
        rp: { name: "RP" },
        user: { id: "AwQ", name: "u", displayName: "U" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      },
      challenge: "mixed",
    })).toThrow(WebAuthnContractError);
  });
});

describe("WebAuthn credential serialization", () => {
  it("serializes attestation buffers, transports and extension buffers", () => {
    const credential = {
      id: "credential-1",
      type: "public-key",
      rawId: bytes(1, 2),
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: bytes(3, 4),
        attestationObject: bytes(5, 6),
        getTransports: () => ["internal"],
      },
      getClientExtensionResults: () => ({ prf: { results: { first: bytes(7, 8) } } }),
    } as unknown as Credential;

    expect(serializeAttestationCredential(credential)).toEqual({
      id: "credential-1",
      type: "public-key",
      rawId: "AQI",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: "AwQ",
        attestationObject: "BQY",
        transports: ["internal"],
      },
      clientExtensionResults: { prf: { results: { first: "Bwg" } } },
    });
  });

  it("serializes assertion buffers including a nullable user handle", () => {
    const credential = {
      id: "credential-2",
      type: "public-key",
      rawId: bytes(1),
      authenticatorAttachment: null,
      response: {
        clientDataJSON: bytes(2),
        authenticatorData: bytes(3),
        signature: bytes(4),
        userHandle: null,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as Credential;

    expect(serializeAssertionCredential(credential)).toEqual({
      id: "credential-2",
      type: "public-key",
      rawId: "AQ",
      authenticatorAttachment: null,
      response: {
        clientDataJSON: "Ag",
        authenticatorData: "Aw",
        signature: "BA",
        userHandle: null,
      },
      clientExtensionResults: {},
    });
  });
});
