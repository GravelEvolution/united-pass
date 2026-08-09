//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-09
// Description: Strict WebAuthn JSON/DOM conversion for account passkeys
//

import type {
  SerializedAssertionCredential,
  SerializedAttestationCredential,
} from "@/features/account/types";

export class WebAuthnContractError extends Error {
  constructor(field: string) {
    super(`WebAuthn payload does not match the ${field} contract`);
    this.name = "WebAuthnContractError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (!isRecord(value)) throw new WebAuthnContractError(field);
  return value;
}

function unwrapPublicKeyOptions(value: unknown, field: string): Record<string, unknown> {
  const record = requireRecord(value, field);
  if (record.publicKey === undefined) return record;
  if (Object.keys(record).some((key) => key !== "publicKey")) {
    throw new WebAuthnContractError(field);
  }
  return requireRecord(record.publicKey, `${field}.publicKey`);
}

function requireString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new WebAuthnContractError(field);
  }
  return value;
}

function optionalString(record: Record<string, unknown>, field: string): string | undefined {
  const value = record[field];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0) {
    throw new WebAuthnContractError(field);
  }
  return value;
}

function optionalNumber(record: Record<string, unknown>, field: string): number | undefined {
  const value = record[field];
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new WebAuthnContractError(field);
  }
  return value;
}

export function base64UrlToArrayBuffer(value: string): ArrayBuffer {
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) {
    throw new WebAuthnContractError("base64url");
  }
  const unpadded = value.replace(/=+$/, "");
  const padding = "=".repeat((4 - (unpadded.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(unpadded.replace(/-/g, "+").replace(/_/g, "/") + padding);
  } catch {
    throw new WebAuthnContractError("base64url");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

export function arrayBufferToBase64Url(value: ArrayBuffer | ArrayBufferView): string {
  const bytes = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const transports = new Set<AuthenticatorTransport>([
  "ble", "hybrid", "internal", "nfc", "usb",
]);

function parseTransports(value: unknown, field: string): AuthenticatorTransport[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) throw new WebAuthnContractError(field);
  return value.map((transport) => {
    if (typeof transport !== "string" || !transports.has(transport as AuthenticatorTransport)) {
      throw new WebAuthnContractError(field);
    }
    return transport as AuthenticatorTransport;
  });
}

function parseCredentialDescriptors(value: unknown, field: string): PublicKeyCredentialDescriptor[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) throw new WebAuthnContractError(field);
  return value.map((descriptorValue) => {
    const descriptor = requireRecord(descriptorValue, field);
    if (descriptor.type !== "public-key") throw new WebAuthnContractError(`${field}.type`);
    const parsedTransports = parseTransports(descriptor.transports, `${field}.transports`);
    return {
      type: "public-key",
      id: base64UrlToArrayBuffer(requireString(descriptor, "id")),
      ...(parsedTransports !== undefined && { transports: parsedTransports }),
    };
  });
}

function parseUserVerification(value: unknown, field: string): UserVerificationRequirement | undefined {
  if (value === undefined) return undefined;
  if (value !== "discouraged" && value !== "preferred" && value !== "required") {
    throw new WebAuthnContractError(field);
  }
  return value;
}

function parseCreationExtensions(value: unknown): AuthenticationExtensionsClientInputs | undefined {
  if (value === undefined) return undefined;
  const record = requireRecord(value, "creationOptions.extensions");
  const keys = Object.keys(record);
  if (keys.some((key) => key !== "credProps")) {
    throw new WebAuthnContractError("creationOptions.extensions");
  }
  if (record.credProps !== undefined && typeof record.credProps !== "boolean") {
    throw new WebAuthnContractError("creationOptions.extensions.credProps");
  }
  return record.credProps === undefined ? {} : { credProps: record.credProps };
}

function parseRequestExtensions(value: unknown): AuthenticationExtensionsClientInputs | undefined {
  if (value === undefined) return undefined;
  const record = requireRecord(value, "requestOptions.extensions");
  const keys = Object.keys(record);
  if (keys.some((key) => key !== "appid")) {
    throw new WebAuthnContractError("requestOptions.extensions");
  }
  if (record.appid !== undefined && typeof record.appid !== "string") {
    throw new WebAuthnContractError("requestOptions.extensions.appid");
  }
  return record.appid === undefined ? {} : { appid: record.appid };
}

export function parseCreationOptions(value: unknown): PublicKeyCredentialCreationOptions {
  const record = unwrapPublicKeyOptions(value, "creationOptions");
  const rp = requireRecord(record.rp, "creationOptions.rp");
  const user = requireRecord(record.user, "creationOptions.user");
  if (!Array.isArray(record.pubKeyCredParams) || record.pubKeyCredParams.length === 0) {
    throw new WebAuthnContractError("creationOptions.pubKeyCredParams");
  }
  const pubKeyCredParams = record.pubKeyCredParams.map((parameterValue) => {
    const parameter = requireRecord(parameterValue, "creationOptions.pubKeyCredParams");
    if (parameter.type !== "public-key" || typeof parameter.alg !== "number" || !Number.isInteger(parameter.alg)) {
      throw new WebAuthnContractError("creationOptions.pubKeyCredParams");
    }
    return { type: "public-key" as const, alg: parameter.alg };
  });

  const timeout = optionalNumber(record, "timeout");
  const excludeCredentials = parseCredentialDescriptors(record.excludeCredentials, "creationOptions.excludeCredentials");
  const extensions = parseCreationExtensions(record.extensions);
  const authenticatorSelectionValue = record.authenticatorSelection;
  let authenticatorSelection: AuthenticatorSelectionCriteria | undefined;
  if (authenticatorSelectionValue !== undefined) {
    const selection = requireRecord(authenticatorSelectionValue, "creationOptions.authenticatorSelection");
    const attachment = selection.authenticatorAttachment;
    if (attachment !== undefined && attachment !== "platform" && attachment !== "cross-platform") {
      throw new WebAuthnContractError("creationOptions.authenticatorSelection.authenticatorAttachment");
    }
    const residentKey = selection.residentKey;
    if (residentKey !== undefined && residentKey !== "discouraged" && residentKey !== "preferred" && residentKey !== "required") {
      throw new WebAuthnContractError("creationOptions.authenticatorSelection.residentKey");
    }
    if (selection.requireResidentKey !== undefined && typeof selection.requireResidentKey !== "boolean") {
      throw new WebAuthnContractError("creationOptions.authenticatorSelection.requireResidentKey");
    }
    authenticatorSelection = {
      ...(attachment !== undefined && { authenticatorAttachment: attachment }),
      ...(residentKey !== undefined && { residentKey }),
      ...(selection.requireResidentKey !== undefined && { requireResidentKey: selection.requireResidentKey }),
      ...(parseUserVerification(selection.userVerification, "creationOptions.authenticatorSelection.userVerification") !== undefined && {
        userVerification: parseUserVerification(selection.userVerification, "creationOptions.authenticatorSelection.userVerification"),
      }),
    };
  }
  const attestation = record.attestation;
  if (attestation !== undefined && attestation !== "none" && attestation !== "indirect" && attestation !== "direct" && attestation !== "enterprise") {
    throw new WebAuthnContractError("creationOptions.attestation");
  }

  return {
    challenge: base64UrlToArrayBuffer(requireString(record, "challenge")),
    rp: {
      name: requireString(rp, "name"),
      ...(optionalString(rp, "id") !== undefined && { id: optionalString(rp, "id") }),
    },
    user: {
      id: base64UrlToArrayBuffer(requireString(user, "id")),
      name: requireString(user, "name"),
      displayName: requireString(user, "displayName"),
    },
    pubKeyCredParams,
    ...(timeout !== undefined && { timeout }),
    ...(excludeCredentials !== undefined && { excludeCredentials }),
    ...(authenticatorSelection !== undefined && { authenticatorSelection }),
    ...(attestation !== undefined && { attestation }),
    ...(extensions !== undefined && { extensions }),
  };
}

export function parseRequestOptions(value: unknown): PublicKeyCredentialRequestOptions {
  const record = unwrapPublicKeyOptions(value, "requestOptions");
  const timeout = optionalNumber(record, "timeout");
  const rpId = optionalString(record, "rpId");
  const allowCredentials = parseCredentialDescriptors(record.allowCredentials, "requestOptions.allowCredentials");
  const userVerification = parseUserVerification(record.userVerification, "requestOptions.userVerification");
  const extensions = parseRequestExtensions(record.extensions);
  return {
    challenge: base64UrlToArrayBuffer(requireString(record, "challenge")),
    ...(timeout !== undefined && { timeout }),
    ...(rpId !== undefined && { rpId }),
    ...(allowCredentials !== undefined && { allowCredentials }),
    ...(userVerification !== undefined && { userVerification }),
    ...(extensions !== undefined && { extensions }),
  };
}

function serializeExtensionValue(value: unknown): unknown {
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return arrayBufferToBase64Url(value);
  }
  if (Array.isArray(value)) return value.map(serializeExtensionValue);
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, serializeExtensionValue(nested)]),
    );
  }
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  throw new WebAuthnContractError("credential.clientExtensionResults");
}

function requireBufferSource(value: unknown, field: string): ArrayBuffer | ArrayBufferView {
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return value;
  throw new WebAuthnContractError(field);
}

function parseAuthenticatorAttachment(
  value: string | null | undefined,
): "platform" | "cross-platform" | null | undefined {
  if (value === undefined || value === null) return value;
  if (value !== "platform" && value !== "cross-platform") {
    throw new WebAuthnContractError("credential.authenticatorAttachment");
  }
  return value;
}

function serializeExtensionResults(credential: PublicKeyCredential): Record<string, unknown> {
  const serialized = serializeExtensionValue(credential.getClientExtensionResults());
  if (!isRecord(serialized)) throw new WebAuthnContractError("credential.clientExtensionResults");
  return serialized;
}

function requirePublicKeyCredential(credential: Credential | null): PublicKeyCredential {
  if (
    credential === null ||
    credential.type !== "public-key" ||
    typeof credential.id !== "string" ||
    credential.id.length === 0 ||
    !("rawId" in credential) ||
    !("response" in credential) ||
    !("getClientExtensionResults" in credential)
  ) {
    throw new WebAuthnContractError("credential");
  }
  return credential as PublicKeyCredential;
}

export function serializeAttestationCredential(credentialValue: Credential | null): SerializedAttestationCredential {
  const credential = requirePublicKeyCredential(credentialValue);
  const response = credential.response;
  if (!("clientDataJSON" in response) || !("attestationObject" in response)) {
    throw new WebAuthnContractError("attestation.response");
  }
  const transportsValue = "getTransports" in response && typeof response.getTransports === "function"
    ? parseTransports(response.getTransports(), "attestation.response.transports")
    : undefined;
  const attachment = parseAuthenticatorAttachment(credential.authenticatorAttachment);
  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: "public-key",
    response: {
      clientDataJSON: arrayBufferToBase64Url(requireBufferSource(response.clientDataJSON, "attestation.response.clientDataJSON")),
      attestationObject: arrayBufferToBase64Url(requireBufferSource(response.attestationObject, "attestation.response.attestationObject")),
      ...(transportsValue !== undefined && { transports: transportsValue }),
    },
    clientExtensionResults: serializeExtensionResults(credential),
    ...(attachment !== undefined && {
      authenticatorAttachment: attachment,
    }),
  };
}

export function serializeAssertionCredential(credentialValue: Credential | null): SerializedAssertionCredential {
  const credential = requirePublicKeyCredential(credentialValue);
  const response = credential.response;
  if (!("clientDataJSON" in response) || !("authenticatorData" in response) || !("signature" in response) || !("userHandle" in response)) {
    throw new WebAuthnContractError("assertion.response");
  }
  const userHandle = response.userHandle;
  if (userHandle !== null && userHandle !== undefined) {
    requireBufferSource(userHandle, "assertion.response.userHandle");
  }
  const attachment = parseAuthenticatorAttachment(credential.authenticatorAttachment);
  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: "public-key",
    response: {
      clientDataJSON: arrayBufferToBase64Url(requireBufferSource(response.clientDataJSON, "assertion.response.clientDataJSON")),
      authenticatorData: arrayBufferToBase64Url(requireBufferSource(response.authenticatorData, "assertion.response.authenticatorData")),
      signature: arrayBufferToBase64Url(requireBufferSource(response.signature, "assertion.response.signature")),
      userHandle: userHandle === null || userHandle === undefined
        ? null
        : arrayBufferToBase64Url(requireBufferSource(userHandle, "assertion.response.userHandle")),
    },
    clientExtensionResults: serializeExtensionResults(credential),
    ...(attachment !== undefined && {
      authenticatorAttachment: attachment,
    }),
  };
}

export function isWebAuthnSupported(): boolean {
  return typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator.credentials?.create === "function" &&
    typeof navigator.credentials?.get === "function";
}

export async function createPasskeyCredential(
  options: unknown,
  signal: AbortSignal,
): Promise<SerializedAttestationCredential> {
  if (!isWebAuthnSupported()) throw new WebAuthnContractError("browserSupport");
  const credential = await navigator.credentials.create({
    publicKey: parseCreationOptions(options),
    signal,
  });
  return serializeAttestationCredential(credential);
}

export async function getPasskeyAssertion(
  options: unknown,
  signal: AbortSignal,
): Promise<SerializedAssertionCredential> {
  if (!isWebAuthnSupported()) throw new WebAuthnContractError("browserSupport");
  const credential = await navigator.credentials.get({
    publicKey: parseRequestOptions(options),
    signal,
  });
  return serializeAssertionCredential(credential);
}
