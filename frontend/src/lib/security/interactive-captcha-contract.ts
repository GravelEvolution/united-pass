export const TURNSTILE_PROVIDER = "cloudflare_turnstile";
export const RECAPTCHA_PROVIDER = "google_recaptcha";
export const FIRST_PARTY_IMAGE_PROVIDER = "moonstone_image_digits";

export type TurnstileChallengeDescriptor = {
  provider: typeof TURNSTILE_PROVIDER;
  siteKey: string;
  action: string;
  cdata: string;
};

export type RecaptchaChallengeDescriptor = {
  provider: typeof RECAPTCHA_PROVIDER;
  siteKey: string;
  action: string;
};

export type FirstPartyImageChallengeDescriptor = {
  provider: typeof FIRST_PARTY_IMAGE_PROVIDER;
  imageDataUrl: string;
  digits: number;
};

export type InteractiveCaptchaDescriptor =
  | TurnstileChallengeDescriptor
  | RecaptchaChallengeDescriptor
  | FirstPartyImageChallengeDescriptor;

const ACTION_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const CDATA_PATTERN = /^[A-Za-z0-9_-]{1,255}$/;

/**
 * Narrows only the reviewed provider payloads implemented by this build. The
 * provider identifier comes from the signed server challenge; the browser has
 * no provider-selection input of its own.
 */
export function parseInteractiveCaptchaDescriptor(
  provider: unknown,
  payload: unknown,
): InteractiveCaptchaDescriptor | undefined {
  if (!isRecord(payload)) return undefined;

  if (provider === TURNSTILE_PROVIDER) {
    if (!hasOnlyKeys(payload, ["siteKey", "action", "cdata"])) return undefined;
    if (!validSiteKey(payload.siteKey)
      || typeof payload.action !== "string"
      || !ACTION_PATTERN.test(payload.action)
      || typeof payload.cdata !== "string"
      || !CDATA_PATTERN.test(payload.cdata)) return undefined;
    return {
      provider,
      siteKey: payload.siteKey,
      action: payload.action,
      cdata: payload.cdata,
    };
  }

  if (provider === RECAPTCHA_PROVIDER) {
    if (!hasOnlyKeys(payload, ["siteKey", "action"])) return undefined;
    if (!validSiteKey(payload.siteKey)
      || typeof payload.action !== "string"
      || !ACTION_PATTERN.test(payload.action)) return undefined;
    return { provider, siteKey: payload.siteKey, action: payload.action };
  }

  if (provider === FIRST_PARTY_IMAGE_PROVIDER) {
    if (!hasOnlyKeys(payload, ["imageDataUrl", "digits"])) return undefined;
    if (!validInlineDigitImage(payload.imageDataUrl)
      || typeof payload.digits !== "number"
      || !Number.isSafeInteger(payload.digits)
      || payload.digits < 4
      || payload.digits > 8) return undefined;
    return {
      provider,
      imageDataUrl: payload.imageDataUrl,
      digits: payload.digits,
    };
  }

  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function validSiteKey(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512;
}

function validInlineDigitImage(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 32 * 1024) return false;
  const prefix = "data:image/png;base64,";
  if (!value.startsWith(prefix)) return false;
  const encoded = value.slice(prefix.length);
  return encoded.startsWith("iVBORw0KGgo")
    && encoded.length % 4 === 0
    && /^[A-Za-z0-9+/]+={0,2}$/u.test(encoded);
}
