"use client";

import type {
  InteractiveCaptchaAdapter,
  InteractiveCaptchaInput,
} from "./interactive-captcha-adapter";
import {
  FIRST_PARTY_IMAGE_PROVIDER,
  parseInteractiveCaptchaDescriptor,
  RECAPTCHA_PROVIDER,
  TURNSTILE_PROVIDER,
  type FirstPartyImageChallengeDescriptor,
  type RecaptchaChallengeDescriptor,
  type TurnstileChallengeDescriptor,
} from "./interactive-captcha-contract";

const TURNSTILE_SCRIPT_ID = "up-turnstile-sdk";
const TURNSTILE_SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
const RECAPTCHA_SCRIPT_ID = "up-recaptcha-sdk";
const RECAPTCHA_SCRIPT_BASE = "https://www.recaptcha.net/recaptcha/api.js";
const SDK_LOAD_TIMEOUT_MS = 12_000;

type TurnstileAPI = {
  render(container: HTMLElement, options: {
    sitekey: string;
    action: string;
    cData: string;
    size: "flexible" | "compact";
    callback: (token: string) => void;
    "error-callback": () => void;
    "expired-callback": () => void;
    "timeout-callback": () => void;
    "response-field": boolean;
  }): string;
  remove(widgetId: string): void;
};

type RecaptchaAPI = {
  ready(callback: () => void): void;
  execute(siteKey: string, options: { action: string }): Promise<string>;
};

type CaptchaWindow = Window & {
  turnstile?: TurnstileAPI;
  grecaptcha?: RecaptchaAPI;
};

let turnstileScriptPromise: Promise<void> | undefined;
let recaptchaScript: { siteKey: string; promise: Promise<void> } | undefined;

/** Supports only server-selected providers whose verifier ships in the API. */
export const officialInteractiveCaptchaAdapter: InteractiveCaptchaAdapter = {
  id: "official-provider-router-v1",
  async execute(input: InteractiveCaptchaInput): Promise<string> {
    const descriptor = parseInteractiveCaptchaDescriptor(
      input.provider,
      input.providerPayload,
    );
    if (!descriptor) throw new Error("unsupported interactive CAPTCHA challenge");
    if (input.signal.aborted) throw abortReason(input.signal);

    switch (descriptor.provider) {
      case FIRST_PARTY_IMAGE_PROVIDER:
        return executeFirstPartyImage(descriptor, input);
      case TURNSTILE_PROVIDER:
        return executeTurnstile(descriptor, input);
      case RECAPTCHA_PROVIDER:
        return executeRecaptcha(descriptor, input);
    }
  },
};

function executeFirstPartyImage(
  descriptor: FirstPartyImageChallengeDescriptor,
  input: InteractiveCaptchaInput,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    if (input.signal.aborted) {
      reject(abortReason(input.signal));
      return;
    }

    const form = document.createElement("form");
    form.setAttribute("aria-label", "数字图片验证");
    form.style.display = "grid";
    form.style.gap = "12px";

    const image = document.createElement("img");
    image.src = descriptor.imageDataUrl;
    image.alt = `${descriptor.digits} 位数字验证码`;
    image.draggable = false;
    image.style.display = "block";
    image.style.width = "100%";
    image.style.maxWidth = "286px";
    image.style.height = "auto";
    image.style.margin = "0 auto";
    image.style.borderRadius = "12px";
    image.style.userSelect = "none";

    const label = document.createElement("label");
    label.style.display = "grid";
    label.style.gap = "6px";
    const labelText = document.createElement("span");
    labelText.textContent = `输入图片中的 ${descriptor.digits} 位数字`;
    const proofInput = document.createElement("input");
    proofInput.type = "text";
    proofInput.inputMode = "numeric";
    proofInput.autocomplete = "off";
    proofInput.maxLength = descriptor.digits * 2;
    proofInput.required = true;
    proofInput.setAttribute("aria-label", "图片验证码数字");
    proofInput.style.width = "100%";
    proofInput.style.boxSizing = "border-box";
    proofInput.style.padding = "11px 12px";
    proofInput.style.border = "1px solid var(--semi-color-border, #d9d9d9)";
    proofInput.style.borderRadius = "6px";
    proofInput.style.fontSize = "20px";
    proofInput.style.letterSpacing = ".25em";
    label.append(labelText, proofInput);

    const submit = document.createElement("button");
    submit.type = "submit";
    submit.textContent = "完成验证";
    submit.style.minHeight = "40px";
    submit.style.border = "0";
    submit.style.borderRadius = "6px";
    submit.style.background = "var(--semi-color-primary, #1456f0)";
    submit.style.color = "#fff";
    submit.style.fontWeight = "600";
    submit.style.cursor = "pointer";

    let settled = false;
    const cleanup = () => {
      input.signal.removeEventListener("abort", onAbort);
      form.removeEventListener("submit", onSubmit);
    };
    const finish = (error?: unknown, proof?: string) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error !== undefined) reject(error);
      else if (proof !== undefined) resolve(proof);
      else reject(new Error("image CAPTCHA returned no proof"));
    };
    const onAbort = () => finish(abortReason(input.signal));
    const onSubmit = (event: Event) => {
      event.preventDefault();
      const proof = proofInput.value.trim();
      const normalizedLength = Array.from(proof).filter((character) => !/\s/u.test(character)).length;
      if (normalizedLength !== descriptor.digits || !/^[0-9０-９\s]+$/u.test(proof)) {
        proofInput.setCustomValidity(`请输入图片中的 ${descriptor.digits} 位数字`);
        proofInput.reportValidity();
        return;
      }
      proofInput.setCustomValidity("");
      finish(undefined, proof);
    };

    input.signal.addEventListener("abort", onAbort, { once: true });
    form.addEventListener("submit", onSubmit);
    form.append(image, label, submit);
    input.container.replaceChildren(form);
    queueMicrotask(() => proofInput.focus());
  });
}

async function executeTurnstile(
  descriptor: TurnstileChallengeDescriptor,
  input: InteractiveCaptchaInput,
): Promise<string> {
  await abortable(loadTurnstile(), input.signal);
  if (input.signal.aborted) throw abortReason(input.signal);
  const api = captchaWindow().turnstile;
  if (!api) throw new Error("Turnstile SDK unavailable");

  return new Promise<string>((resolve, reject) => {
    let settled = false;
    let widgetId: string | undefined;
    const finish = (error?: Error, token?: string) => {
      if (settled) return;
      settled = true;
      input.signal.removeEventListener("abort", onAbort);
      if (widgetId !== undefined) removeTurnstileWidget(api, widgetId);
      if (error) reject(error);
      else if (token) resolve(token);
      else reject(new Error("Turnstile returned no proof"));
    };
    const onAbort = () => finish(abortReason(input.signal));
    input.signal.addEventListener("abort", onAbort, { once: true });

    try {
      const containerWidth = input.container.clientWidth;
      widgetId = api.render(input.container, {
        sitekey: descriptor.siteKey,
        action: descriptor.action,
        cData: descriptor.cdata,
        size: typeof containerWidth === "number" && containerWidth > 0 && containerWidth < 300
          ? "compact"
          : "flexible",
        callback: (token) => finish(undefined, token),
        "error-callback": () => finish(new Error("Turnstile verification failed")),
        "expired-callback": () => finish(new Error("Turnstile proof expired")),
        "timeout-callback": () => finish(new Error("Turnstile verification timed out")),
        "response-field": false,
      });
      if (settled && widgetId !== undefined) removeTurnstileWidget(api, widgetId);
    } catch (error) {
      finish(asError(error, "Turnstile render failed"));
    }
  });
}

function removeTurnstileWidget(api: TurnstileAPI, widgetId: string): void {
  try {
    api.remove(widgetId);
  } catch {
    // Cleanup failure must not leave the caller's promise unsettled; the API
    // still remains authoritative for accepting or rejecting the proof.
  }
}

async function executeRecaptcha(
  descriptor: RecaptchaChallengeDescriptor,
  input: InteractiveCaptchaInput,
): Promise<string> {
  await abortable(loadRecaptcha(descriptor.siteKey), input.signal);
  if (input.signal.aborted) throw abortReason(input.signal);
  const api = captchaWindow().grecaptcha;
  if (!api) throw new Error("reCAPTCHA SDK unavailable");

  await waitForRecaptcha(api, input.signal);
  const proofPromise = api.execute(descriptor.siteKey, { action: descriptor.action });
  const proof = await abortable(proofPromise, input.signal);
  if (typeof proof !== "string" || proof.length === 0 || proof.length > 4096) {
    throw new Error("reCAPTCHA returned an invalid proof");
  }
  return proof;
}

function loadTurnstile(): Promise<void> {
  turnstileScriptPromise ??= loadFixedScript(
    TURNSTILE_SCRIPT_ID,
    TURNSTILE_SCRIPT_URL,
    () => Boolean(captchaWindow().turnstile),
  ).catch((error: unknown) => {
    turnstileScriptPromise = undefined;
    throw error;
  });
  return turnstileScriptPromise;
}

function loadRecaptcha(siteKey: string): Promise<void> {
  if (recaptchaScript?.siteKey === siteKey && captchaWindow().grecaptcha) {
    return Promise.resolve();
  }
  if (recaptchaScript && recaptchaScript.siteKey !== siteKey) {
    return Promise.reject(new Error("reCAPTCHA site key changed during this page session"));
  }
  if (!recaptchaScript) {
    const source = `${RECAPTCHA_SCRIPT_BASE}?render=${encodeURIComponent(siteKey)}`;
    const promise = loadFixedScript(
      RECAPTCHA_SCRIPT_ID,
      source,
      () => Boolean(captchaWindow().grecaptcha),
    ).catch((error: unknown) => {
      recaptchaScript = undefined;
      throw error;
    });
    recaptchaScript = { siteKey, promise };
  }
  return recaptchaScript.promise;
}

function loadFixedScript(id: string, source: string, ready: () => boolean): Promise<void> {
  const existing = document.getElementById(id);
  if (existing) {
    if (!(existing instanceof HTMLScriptElement) || existing.src !== source) {
      return Promise.reject(new Error("CAPTCHA SDK source mismatch"));
    }
    if (ready()) return Promise.resolve();
    return waitForScript(existing, ready);
  }
  if (ready()) {
    return Promise.reject(new Error("pre-existing CAPTCHA SDK source cannot be verified"));
  }

  const script = document.createElement("script");
  script.id = id;
  script.src = source;
  script.async = true;
  script.defer = true;
  script.referrerPolicy = "no-referrer";
  const loaded = waitForScript(script, ready);
  document.head.append(script);
  return loaded;
}

function waitForScript(script: HTMLScriptElement, ready: () => boolean): Promise<void> {
  if (ready()) return Promise.resolve();
  if (script.dataset.upCaptchaState === "loaded") {
    return Promise.reject(new Error("CAPTCHA SDK loaded without its API"));
  }
  return new Promise<void>((resolve, reject) => {
    const timeout = globalThis.setTimeout(() => {
      cleanup();
      reject(new Error("CAPTCHA SDK load timed out"));
    }, SDK_LOAD_TIMEOUT_MS);
    const cleanup = () => {
      globalThis.clearTimeout(timeout);
      script.removeEventListener("load", onLoad);
      script.removeEventListener("error", onError);
    };
    const onLoad = () => {
      script.dataset.upCaptchaState = "loaded";
      cleanup();
      if (ready()) resolve();
      else reject(new Error("CAPTCHA SDK loaded without its API"));
    };
    const onError = () => {
      script.dataset.upCaptchaState = "failed";
      cleanup();
      script.remove();
      reject(new Error("CAPTCHA SDK failed to load"));
    };
    script.addEventListener("load", onLoad, { once: true });
    script.addEventListener("error", onError, { once: true });
  });
}

function waitForRecaptcha(api: RecaptchaAPI, signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal.aborted) {
      reject(abortReason(signal));
      return;
    }
    const timeout = globalThis.setTimeout(() => {
      cleanup();
      reject(new Error("reCAPTCHA SDK readiness timed out"));
    }, SDK_LOAD_TIMEOUT_MS);
    const cleanup = () => {
      globalThis.clearTimeout(timeout);
      signal.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(abortReason(signal));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    api.ready(() => {
      cleanup();
      if (signal.aborted) reject(abortReason(signal));
      else resolve();
    });
  });
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    if (signal.aborted) {
      reject(abortReason(signal));
      return;
    }
    const onAbort = () => reject(abortReason(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        if (!signal.aborted) resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function captchaWindow(): CaptchaWindow {
  return window as CaptchaWindow;
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new DOMException("Aborted", "AbortError");
}

function asError(value: unknown, fallback: string): Error {
  return value instanceof Error ? value : new Error(fallback);
}
