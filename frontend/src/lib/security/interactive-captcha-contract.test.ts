import { afterEach, describe, expect, it, vi } from "vitest";
import {
  FIRST_PARTY_IMAGE_PROVIDER,
  parseInteractiveCaptchaDescriptor,
  RECAPTCHA_PROVIDER,
  TURNSTILE_PROVIDER,
} from "./interactive-captcha-contract";
import { officialInteractiveCaptchaAdapter } from "./official-interactive-captcha-adapter";

class FakeScriptElement {
  src = "";
  dataset: Record<string, string> = { upCaptchaState: "loaded" };
}

class FakeInteractiveElement {
  readonly style: Record<string, string> = {};
  readonly attributes: Record<string, string> = {};
  readonly children: FakeInteractiveElement[] = [];
  readonly listeners = new Map<string, (event: Event) => void>();
  src = "";
  alt = "";
  draggable = false;
  textContent = "";
  type = "";
  inputMode = "";
  autocomplete = "";
  maxLength = 0;
  required = false;
  value = "";
  validationMessage = "";
  focused = false;

  constructor(readonly tagName: string) {}

  setAttribute(name: string, value: string): void {
    this.attributes[name] = value;
  }

  append(...nodes: FakeInteractiveElement[]): void {
    this.children.push(...nodes);
  }

  replaceChildren(...nodes: FakeInteractiveElement[]): void {
    this.children.splice(0, this.children.length, ...nodes);
  }

  addEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
    if (typeof listener === "function") this.listeners.set(type, listener);
  }

  removeEventListener(type: string): void {
    this.listeners.delete(type);
  }

  setCustomValidity(message: string): void {
    this.validationMessage = message;
  }

  reportValidity(): boolean {
    return this.validationMessage === "";
  }

  focus(): void {
    this.focused = true;
  }

  dispatch(type: string): void {
    this.listeners.get(type)?.({ preventDefault() {} } as Event);
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("interactive CAPTCHA public contract", () => {
  it("accepts only the exact Turnstile payload", () => {
    expect(parseInteractiveCaptchaDescriptor(TURNSTILE_PROVIDER, {
      siteKey: "public-site-key",
      action: "united_pass_login_A1-b2",
      cdata: "server_nonce-1",
    })).toEqual({
      provider: TURNSTILE_PROVIDER,
      siteKey: "public-site-key",
      action: "united_pass_login_A1-b2",
      cdata: "server_nonce-1",
    });
    expect(parseInteractiveCaptchaDescriptor(TURNSTILE_PROVIDER, {
      siteKey: "public-site-key",
      action: "login",
      cdata: "nonce",
      scriptUrl: "https://evil.example/sdk.js",
    })).toBeUndefined();
  });

  it("accepts only a bounded reCAPTCHA action and public site key", () => {
    expect(parseInteractiveCaptchaDescriptor(RECAPTCHA_PROVIDER, {
      siteKey: "public-site-key",
      action: "united_pass_register_A1-b2",
    })).toBeDefined();
    expect(parseInteractiveCaptchaDescriptor(RECAPTCHA_PROVIDER, {
      siteKey: "public-site-key",
      action: "spaces are rejected",
    })).toBeUndefined();
  });

  it("accepts only a bounded inline PNG payload for the first-party provider", () => {
    const imageDataUrl = "data:image/png;base64,iVBORw0KGgo=";
    expect(parseInteractiveCaptchaDescriptor(FIRST_PARTY_IMAGE_PROVIDER, {
      imageDataUrl,
      digits: 5,
    })).toEqual({ provider: FIRST_PARTY_IMAGE_PROVIDER, imageDataUrl, digits: 5 });
    expect(parseInteractiveCaptchaDescriptor(FIRST_PARTY_IMAGE_PROVIDER, {
      imageDataUrl,
      digits: 5,
      answer: "12345",
    })).toBeUndefined();
    expect(parseInteractiveCaptchaDescriptor(FIRST_PARTY_IMAGE_PROVIDER, {
      imageDataUrl: "data:image/svg+xml;base64,PHN2Zy8+",
      digits: 5,
    })).toBeUndefined();
  });

  it("renders the first-party image and returns only the entered digit proof", async () => {
    const created: FakeInteractiveElement[] = [];
    vi.stubGlobal("document", {
      createElement: (tagName: string) => {
        const element = new FakeInteractiveElement(tagName);
        created.push(element);
        return element;
      },
    });
    const container = new FakeInteractiveElement("div");
    const execution = officialInteractiveCaptchaAdapter.execute({
      provider: FIRST_PARTY_IMAGE_PROVIDER,
      providerPayload: {
        imageDataUrl: "data:image/png;base64,iVBORw0KGgo=",
        digits: 5,
      },
      container: container as unknown as HTMLElement,
      signal: new AbortController().signal,
    });

    const form = created.find((element) => element.tagName === "form");
    const image = created.find((element) => element.tagName === "img");
    const proofInput = created.find((element) => element.tagName === "input");
    expect(form).toBeDefined();
    expect(image?.src).toBe("data:image/png;base64,iVBORw0KGgo=");
    expect(container.children).toEqual([form]);
    if (!form || !proofInput) throw new Error("first-party CAPTCHA controls were not rendered");

    proofInput.value = "１ ２ ３ ４ ５";
    form.dispatch("submit");

    await expect(execution).resolves.toBe("１ ２ ３ ４ ５");
  });

  it("fails closed for a browser-selected or unknown provider", async () => {
    await expect(officialInteractiveCaptchaAdapter.execute({
      provider: "arbitrary-provider",
      providerPayload: { siteKey: "x", action: "login" },
      container: {} as HTMLElement,
      signal: new AbortController().signal,
    })).rejects.toThrow("unsupported");
  });

  it("passes only the bound Turnstile fields to the fixed-source SDK", async () => {
    const script = new FakeScriptElement();
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    let rendered: Record<string, unknown> | undefined;
    const remove = vi.fn();
    vi.stubGlobal("HTMLScriptElement", FakeScriptElement);
    vi.stubGlobal("document", { getElementById: () => script });
    vi.stubGlobal("window", {
      turnstile: {
        render: (_container: HTMLElement, options: Record<string, unknown>) => {
          rendered = options;
          (options.callback as (proof: string) => void)("turnstile-proof");
          return "widget-1";
        },
        remove,
      },
    });

    await expect(officialInteractiveCaptchaAdapter.execute({
      provider: TURNSTILE_PROVIDER,
      providerPayload: {
        siteKey: "public-site-key",
        action: "united_pass_login_A1-b2",
        cdata: "server_nonce-1",
      },
      container: {} as HTMLElement,
      signal: new AbortController().signal,
    })).resolves.toBe("turnstile-proof");

    expect(rendered).toMatchObject({
      sitekey: "public-site-key",
      action: "united_pass_login_A1-b2",
      cData: "server_nonce-1",
      size: "flexible",
      "response-field": false,
    });
    expect(remove).toHaveBeenCalledWith("widget-1");
  });

  it("executes reCAPTCHA only with the server-issued site key and action", async () => {
    const script = new FakeScriptElement();
    script.src = "https://www.recaptcha.net/recaptcha/api.js?render=public-site-key";
    const execute = vi.fn(async () => "recaptcha-proof");
    vi.stubGlobal("HTMLScriptElement", FakeScriptElement);
    vi.stubGlobal("document", { getElementById: () => script });
    vi.stubGlobal("window", {
      grecaptcha: {
        ready: (callback: () => void) => callback(),
        execute,
      },
    });

    await expect(officialInteractiveCaptchaAdapter.execute({
      provider: RECAPTCHA_PROVIDER,
      providerPayload: {
        siteKey: "public-site-key",
        action: "united_pass_register_A1-b2",
      },
      container: {} as HTMLElement,
      signal: new AbortController().signal,
    })).resolves.toBe("recaptcha-proof");
    expect(execute).toHaveBeenCalledWith("public-site-key", {
      action: "united_pass_register_A1-b2",
    });
  });
});
