//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-25
// Description: Aliyun ESA AI captcha (image-restoration) frontend integration
//

"use client";

/**
 * Aliyun ESA AI Captcha (图像复原) client integration.
 *
 * Verification happens at the ESA edge: this module loads the AliyunCaptcha.js
 * SDK, initializes the image-restoration captcha, and — when a caller requests
 * verification — pops the dialog and resolves with the opaque
 * `captchaVerifyParam` to attach to the business request as
 * `captcha_verify_param`. ESA verifies the param before forwarding to origin.
 *
 * Aliyun requires the captcha JS to be loaded and initialized EARLY (前置),
 * with a >2s gap between initialization and the verification request, so that
 * device/environment data can be collected and image assets can be prefetched.
 * Callers must therefore invoke `preloadAliyunCaptcha()` when their page
 * mounts, and call `verifyAliyunCaptcha()` only at the moment verification is
 * needed (e.g. on form submit).
 *
 * The region, identity prefix and scene id are public client-side values, not
 * secrets. The scene type is image restoration (图像复原).
 */

const CAPTCHA_IDENTITY = "esa-rijvhs6c3b";
const CAPTCHA_SCENE_ID = "h5vruly8";
const CAPTCHA_SCRIPT_URL =
  "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js";
const CAPTCHA_SERVERS = [
  "captcha-esa-open.aliyuncs.com",
  "captcha-esa-open-b.aliyuncs.com",
];
const CAPTCHA_ELEMENT_ID = "up-aliyun-captcha-element";
const CAPTCHA_BUTTON_ID = "up-aliyun-captcha-trigger";

type AliyunCaptchaInstance = {
  show: () => void;
  hide: () => void;
  refresh: () => void;
};

type AliyunCaptchaInitOptions = {
  SceneId: string;
  mode: "popup";
  element: string;
  button: string;
  success: (captchaVerifyParam: string) => void;
  fail?: (result: { code?: string }) => void;
  onClose?: () => void;
  getInstance: (instance: AliyunCaptchaInstance) => void;
  server: string[];
};

declare global {
  interface Window {
    AliyunCaptchaConfig?: { region: string; prefix: string };
    initAliyunCaptcha?: (options: AliyunCaptchaInitOptions) => void;
  }
}

let scriptPromise: Promise<void> | null = null;
let instancePromise: Promise<AliyunCaptchaInstance> | null = null;
let pendingResolve: ((param: string) => void) | null = null;
let pendingReject: ((error: Error) => void) | null = null;

function loadScript(): Promise<void> {
  if (scriptPromise) return scriptPromise;
  scriptPromise = new Promise<void>((resolve, reject) => {
    // The identity/prefix must be set before the SDK script executes.
    window.AliyunCaptchaConfig = { region: "cn", prefix: CAPTCHA_IDENTITY };

    const existing = document.querySelector(`script[src="${CAPTCHA_SCRIPT_URL}"]`);
    if (existing) {
      resolve();
      return;
    }

    const script = document.createElement("script");
    script.type = "text/javascript";
    script.src = CAPTCHA_SCRIPT_URL;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => {
      scriptPromise = null;
      reject(new Error("人机验证组件加载失败，请检查网络后重试。"));
    };
    document.head.appendChild(script);
  });
  return scriptPromise;
}

function ensureHostElements(): void {
  // The reserved element the SDK mounts the popup into. It must be a plain,
  // visible (empty) div — hiding it with display:none can suppress the popup.
  if (!document.getElementById(CAPTCHA_ELEMENT_ID)) {
    const element = document.createElement("div");
    element.id = CAPTCHA_ELEMENT_ID;
    document.body.appendChild(element);
  }

  // A hidden trigger button. We never click it — verification is opened via
  // instance.show() — but the SDK requires the `button` option to reference an
  // element in the DOM.
  if (!document.getElementById(CAPTCHA_BUTTON_ID)) {
    const button = document.createElement("button");
    button.id = CAPTCHA_BUTTON_ID;
    button.type = "button";
    button.style.display = "none";
    document.body.appendChild(button);
  }
}

function initInstance(): Promise<AliyunCaptchaInstance> {
  if (instancePromise) return instancePromise;
  instancePromise = loadScript()
    .then(
      () =>
        new Promise<AliyunCaptchaInstance>((resolve, reject) => {
          if (typeof window.initAliyunCaptcha !== "function") {
            reject(new Error("人机验证组件不可用，请刷新页面后重试。"));
            return;
          }

          ensureHostElements();

          window.initAliyunCaptcha({
            SceneId: CAPTCHA_SCENE_ID,
            mode: "popup",
            element: `#${CAPTCHA_ELEMENT_ID}`,
            button: `#${CAPTCHA_BUTTON_ID}`,
            success: (captchaVerifyParam) => {
              const done = pendingResolve;
              pendingResolve = null;
              pendingReject = null;
              done?.(captchaVerifyParam);
            },
            fail: () => {
              const done = pendingReject;
              pendingResolve = null;
              pendingReject = null;
              done?.(new Error("人机验证未通过，请重试。"));
            },
            onClose: () => {
              const done = pendingReject;
              pendingResolve = null;
              pendingReject = null;
              done?.(new Error("人机验证已取消。"));
            },
            getInstance: (instance) => resolve(instance),
            server: CAPTCHA_SERVERS,
          });
        }),
    )
    .catch((error) => {
      // Allow a later attempt to re-initialize after a transient failure.
      instancePromise = null;
      throw error;
    });
  return instancePromise;
}

/**
 * Loads and initializes the captcha SDK without popping the dialog. Call this
 * when the page mounts so the >2s init→verify gap is satisfied before the user
 * can submit. Safe to call multiple times — it is a singleton and swallows its
 * own errors (the real error surfaces later from verifyAliyunCaptcha()).
 */
export async function preloadAliyunCaptcha(): Promise<void> {
  try {
    await initInstance();
  } catch {
    // Ignore: verifyAliyunCaptcha() reports the failure to the caller.
  }
}

/**
 * Pops the Aliyun image-restoration captcha and resolves with the opaque
 * verify parameter to attach to the business request. Rejects when the user
 * cancels, the verification fails, or the SDK could not be initialized.
 */
export async function verifyAliyunCaptcha(): Promise<string> {
  const instance = await initInstance();
  return new Promise<string>((resolve, reject) => {
    pendingResolve = resolve;
    pendingReject = reject;
    instance.show();
  });
}
