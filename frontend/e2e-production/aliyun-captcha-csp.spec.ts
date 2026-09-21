//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-28
// Description: Real Aliyun CAPTCHA execution under the production document CSP
//

import { expect, test } from "@playwright/test";
import { ALIYUN_CAPTCHA_INLINE_STYLE_HASHES } from "../src/lib/security/aliyun-captcha-config";

type CspViolation = {
  blockedUri: string;
  effectiveDirective: string;
  sourceFile: string;
};

const CAPTCHA_PRIMARY_IDENTITY_ORIGIN =
  "https://esa-rijvhs6c3b.captcha-esa-open.aliyuncs.com";
const CAPTCHA_BACKUP_IDENTITY_ORIGIN =
  "https://esa-rijvhs6c3b.captcha-esa-open-b.aliyuncs.com";
const CAPTCHA_DEVICE_ORIGIN =
  "https://cloudauth-device-dualstack.cn-shanghai.aliyuncs.com";
const CAPTCHA_RESOURCE_ORIGIN = "https://g.alicdn.com";
const CAPTCHA_STATIC_ORIGIN = "https://static-captcha.aliyuncs.com";
const CAPTCHA_UPLOAD_ORIGIN = "https://upload.captcha-esa-open.aliyuncs.com";

type VendorSignal = "challenge-image" | "device" | "identity" | "stylesheet" | "upload";

const ALIYUN_CAPTCHA_RETAINED_INLINE_STYLE_COUNT = 4;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

test("dotted administration identifiers remain behind the production gate", async ({ request }) => {
  const response = await request.get("/admin/applications/client.example", {
    headers: { Accept: "text/html" },
    maxRedirects: 0,
  });

  expect(response.status()).toBe(307);
  expect(new URL(response.headers().location, "http://localhost").pathname).toBe("/login");
  expect(response.headers()["content-security-policy"]).toContain("script-src 'self' 'nonce-");
});

test("dotted HTML 404 responses retain the document policy", async ({ request }) => {
  const response = await request.get("/missing/document.v2", {
    headers: { Accept: "text/html,application/xhtml+xml" },
    maxRedirects: 0,
  });

  expect(response.status()).toBe(404);
  expect(response.headers()["content-security-policy"]).toContain("script-src 'self' 'nonce-");
  expect(response.headers()["cache-control"]).toContain("no-store");
});

test("caller-controlled Accept cannot remove CSP from an HTML document", async ({ request }) => {
  const response = await request.get("/login", {
    headers: { Accept: "application/json" },
    maxRedirects: 0,
  });

  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("text/html");
  expect(response.headers()["content-security-policy"]).toContain("script-src 'self' 'nonce-");
  expect(response.headers()["cache-control"]).toContain("no-store");
});

test("reviewed public assets remain outside the document policy", async ({ request }) => {
  const response = await request.get("/brand/gravel-evolution-logo.png", {
    headers: { Accept: "text/html" },
    maxRedirects: 0,
  });

  expect(response.status()).toBe(200);
  expect(response.headers()["content-type"]).toContain("image/png");
  expect(response.headers()["content-security-policy"]).toBeUndefined();
  expect(response.headers()["cache-control"]).not.toContain("no-store");
});

test("asset-lookalike HTML 404s retain the document policy", async ({ request }) => {
  for (const path of ["/_next/staticity/not-found", "/brand/missing.v2"]) {
    const response = await request.get(path, {
      headers: { Accept: "application/json" },
      maxRedirects: 0,
    });

    expect(response.status()).toBe(404);
    expect(response.headers()["content-type"]).toContain("text/html");
    expect(response.headers()["content-security-policy"]).toContain("script-src 'self' 'nonce-");
    expect(response.headers()["cache-control"]).toContain("no-store");
  }
});

test("real Aliyun CAPTCHA renders its challenge under the production CSP", async ({ page }) => {
  const successfulVendorSignals = new Set<VendorSignal>();
  const cspRequestFailures: string[] = [];
  const cspConsoleErrors: string[] = [];
  const businessLoginRequests: string[] = [];

  page.on("response", async (response) => {
    const url = new URL(response.url());
    if (!response.ok()) return;

    if (url.origin === CAPTCHA_RESOURCE_ORIGIN
      && response.request().resourceType() === "stylesheet"
      && url.pathname.endsWith("/main.css")) {
      successfulVendorSignals.add("stylesheet");
    }
    if (url.origin === CAPTCHA_DEVICE_ORIGIN) {
      successfulVendorSignals.add("device");
    }
    if (url.origin === CAPTCHA_STATIC_ORIGIN) {
      successfulVendorSignals.add("challenge-image");
    }
    if (url.origin === CAPTCHA_UPLOAD_ORIGIN) {
      successfulVendorSignals.add("upload");
    }
    if (url.origin === CAPTCHA_PRIMARY_IDENTITY_ORIGIN
      || url.origin === CAPTCHA_BACKUP_IDENTITY_ORIGIN) {
      try {
        const payload: unknown = await response.json();
        if (isRecord(payload)
          && payload.Success === true
          && payload.Code === "Success"
          && payload.CaptchaType === "INPAINTING") {
          successfulVendorSignals.add("identity");
        }
      } catch {
        // The signal remains absent and the bounded poll below fails closed.
      }
    }
  });
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (request.method() === "POST" && url.pathname === "/api/v1/auth/login") {
      businessLoginRequests.push(url.pathname);
    }
  });
  page.on("requestfailed", (request) => {
    if (request.failure()?.errorText.toLowerCase().includes("csp")) {
      cspRequestFailures.push(`${request.resourceType()} ${request.url()}`);
    }
  });
  page.on("console", (message) => {
    if (message.type() === "error" && /content security policy|violates the following/iu.test(message.text())) {
      cspConsoleErrors.push(message.text());
    }
  });
  await page.addInitScript(() => {
    const browserState = globalThis as typeof globalThis & {
      __upCspViolations?: CspViolation[];
    };
    browserState.__upCspViolations = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      browserState.__upCspViolations?.push({
        blockedUri: event.blockedURI,
        effectiveDirective: event.effectiveDirective,
        sourceFile: event.sourceFile,
      });
    });
  });

  const documentResponse = await page.goto("/login", { waitUntil: "domcontentloaded" });
  expect(documentResponse?.status()).toBe(200);
  const policy = await documentResponse?.headerValue("content-security-policy");
  expect(policy).toContain("script-src 'self' 'nonce-");
  expect(policy).toContain("'strict-dynamic'");
  expect(policy).not.toContain("'unsafe-eval'");
  expect(policy?.match(/script-src [^;]+/u)?.[0]).not.toContain("'unsafe-inline'");
  expect(policy?.match(/style-src-attr [^;]+/u)?.[0]).toContain("'unsafe-inline'");
  const styleElementPolicy = policy?.match(/style-src-elem [^;]+/u)?.[0] ?? "";
  expect(styleElementPolicy).not.toContain("'unsafe-inline'");
  for (const hash of ALIYUN_CAPTCHA_INLINE_STYLE_HASHES) {
    expect(styleElementPolicy).toContain(`'${hash}'`);
  }

  // Next/Image uses a style attribute for fill layout. This representative
  // application-owned attribute must remain applied under the narrowly scoped
  // style-src-attr compatibility rule; style elements and scripts stay strict.
  const carouselImage = page.locator('img[src*="auth-carousel-1.jpg"]');
  await expect(carouselImage).toHaveAttribute("style", /position:\s*absolute/u);
  await expect.poll(
    () => carouselImage.evaluate((element) => getComputedStyle(element).position),
  ).toBe("absolute");

  await expect.poll(
    () => page.evaluate(() => typeof (window as Window & { initAliyunCaptcha?: unknown }).initAliyunCaptcha),
    { timeout: 20_000 },
  ).toBe("function");

  await page.locator('input[name="identifier"]').fill("csp-browser-audit");
  await page.locator('input[name="password"]').fill("Not-Submitted-CSP-Audit9!");
  await page.getByRole("button", { name: "登录", exact: true }).click();

  await expect(page.locator("#aliyunCaptcha-window-popup.window-show")).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.locator("#aliyunCaptcha-img-box")).toBeVisible();
  await expect.poll(
    () => [...successfulVendorSignals].sort(),
    { timeout: 20_000 },
  ).toEqual(["challenge-image", "device", "identity", "stylesheet", "upload"]);

  // The vendor inserts nonce-less style elements. Their visible, violation-free
  // popup proves that the exact hash sources — not unsafe-inline — authorized
  // the reviewed runtime CSS.
  await expect(page.locator("style:not([nonce])")).toHaveCount(
    ALIYUN_CAPTCHA_RETAINED_INLINE_STYLE_COUNT,
  );

  await page.waitForTimeout(1_000);
  const violations = await page.evaluate(() => (
    globalThis as typeof globalThis & { __upCspViolations?: CspViolation[] }
  ).__upCspViolations ?? []);
  expect(violations).toEqual([]);
  expect(cspRequestFailures).toEqual([]);
  expect(cspConsoleErrors).toEqual([]);
  expect(businessLoginRequests).toEqual([]);
});
