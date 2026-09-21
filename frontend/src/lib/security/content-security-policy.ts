//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-28
// Description: Per-request CSP and browser security-header contract
//

import {
  ALIYUN_CAPTCHA_CONNECT_ORIGINS,
  ALIYUN_CAPTCHA_FRAME_ORIGINS,
  ALIYUN_CAPTCHA_IMAGE_ORIGINS,
  ALIYUN_CAPTCHA_INLINE_STYLE_HASHES,
  ALIYUN_CAPTCHA_RESOURCE_ORIGINS,
} from "@/lib/security/aliyun-captcha-config";

export type ApplicationEnvironment = "development" | "production" | "test";

const MOONSTONE_IMAGE_ORIGINS = [
  "https://moonstone.org.cn",
  "https://www.moonstone.org.cn",
];

/**
 * Builds the document policy consumed by Next.js to nonce its framework,
 * application, and inline bootstrap scripts. Keep third-party sources exact:
 * adding a provider here is a security-boundary change, not ordinary config.
 */
export function createContentSecurityPolicy(
  nonce: string,
  environment: ApplicationEnvironment,
): string {
  const captchaConnectSources = ALIYUN_CAPTCHA_CONNECT_ORIGINS.join(" ");
  const captchaFrameSources = ALIYUN_CAPTCHA_FRAME_ORIGINS.join(" ");
  const captchaImageSources = ALIYUN_CAPTCHA_IMAGE_ORIGINS.join(" ");
  const captchaResourceSources = ALIYUN_CAPTCHA_RESOURCE_ORIGINS.join(" ");
  const captchaInlineStyleSources = ALIYUN_CAPTCHA_INLINE_STYLE_HASHES
    .map((hash) => `'${hash}'`)
    .join(" ");
  const scriptSources = [
    "'self'",
    `'nonce-${nonce}'`,
    "'strict-dynamic'",
    // CSP2 fallback. CSP3 browsers ignore host allowlists under strict-dynamic.
    ...ALIYUN_CAPTCHA_RESOURCE_ORIGINS,
    ...(environment === "development" ? ["'unsafe-eval'"] : []),
  ].join(" ");
  const styleSources = environment === "development"
    ? `'self' 'unsafe-inline' ${captchaResourceSources}`
    : `'self' 'nonce-${nonce}' ${captchaResourceSources}`;
  // Production pins the exact inline <style> blocks emitted by the reviewed
  // vendor SDK. Development keeps inline styles for React/Next diagnostics.
  const styleElementSources = environment === "development"
    ? `'self' 'unsafe-inline' ${captchaResourceSources}`
    : `'self' 'nonce-${nonce}' ${captchaInlineStyleSources} ${captchaResourceSources}`;
  const connectSources = [
    "'self'",
    captchaConnectSources,
    ...(environment === "development" ? ["ws:", "wss:"] : []),
  ].join(" ");

  const directives = [
    "default-src 'none'",
    `script-src ${scriptSources}`,
    "script-src-attr 'none'",
    `style-src ${styleSources}`,
    `style-src-elem ${styleElementSources}`,
    // React/Semi components use style attributes. This does not permit script.
    "style-src-attr 'unsafe-inline'",
    `img-src 'self' data: blob: ${MOONSTONE_IMAGE_ORIGINS.join(" ")} ${captchaImageSources}`,
    "font-src 'self' data:",
    `connect-src ${connectSources}`,
    `frame-src ${captchaFrameSources}`,
    "worker-src 'self'",
    "manifest-src 'self'",
    "media-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(environment === "production" ? ["upgrade-insecure-requests"] : []),
  ];

  return `${directives.join("; ")};`;
}

/**
 * Returns headers for nonce-bearing HTML responses. no-store prevents a shared
 * cache from replaying a document and its one-time nonce to another request.
 */
export function createDocumentSecurityHeaders(
  contentSecurityPolicy: string,
  environment: ApplicationEnvironment,
): ReadonlyArray<readonly [string, string]> {
  return [
    ["Content-Security-Policy", contentSecurityPolicy],
    ["Cache-Control", "no-store"],
    ["Referrer-Policy", "no-referrer"],
    ["X-Content-Type-Options", "nosniff"],
    ["X-Frame-Options", "DENY"],
    ["X-DNS-Prefetch-Control", "off"],
    ["X-Permitted-Cross-Domain-Policies", "none"],
    ["Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()"],
    ...(environment === "production"
      ? [["Strict-Transport-Security", "max-age=31536000; includeSubDomains"] as const]
      : []),
  ];
}
