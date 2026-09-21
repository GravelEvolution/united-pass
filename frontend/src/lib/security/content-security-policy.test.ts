//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-28
// Description: CSP and browser security-header contract tests
//

import { describe, expect, it } from "vitest";
import {
  createContentSecurityPolicy,
  createDocumentSecurityHeaders,
} from "@/lib/security/content-security-policy";
import { ALIYUN_CAPTCHA_INLINE_STYLE_HASHES } from "@/lib/security/aliyun-captcha-config";

function directive(policy: string, name: string): string {
  const value = policy
    .split(";")
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith(`${name} `));
  if (!value) throw new Error(`Missing ${name} directive`);
  return value;
}

describe("document content security policy", () => {
  it("uses a strict nonce policy with only reviewed production origins", () => {
    const policy = createContentSecurityPolicy("fixednonce", "production");
    const script = directive(policy, "script-src");

    expect(policy).not.toMatch(/[\r\n]/u);
    expect(policy).toContain("default-src 'none'");
    expect(script).toContain("'nonce-fixednonce'");
    expect(script).toContain("'strict-dynamic'");
    expect(script).toContain("https://o.alicdn.com");
    expect(script).toContain("https://g.alicdn.com");
    expect(script).toContain("https://x.alicdn.com");
    expect(script).not.toContain("'unsafe-inline'");
    expect(script).not.toContain("'unsafe-eval'");
    expect(directive(policy, "style-src")).toContain("'nonce-fixednonce'");
    expect(directive(policy, "style-src")).not.toContain("'unsafe-inline'");
    const styleElements = directive(policy, "style-src-elem");
    expect(styleElements).not.toContain("'unsafe-inline'");
    expect(styleElements).toContain("'nonce-fixednonce'");
    expect(styleElements).toContain("https://g.alicdn.com");
    for (const hash of ALIYUN_CAPTCHA_INLINE_STYLE_HASHES) {
      expect(styleElements).toContain(`'${hash}'`);
    }
    expect(directive(policy, "script-src-attr")).toBe("script-src-attr 'none'");
    expect(directive(policy, "style-src-attr")).toBe("style-src-attr 'unsafe-inline'");
    const connect = directive(policy, "connect-src");
    expect(connect).toContain("https://captcha-esa-open.aliyuncs.com");
    expect(connect).toContain("https://captcha-esa-open-b.aliyuncs.com");
    expect(connect).toContain("https://esa-rijvhs6c3b.captcha-esa-open.aliyuncs.com");
    expect(connect).toContain("https://esa-rijvhs6c3b.captcha-esa-open-b.aliyuncs.com");
    expect(connect).toContain("https://upload.captcha-esa-open.aliyuncs.com");
    expect(connect).toContain("https://upload.captcha-esa-open-b.aliyuncs.com");
    expect(connect).toContain("https://cloudauth-device-dualstack.cn-shanghai.aliyuncs.com");
    expect(connect).toContain("https://cn-shanghai.device.saf.aliyuncs.com");
    expect(connect).toContain("https://static-captcha.aliyuncs.com");
    expect(connect).not.toContain("https://o.alicdn.com");
    expect(connect).not.toContain("https://g.alicdn.com");
    expect(connect).not.toContain("https://x.alicdn.com");
    expect(connect).not.toMatch(/(?:^|\s)https:(?:\s|$)/u);
    expect(connect).not.toContain("*.");

    const image = directive(policy, "img-src");
    expect(image).toContain("https://moonstone.org.cn");
    expect(image).toContain("https://static-captcha.aliyuncs.com");
    expect(image).not.toMatch(/(?:^|\s)https:(?:\s|$)/u);

    const frame = directive(policy, "frame-src");
    expect(frame).toContain("https://esa-rijvhs6c3b.captcha-esa-open.aliyuncs.com");
    expect(frame).toContain("https://esa-rijvhs6c3b.captcha-esa-open-b.aliyuncs.com");
    expect(frame).not.toContain("cloudauth-device");
    expect(frame).not.toMatch(/(?:^|\s)https:(?:\s|$)/u);
    expect(directive(policy, "worker-src")).toBe("worker-src 'self'");
    expect(directive(policy, "object-src")).toBe("object-src 'none'");
    expect(directive(policy, "base-uri")).toBe("base-uri 'none'");
    expect(directive(policy, "form-action")).toBe("form-action 'self'");
    expect(directive(policy, "frame-ancestors")).toBe("frame-ancestors 'none'");
    expect(policy).toContain("upgrade-insecure-requests");
  });

  it("isolates the React development eval allowance from production", () => {
    const development = createContentSecurityPolicy("devnonce", "development");
    const production = createContentSecurityPolicy("prodnonce", "production");
    const test = createContentSecurityPolicy("testnonce", "test");

    expect(directive(development, "script-src")).toContain("'unsafe-eval'");
    expect(directive(development, "style-src")).toContain("'unsafe-inline'");
    expect(directive(production, "style-src")).not.toContain("'unsafe-inline'");
    expect(directive(production, "style-src-elem")).not.toContain("'unsafe-inline'");
    expect(directive(test, "style-src-elem")).not.toContain("'unsafe-inline'");
    expect(directive(development, "style-src-elem")).toContain("'unsafe-inline'");
    expect(directive(development, "connect-src")).toContain("ws:");
    expect(development).not.toContain("upgrade-insecure-requests");
    expect(directive(production, "script-src")).not.toContain("'unsafe-eval'");
    expect(directive(production, "connect-src")).not.toContain("ws:");
    expect(directive(test, "script-src")).not.toContain("'unsafe-eval'");
  });

  it("adds transport enforcement only to production responses", () => {
    const production = new Map(createDocumentSecurityHeaders("policy", "production"));
    const development = new Map(createDocumentSecurityHeaders("policy", "development"));

    expect(production.get("Content-Security-Policy")).toBe("policy");
    expect(production.get("Cache-Control")).toBe("no-store");
    expect(production.get("Referrer-Policy")).toBe("no-referrer");
    expect(production.get("X-Content-Type-Options")).toBe("nosniff");
    expect(production.get("X-Frame-Options")).toBe("DENY");
    expect(production.get("Strict-Transport-Security")).toBe(
      "max-age=31536000; includeSubDomains",
    );
    expect(development.has("Strict-Transport-Security")).toBe(false);
  });
});
