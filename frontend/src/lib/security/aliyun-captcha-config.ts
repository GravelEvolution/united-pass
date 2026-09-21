//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-28
// Description: Public Aliyun CAPTCHA endpoints shared by the client and CSP
//

export const ALIYUN_CAPTCHA_SCRIPT_URL =
  "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js";

export const ALIYUN_CAPTCHA_SCRIPT_ORIGIN = new URL(ALIYUN_CAPTCHA_SCRIPT_URL).origin;

export const ALIYUN_CAPTCHA_IDENTITY = "esa-rijvhs6c3b";

/**
 * Exact resource hosts used by the vendor loader. The primary loader delegates
 * trusted scripts to g.alicdn.com; x.alicdn.com is the documented failover
 * resource host. Do not replace these entries with an alicdn wildcard.
 */
export const ALIYUN_CAPTCHA_RESOURCE_ORIGINS = [
  ALIYUN_CAPTCHA_SCRIPT_ORIGIN,
  "https://g.alicdn.com",
  "https://x.alicdn.com",
] as const;

/**
 * SHA-256 sources for the reviewed Aliyun CAPTCHA loader's empty style-loader
 * bootstrap plus four stable retained style blocks. Pinning their exact
 * contents keeps the document policy free of style-element `unsafe-inline`;
 * a vendor style change therefore fails closed until the browser contract is
 * reviewed.
 */
export const ALIYUN_CAPTCHA_INLINE_STYLE_HASHES = [
  // style-loader appends three empty elements before populating them.
  "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
  "sha256-LMCUvnQYNGxDHtBMl0ntaFxBjVW0KdEojkQXGGBRbpY=",
  "sha256-usJkg0sP1W3kE1rpOnYFVm3rtY9i0oarXsKbLGE1Bq4=",
  "sha256-F8gG9t55ebrNBJONpiI1fdUusT/ksVKF2dUtyzhY4eg=",
  "sha256-ANf/oPwNbjbOFZI0hk8OYW3ZWU8lw/w3KMkdtq5T7qo=",
] as const;

export const ALIYUN_CAPTCHA_SERVER_HOSTS = [
  "captcha-esa-open.aliyuncs.com",
  "captcha-esa-open-b.aliyuncs.com",
] as const;

export const ALIYUN_CAPTCHA_SERVICE_ORIGINS: readonly string[] =
  ALIYUN_CAPTCHA_SERVER_HOSTS.map((hostname) => `https://${hostname}`);

export const ALIYUN_CAPTCHA_IDENTITY_ORIGINS: readonly string[] =
  ALIYUN_CAPTCHA_SERVER_HOSTS.map(
    (hostname) => `https://${ALIYUN_CAPTCHA_IDENTITY}.${hostname}`,
  );

export const ALIYUN_CAPTCHA_UPLOAD_ORIGINS: readonly string[] =
  ALIYUN_CAPTCHA_SERVER_HOSTS.map((hostname) => `https://upload.${hostname}`);

export const ALIYUN_CAPTCHA_DEVICE_ORIGINS = [
  "https://cloudauth-device-dualstack.cn-shanghai.aliyuncs.com",
  "https://cn-shanghai.device.saf.aliyuncs.com",
] as const;

export const ALIYUN_CAPTCHA_STATIC_IMAGE_ORIGIN =
  "https://static-captcha.aliyuncs.com";

/** All exact origins observed or documented for the mainland ESA flow. */
export const ALIYUN_CAPTCHA_CONNECT_ORIGINS: readonly string[] = [
  ...ALIYUN_CAPTCHA_DEVICE_ORIGINS,
  ...ALIYUN_CAPTCHA_SERVICE_ORIGINS,
  ...ALIYUN_CAPTCHA_IDENTITY_ORIGINS,
  ...ALIYUN_CAPTCHA_UPLOAD_ORIGINS,
  ALIYUN_CAPTCHA_STATIC_IMAGE_ORIGIN,
];

export const ALIYUN_CAPTCHA_IMAGE_ORIGINS: readonly string[] = [
  ...ALIYUN_CAPTCHA_RESOURCE_ORIGINS,
  ...ALIYUN_CAPTCHA_SERVICE_ORIGINS,
  ...ALIYUN_CAPTCHA_IDENTITY_ORIGINS,
  ...ALIYUN_CAPTCHA_UPLOAD_ORIGINS,
  ALIYUN_CAPTCHA_STATIC_IMAGE_ORIGIN,
];

export const ALIYUN_CAPTCHA_FRAME_ORIGINS: readonly string[] = [
  ...ALIYUN_CAPTCHA_SERVICE_ORIGINS,
  ...ALIYUN_CAPTCHA_IDENTITY_ORIGINS,
];
