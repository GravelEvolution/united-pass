//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Description: Contact verification-code input rules shared by account UI tests
//

import type { ContactKind } from "./contact-validation";

const EMAIL_CODE_PATTERN = /^[A-Z0-9]{6}$/u;
const PHONE_CODE_PATTERN = /^[0-9]{6}$/u;

/**
 * Removes paste separators and caps length without changing letter case.
 * ZITADEL email codes are case-sensitive, so the exact typed casing must reach
 * the backend unchanged.
 */
export function normalizeContactVerificationCode(kind: ContactKind, value: string): string {
  const allowedCharacters = kind === "email" ? /[^A-Za-z0-9]/gu : /[^0-9]/gu;
  return value.replace(allowedCharacters, "").slice(0, 6);
}

export function getContactVerificationCodeError(
  kind: ContactKind,
  value: string,
): string | undefined {
  if (kind === "email") {
    return EMAIL_CODE_PATTERN.test(value)
      ? undefined
      : "请输入邮件中的 6 位大写字母或数字验证码，并保持原有大小写。";
  }

  return PHONE_CODE_PATTERN.test(value)
    ? undefined
    : "请输入短信中的 6 位数字验证码。";
}
