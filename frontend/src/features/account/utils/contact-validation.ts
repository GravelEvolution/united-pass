//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Email and phone contact validation utilities
//

export type ContactKind = "email" | "phone";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_PATTERN = /^\+[1-9]\d{7,14}$/;

export function validateContactValue(kind: ContactKind, value: string): string | undefined {
  if (!value) return kind === "email" ? "请输入新邮箱地址。" : "请输入新手机号码。";
  if (kind === "email" && !EMAIL_PATTERN.test(value)) return "请输入有效的邮箱地址。";
  if (kind === "phone" && !PHONE_PATTERN.test(value)) return "请输入含国家代码的手机号码，例如 +8613800138000。";
  return undefined;
}
