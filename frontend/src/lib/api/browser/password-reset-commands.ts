"use client";

import { browserFetch } from "@/lib/api/browser/browser-http-client";

export type PasswordResetRequestInput = {
  identifier: string;
};

export async function requestPasswordReset(input: PasswordResetRequestInput): Promise<void> {
  await browserFetch<unknown>("/auth/password-reset", {
    method: "POST",
    body: { identifier: input.identifier },
  });
}

export type PasswordResetConfirmInput = {
  token: string;
  newPassword: string;
};

export async function confirmPasswordReset(input: PasswordResetConfirmInput): Promise<void> {
  await browserFetch<unknown>("/auth/password-reset/confirm", {
    method: "POST",
    body: { token: input.token, newPassword: input.newPassword },
  });
}
