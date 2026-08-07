//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-04
// Description: Authorization feature contract types
//

export type ConsentScope = {
  scope: string;
  label: string;
  description: string;
};

export type ConsentRequest = {
  requestId: string;
  applicationName: string;
  applicationDescription: string;
  applicationOwner: string;
  redirectHost: string;
  scopes: ConsentScope[];
};

export type ConsentResolution =
  | { status: "valid"; request: ConsentRequest }
  | { status: "expired"; requestId: string; expiredAt: string }
  | { status: "client_not_found"; requestId: string }
  | { status: "redirect_mismatch"; requestId: string; attemptedRedirect: string }
  | { status: "unauthenticated"; requestId: string }
  | { status: "scope_not_allowed"; requestId: string; disallowedScopes: string[] }
  | { status: "already_authorized"; requestId: string; applicationName: string; redirectHost: string };

export type ConsentDecision = "allow" | "deny";
