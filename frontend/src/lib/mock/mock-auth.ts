//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Mock authentication state helpers for the frozen frontend
//

export type MockLoginDestination = "/account" | "/admin";

type MockLoginAccount = {
  username: string;
  email: string;
  password: string;
  destination: MockLoginDestination;
};

// Public demo credentials only. These values are not secrets and must never be
// reused as production authentication configuration.
export const MOCK_LOGIN_ACCOUNTS = {
  externalUser: {
    username: "app.user",
    email: "app.user@example.com",
    password: "MockUser123!",
    destination: "/account",
  },
  employeeAdmin: {
    username: "zhixing.lin",
    email: "zhixing.lin@example.com",
    password: "MockAdmin123!",
    destination: "/admin",
  },
} satisfies Record<string, MockLoginAccount>;

export function authenticateMockAccount(
  identifier: string,
  password: string,
): MockLoginDestination | undefined {
  const normalizedIdentifier = identifier.trim().toLocaleLowerCase("en-US");

  return Object.values(MOCK_LOGIN_ACCOUNTS).find((mockAccount) => {
    const matchesIdentifier =
      mockAccount.username.toLocaleLowerCase("en-US") === normalizedIdentifier ||
      mockAccount.email.toLocaleLowerCase("en-US") === normalizedIdentifier;

    return matchesIdentifier && mockAccount.password === password;
  })?.destination;
}
