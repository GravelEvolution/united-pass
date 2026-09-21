//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-09-03
// Description: Authorization page read concurrency regression tests
//

import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ConsentResolution } from "@/features/authorization/types";
import type { CurrentUser } from "@/types/identity";

const queryMocks = vi.hoisted(() => ({
  getConsentResolution: vi.fn(),
  getCurrentUser: vi.fn(),
}));

vi.mock("@/lib/api/server/server-queries", () => ({
  serverQueries: queryMocks,
}));

vi.mock("@/features/authorization/components/authorization-consent", () => ({
  AuthorizationConsent: () => null,
  MissingRequestIdCard: () => null,
}));

import AuthorizePage from "./(auth)/authorize/page";

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
};

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

const validResolution: ConsentResolution = {
  status: "valid",
  request: {
    requestId: "request_valid",
    applicationName: "Test application",
    applicationDescription: "",
    applicationOwner: "Test owner",
    redirectHost: "client.example",
    scopes: [],
  },
};

const currentUser: CurrentUser = {
  userId: "user_1",
  displayName: "Test user",
  email: "user@example.com",
  phoneMasked: "",
  personas: ["consumer"],
};

afterEach(() => {
  queryMocks.getConsentResolution.mockReset();
  queryMocks.getCurrentUser.mockReset();
});

describe("AuthorizePage", () => {
  it("starts consent resolution and /me concurrently for a valid request", async () => {
    const resolution = deferred<ConsentResolution>();
    const user = deferred<CurrentUser>();
    queryMocks.getConsentResolution.mockReturnValue(resolution.promise);
    queryMocks.getCurrentUser.mockReturnValue(user.promise);

    let pageSettled = false;
    const pagePromise = AuthorizePage({
      searchParams: Promise.resolve({ requestId: "request_valid" }),
    }).then((page) => {
      pageSettled = true;
      return page;
    });

    await Promise.resolve();
    await Promise.resolve();
    expect(queryMocks.getConsentResolution).toHaveBeenCalledWith("request_valid");
    expect(queryMocks.getCurrentUser).toHaveBeenCalledTimes(1);

    resolution.resolve(validResolution);
    await Promise.resolve();
    expect(pageSettled).toBe(false);

    user.resolve(currentUser);
    const page = await pagePromise as ReactElement<{
      currentUser: CurrentUser;
      resolution: ConsentResolution;
    }>;
    expect(page.props.currentUser).toBe(currentUser);
    expect(page.props.resolution).toBe(validResolution);
  });

  it("keeps a terminal resolution authoritative when /me rejects", async () => {
    const resolution = deferred<ConsentResolution>();
    const user = deferred<CurrentUser>();
    const terminalResolution: ConsentResolution = {
      status: "expired",
      requestId: "request_expired",
      expiredAt: "2026-09-03T00:00:00Z",
    };
    queryMocks.getConsentResolution.mockReturnValue(resolution.promise);
    queryMocks.getCurrentUser.mockReturnValue(user.promise);

    const pagePromise = AuthorizePage({
      searchParams: Promise.resolve({ requestId: "request_expired" }),
    });
    await Promise.resolve();
    await Promise.resolve();
    user.reject(new Error("unauthenticated"));
    resolution.resolve(terminalResolution);

    const page = await pagePromise as ReactElement<{
      resolution: ConsentResolution;
    }>;
    expect(page.props.resolution).toBe(terminalResolution);
  });

  it("preserves /me failures for a valid resolution", async () => {
    const resolution = deferred<ConsentResolution>();
    const user = deferred<CurrentUser>();
    const failure = new Error("/me unavailable");
    queryMocks.getConsentResolution.mockReturnValue(resolution.promise);
    queryMocks.getCurrentUser.mockReturnValue(user.promise);

    const pagePromise = AuthorizePage({
      searchParams: Promise.resolve({ requestId: "request_valid" }),
    });
    await Promise.resolve();
    await Promise.resolve();
    user.reject(failure);
    resolution.resolve(validResolution);

    await expect(pagePromise).rejects.toBe(failure);
  });
});
