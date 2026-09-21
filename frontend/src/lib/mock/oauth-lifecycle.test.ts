//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Unit tests for the mocked OAuth lifecycle
//

import { describe, it, expect, beforeEach } from "vitest";
import type { UnitedPassDataSource } from "@/lib/api/united-pass-data-source";
import type { ApplicationAudience } from "@/features/applications/types";
import { createMockUnitedPassDataSource } from "./united-pass-data-source";

/**
 * Integration tests for the mock UnitedPassDataSource.
 *
 * Each test gets a fresh mock instance via createMockUnitedPassDataSource()
 * to guarantee full isolation — no shared mutable state between tests,
 * no cleanup boilerlette, and no risk of cross-test pollution when the
 * suite grows or runs in parallel.
 *
 * Contract note: standalone application creation does not exist in the
 * backend REST contract, so every test creates applications through
 * createApplicationWithInitialClient (the only creation path).
 */

const OWNER_USER_ID = "usr_02F4PXKQ0EZP5F7B9V3C"; // 周予安 in the mock directory

async function createTestApplication(
  dataSource: UnitedPassDataSource,
  overrides?: Partial<{
    name: string;
    description: string;
    audience: ApplicationAudience;
    ownerId: string;
  }>,
): Promise<{ applicationId: string; clientId: string }> {
  const result = await dataSource.createApplicationWithInitialClient({
    application: {
      name: overrides?.name ?? "Test App",
      description: overrides?.description ?? "",
      audience: overrides?.audience ?? "internal",
      ownerId: overrides?.ownerId ?? OWNER_USER_ID,
    },
    initialClient: {
      name: "Initial Web Client",
      profile: "web_server",
      redirectUris: ["https://example.com/callback"],
      logoutUri: "",
      allowedScopes: ["openid"],
      consentMode: "always",
    },
  });
  return { applicationId: result.applicationId, clientId: result.clientId };
}

describe("OAuth application lifecycle", () => {
  let dataSource: UnitedPassDataSource;

  beforeEach(() => {
    dataSource = createMockUnitedPassDataSource();
  });

  it("persists an application created with its initial client in list and detail", async () => {
    const result = await dataSource.createApplicationWithInitialClient({
      application: {
        name: "Lifecycle Test App",
        description: "Integration test application",
        audience: "internal",
        ownerId: OWNER_USER_ID,
      },
      initialClient: {
        name: "Web Client",
        profile: "web_server",
        redirectUris: ["https://example.com/callback"],
        logoutUri: "",
        allowedScopes: ["openid"],
        consentMode: "always",
      },
    });

    expect(result.applicationId).toMatch(/^app_/);

    const apps = (await dataSource.getApplications()).items;
    const found = apps.find((a) => a.applicationId === result.applicationId);
    expect(found).toBeDefined();
    expect(found?.name).toBe("Lifecycle Test App");
    expect(found?.status).toBe("active");
    expect(found?.ownerId).toBe(OWNER_USER_ID);
    expect(found?.ownerName).toBe("周予安");
    expect(found?.clientCount).toBe(1);

    const detail = await dataSource.getApplicationDetail(result.applicationId);
    expect(detail).not.toBeNull();
    expect(detail?.name).toBe("Lifecycle Test App");
    expect(detail?.audience).toBe("internal");
    expect(detail?.ownerId).toBe(OWNER_USER_ID);
    expect(detail?.ownerName).toBe("周予安");
    expect(detail?.clients).toHaveLength(1);
    expect(detail?.auditEntries.length).toBeGreaterThanOrEqual(2);
    expect(detail?.auditEntries[0]?.eventType).toBe("应用创建");
  });

  it("persists a created OAuth client in application detail", async () => {
    const app = await createTestApplication(dataSource, { name: "Client Test App", audience: "external" });

    const client = await dataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "Web Client",
      profile: "web_server",
      redirectUris: ["https://example.com/callback"],
      logoutUri: "https://example.com/logout",
      allowedScopes: ["openid", "profile"],
      consentMode: "always",
    });

    expect(client.clientId).toMatch(/^we_/);
    expect(client.clientSecret).toBeDefined();
    expect(client.clientSecret?.length).toBeGreaterThan(10);

    const detail = await dataSource.getApplicationDetail(app.applicationId);
    expect(detail?.clients).toHaveLength(2);
    const created = detail?.clients.find((c) => c.clientId === client.clientId);
    expect(created?.name).toBe("Web Client");
    expect(created?.clientType).toBe("confidential");
    expect(created?.grantTypes).toEqual(["authorization_code", "refresh_token"]);
    expect(created?.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(created?.clientSecrets).toHaveLength(1);
    expect(created?.redirectUris).toHaveLength(1);
    expect(created?.redirectUris[0]?.uri).toBe("https://example.com/callback");

    const apps = (await dataSource.getApplications()).items;
    const found = apps.find((a) => a.applicationId === app.applicationId);
    expect(found?.clientCount).toBe(2);
  });

  it("creates a public client without a secret", async () => {
    const app = await createTestApplication(dataSource, { name: "SPA Test App", audience: "external" });

    const client = await dataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "SPA Client",
      profile: "spa_mobile",
      redirectUris: ["https://app.example.com/auth"],
      logoutUri: "",
      allowedScopes: ["openid"],
      consentMode: "always",
    });

    expect(client.clientSecret).toBeUndefined();

    const detail = await dataSource.getApplicationDetail(app.applicationId);
    const created = detail?.clients.find((c) => c.clientId === client.clientId);
    expect(created?.clientType).toBe("public");
    expect(created?.clientSecrets).toHaveLength(0);
    expect(created?.tokenEndpointAuthMethod).toBe("none");
  });

  it("creates a web_server client without openid (OAuth-only authorization)", async () => {
    const app = await createTestApplication(dataSource, { name: "OAuth-Only App" });

    const client = await dataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "API Client",
      profile: "web_server",
      redirectUris: ["https://example.com/cb"],
      logoutUri: "",
      allowedScopes: ["reporting:read"],
      consentMode: "always",
    });

    expect(client.clientSecret).toBeDefined();

    const detail = await dataSource.getApplicationDetail(app.applicationId);
    const created = detail?.clients.find((c) => c.clientId === client.clientId);
    expect(created?.allowedScopes.map((s) => s.scope)).toEqual(["reporting:read"]);
    expect(created?.allowedScopes.some((s) => s.scope === "openid")).toBe(false);
  });

  it("creates a server-to-server client without redirect URIs or openid", async () => {
    const app = await createTestApplication(dataSource, { name: "M2M Test App" });

    const client = await dataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "Service Account",
      profile: "server_to_server",
      redirectUris: [],
      logoutUri: "",
      allowedScopes: [],
      consentMode: "always",
    });

    expect(client.clientSecret).toBeDefined();

    const detail = await dataSource.getApplicationDetail(app.applicationId);
    const created = detail?.clients.find((c) => c.clientId === client.clientId);
    expect(created?.clientType).toBe("confidential");
    expect(created?.grantTypes).toEqual(["client_credentials"]);
    expect(created?.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(created?.redirectUris).toHaveLength(0);
  });

  it("updates application fields and persists changes", async () => {
    const app = await createTestApplication(dataSource, {
      name: "Update Test",
      description: "Original",
    });

    await dataSource.updateApplication(app.applicationId, {
      name: "Updated Name",
      description: "Updated Description",
      audience: "hybrid",
      ownerId: "usr_05QG6E8W4NR7Y2Z1PC9S",
    });

    const detail = await dataSource.getApplicationDetail(app.applicationId);
    expect(detail?.name).toBe("Updated Name");
    expect(detail?.description).toBe("Updated Description");
    expect(detail?.audience).toBe("hybrid");
    expect(detail?.ownerId).toBe("usr_05QG6E8W4NR7Y2Z1PC9S");
    expect(detail?.ownerName).toBe("顾言");

    const apps = (await dataSource.getApplications()).items;
    const found = apps.find((a) => a.applicationId === app.applicationId);
    expect(found?.name).toBe("Updated Name");
    expect(found?.audience).toBe("hybrid");
    expect(found?.ownerId).toBe("usr_05QG6E8W4NR7Y2Z1PC9S");
    expect(found?.ownerName).toBe("顾言");
  });

  it("disables and re-enables an application with audit trail", async () => {
    const app = await createTestApplication(dataSource, { name: "Disable Test" });

    await dataSource.updateApplicationStatus(app.applicationId, "disabled");

    let detail = await dataSource.getApplicationDetail(app.applicationId);
    expect(detail?.status).toBe("disabled");

    const apps = (await dataSource.getApplications()).items;
    const found = apps.find((a) => a.applicationId === app.applicationId);
    expect(found?.status).toBe("disabled");

    const disableAudit = detail?.auditEntries.find((e) => e.eventType === "应用停用");
    expect(disableAudit).toBeDefined();
    expect(disableAudit?.result).toBe("success");

    await dataSource.updateApplicationStatus(app.applicationId, "active");

    detail = await dataSource.getApplicationDetail(app.applicationId);
    expect(detail?.status).toBe("active");

    const enableAudit = detail?.auditEntries.find((e) => e.eventType === "应用启用");
    expect(enableAudit).toBeDefined();
  });

  it("rotates a client secret and adds a new secret record", async () => {
    const app = await createTestApplication(dataSource, { name: "Rotate Test" });

    const beforeDetail = await dataSource.getApplicationDetail(app.applicationId);
    const beforeClient = beforeDetail?.clients.find((c) => c.clientId === app.clientId);
    const beforeSecretCount = beforeClient?.clientSecrets.length ?? 0;

    const rotation = await dataSource.rotateClientSecret(app.applicationId, app.clientId);
    expect(rotation.secretId).toMatch(/^sec_/);
    expect(rotation.clientSecret).toBeDefined();
    expect(rotation.previousSecretExpiresAt).toBeDefined();

    const afterDetail = await dataSource.getApplicationDetail(app.applicationId);
    const afterClient = afterDetail?.clients.find((c) => c.clientId === app.clientId);
    const afterSecretCount = afterClient?.clientSecrets.length ?? 0;
    expect(afterSecretCount).toBe(beforeSecretCount + 1);
  });

  it("rejects secret rotation for public clients", async () => {
    const app = await createTestApplication(dataSource, { name: "Public Rotate Test", audience: "external" });

    const client = await dataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "SPA",
      profile: "spa_mobile",
      redirectUris: ["https://app.example.com/auth"],
      logoutUri: "",
      allowedScopes: ["openid"],
      consentMode: "always",
    });

    await expect(
      dataSource.rotateClientSecret(app.applicationId, client.clientId),
    ).rejects.toThrow("Public clients do not use client secrets.");
  });

  it("rejects secret rotation when the client is not under the addressed application", async () => {
    const app = await createTestApplication(dataSource, { name: "Binding Test" });
    const otherApp = await createTestApplication(dataSource, { name: "Other App" });

    // The initial client exists, but under `app`, not under `otherApp`:
    // rotation is scoped to the parent application like the backend URL.
    await expect(
      dataSource.rotateClientSecret(otherApp.applicationId, app.clientId),
    ).rejects.toThrow("not found under application");
  });

  it("deletes an application and removes it from list and detail", async () => {
    const app = await createTestApplication(dataSource, { name: "Delete Test" });

    await dataSource.deleteApplication(app.applicationId);

    const detail = await dataSource.getApplicationDetail(app.applicationId);
    expect(detail).toBeNull();

    const apps = (await dataSource.getApplications()).items;
    const found = apps.find((a) => a.applicationId === app.applicationId);
    expect(found).toBeUndefined();
  });

  it("rejects operations on non-existent applications", async () => {
    await expect(
      dataSource.getApplicationDetail("app_nonexistent"),
    ).resolves.toBeNull();

    await expect(
      dataSource.updateApplicationStatus("app_nonexistent", "disabled"),
    ).rejects.toThrow();

    await expect(
      dataSource.updateApplication("app_nonexistent", { name: "X" }),
    ).rejects.toThrow();

    await expect(
      dataSource.rotateClientSecret("app_nonexistent", "client_nonexistent"),
    ).rejects.toThrow();
  });

  it("atomically creates an application with an initial OAuth client", async () => {
    const result = await dataSource.createApplicationWithInitialClient({
      application: {
        name: "Atomic Test App",
        description: "Created atomically",
        audience: "internal",
        ownerId: OWNER_USER_ID,
      },
      initialClient: {
        name: "Web Client",
        profile: "web_server",
        redirectUris: ["https://example.com/callback"],
        logoutUri: "",
        allowedScopes: ["openid", "profile"],
        consentMode: "always",
      },
    });

    expect(result.applicationId).toMatch(/^app_/);
    expect(result.clientId).toMatch(/^we_/);
    expect(result.clientSecret).toBeDefined();

    const detail = await dataSource.getApplicationDetail(result.applicationId);
    expect(detail).not.toBeNull();
    expect(detail?.clients).toHaveLength(1);
    expect(detail?.clients[0]?.name).toBe("Web Client");
    expect(detail?.clients[0]?.clientType).toBe("confidential");

    const apps = (await dataSource.getApplications()).items;
    const found = apps.find((a) => a.applicationId === result.applicationId);
    expect(found?.clientCount).toBe(1);
  });

  it("atomically creates with a public client and no secret", async () => {
    const result = await dataSource.createApplicationWithInitialClient({
      application: {
        name: "Atomic SPA App",
        description: "",
        audience: "external",
        ownerId: OWNER_USER_ID,
      },
      initialClient: {
        name: "SPA Client",
        profile: "spa_mobile",
        redirectUris: ["https://app.example.com/auth"],
        logoutUri: "",
        allowedScopes: ["openid"],
        consentMode: "always",
      },
    });

    expect(result.clientSecret).toBeUndefined();

    const detail = await dataSource.getApplicationDetail(result.applicationId);
    expect(detail?.clients[0]?.clientType).toBe("public");
  });
});

describe("OAuth client invariant enforcement", () => {
  let dataSource: UnitedPassDataSource;

  beforeEach(() => {
    dataSource = createMockUnitedPassDataSource();
  });

  it("rejects createOAuthClient for a non-existent parent application", async () => {
    await expect(
      dataSource.createOAuthClient({
        applicationId: "app_nonexistent",
        name: "Orphan Client",
        profile: "web_server",
        redirectUris: ["https://example.com/cb"],
        logoutUri: "",
        allowedScopes: ["openid"],
        consentMode: "always",
      }),
    ).rejects.toThrow("不存在");
  });

  it("rejects unknown scopes", async () => {
    const app = await createTestApplication(dataSource, { name: "Scope Test App" });

    await expect(
      dataSource.createOAuthClient({
        applicationId: app.applicationId,
        name: "Bad Scope Client",
        profile: "web_server",
        redirectUris: ["https://example.com/cb"],
        logoutUri: "",
        allowedScopes: ["openid", "admin:read"],
        consentMode: "always",
      }),
    ).rejects.toThrow("未知");
  });

  it("rejects openid on server_to_server profile", async () => {
    const app = await createTestApplication(dataSource, { name: "M2M Scope Test" });

    await expect(
      dataSource.createOAuthClient({
        applicationId: app.applicationId,
        name: "M2M with openid",
        profile: "server_to_server",
        redirectUris: [],
        logoutUri: "",
        allowedScopes: ["openid"],
        consentMode: "always",
      }),
    ).rejects.toThrow("openid");
  });

  it("rejects trusted_first_party consent mode as unknown in MVP", async () => {
    const app = await createTestApplication(dataSource, { name: "Consent Test App" });

    await expect(
      dataSource.createOAuthClient({
        applicationId: app.applicationId,
        name: "Trusted Client",
        profile: "web_server",
        redirectUris: ["https://example.com/cb"],
        logoutUri: "",
        allowedScopes: ["openid"],
        consentMode: "trusted_first_party" as never,
      }),
    ).rejects.toThrow("未知");
  });

  it("rejects redirect URIs with non-https scheme (except localhost)", async () => {
    const app = await createTestApplication(dataSource, { name: "URI Test App" });

    await expect(
      dataSource.createOAuthClient({
        applicationId: app.applicationId,
        name: "Bad URI Client",
        profile: "web_server",
        redirectUris: ["ftp://evil.example/callback"],
        logoutUri: "",
        allowedScopes: ["openid"],
        consentMode: "always",
      }),
    ).rejects.toThrow("Redirect URI");
  });

  it("accepts localhost http redirect URIs", async () => {
    const app = await createTestApplication(dataSource, { name: "Localhost Test" });

    const client = await dataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "Dev Client",
      profile: "web_server",
      redirectUris: ["http://localhost:3000/callback"],
      logoutUri: "",
      allowedScopes: ["openid"],
      consentMode: "always",
    });

    expect(client.clientId).toMatch(/^de_/);
  });

  it("rejects redirect URIs on server_to_server profile", async () => {
    const app = await createTestApplication(dataSource, { name: "M2M URI Test" });

    await expect(
      dataSource.createOAuthClient({
        applicationId: app.applicationId,
        name: "M2M with URIs",
        profile: "server_to_server",
        redirectUris: ["https://example.com/cb"],
        logoutUri: "",
        allowedScopes: [],
        consentMode: "always",
      }),
    ).rejects.toThrow("不需要");
  });

  it("rejects atomic creation with server_to_server and openid", async () => {
    await expect(
      dataSource.createApplicationWithInitialClient({
        application: {
          name: "Bad Atomic App",
          description: "",
          audience: "internal",
          ownerId: OWNER_USER_ID,
        },
        initialClient: {
          name: "M2M with openid",
          profile: "server_to_server",
          redirectUris: [],
          logoutUri: "",
          allowedScopes: ["openid"],
          consentMode: "always",
        },
      }),
    ).rejects.toThrow("openid");
  });

  it("rejects atomic creation with trusted_first_party as unknown in MVP", async () => {
    await expect(
      dataSource.createApplicationWithInitialClient({
        application: {
          name: "External Trusted",
          description: "",
          audience: "external",
          ownerId: OWNER_USER_ID,
        },
        initialClient: {
          name: "Trusted External",
          profile: "web_server",
          redirectUris: ["https://example.com/cb"],
          logoutUri: "",
          allowedScopes: ["openid"],
          consentMode: "trusted_first_party" as never,
        },
      }),
    ).rejects.toThrow("未知");
  });

  it("rejects atomic creation without an owner ID", async () => {
    await expect(
      dataSource.createApplicationWithInitialClient({
        application: {
          name: "No Owner App",
          description: "",
          audience: "internal",
          ownerId: "   ",
        },
        initialClient: {
          name: "Web Client",
          profile: "web_server",
          redirectUris: ["https://example.com/callback"],
          logoutUri: "",
          allowedScopes: ["openid"],
          consentMode: "always",
        },
      }),
    ).rejects.toThrow("负责人");
  });
});

describe("consent resolution and decision", () => {
  let dataSource: UnitedPassDataSource;

  beforeEach(() => {
    dataSource = createMockUnitedPassDataSource();
  });

  it("resolves a valid consent request with scopes and redirect host", async () => {
    const resolution = await dataSource.getConsentResolution("consent_demo_001");

    expect(resolution.status).toBe("valid");
    if (resolution.status === "valid") {
      expect(resolution.request.applicationName).toBe("United Workspace");
      expect(resolution.request.redirectHost).toBe("workspace.united.example");
      expect(resolution.request.scopes.length).toBeGreaterThan(0);
      expect(resolution.request.scopes.some((s) => s.scope === "openid")).toBe(true);
    }
  });

  it("resolves expired, not_found, and mismatch states", async () => {
    const expired = await dataSource.getConsentResolution("consent_demo_002");
    expect(expired.status).toBe("expired");

    const notFound = await dataSource.getConsentResolution("consent_demo_003");
    expect(notFound.status).toBe("client_not_found");

    const mismatch = await dataSource.getConsentResolution("consent_demo_004");
    expect(mismatch.status).toBe("redirect_mismatch");
    if (mismatch.status === "redirect_mismatch") {
      expect(mismatch.attemptedRedirect).toBe("https://evil.example/callback");
    }
  });

  it("resolves unauthenticated and scope_not_allowed states", async () => {
    const unauth = await dataSource.getConsentResolution("consent_demo_005");
    expect(unauth.status).toBe("unauthenticated");
    if (unauth.status === "unauthenticated") {
      expect(unauth.requestId).toBe("consent_demo_005");
    }

    const scopeNotAllowed = await dataSource.getConsentResolution("consent_demo_006");
    expect(scopeNotAllowed.status).toBe("scope_not_allowed");
    if (scopeNotAllowed.status === "scope_not_allowed") {
      expect(scopeNotAllowed.disallowedScopes).toContain("admin:read");
    }
  });

  it("returns client_not_found for unknown requestId", async () => {
    const resolution = await dataSource.getConsentResolution("unknown_request");
    expect(resolution.status).toBe("client_not_found");
  });

  it("decideConsent returns a redirect URL for allow and deny", async () => {
    const allowResult = await dataSource.decideConsent("consent_demo_001", "allow");
    expect(allowResult.redirectUrl).toContain("callback");
    expect(allowResult.redirectUrl.startsWith("http")).toBe(true);

    const denyResult = await dataSource.decideConsent("consent_demo_001", "deny");
    expect(denyResult.redirectUrl).toBe("/account");
    expect(denyResult.redirectUrl.startsWith("/")).toBe(true);
  });
});

describe("authorized application grant lifecycle", () => {
  let dataSource: UnitedPassDataSource;

  beforeEach(() => {
    dataSource = createMockUnitedPassDataSource();
  });

  it("lists authorized applications with grants", async () => {
    const apps = await dataSource.getAuthorizedApplications();
    expect(apps.length).toBeGreaterThanOrEqual(3);

    const active = apps.find((a) => a.grantId === "grant_001");
    expect(active?.applicationName).toBe("United Workspace");
    expect(active?.status).toBe("active");
    expect(active?.scopes).toContain("openid");
  });

  it("revokes a grant and removes it from the authorized list", async () => {
    const before = await dataSource.getAuthorizedApplications();
    const beforeCount = before.length;
    const grantToRevoke = before.find((a) => a.grantId === "grant_002");
    expect(grantToRevoke).toBeDefined();

    await dataSource.revokeGrant("grant_002");

    const after = await dataSource.getAuthorizedApplications();
    const revoked = after.find((a) => a.grantId === "grant_002");
    expect(revoked).toBeUndefined();
    expect(after.length).toBe(beforeCount - 1);
  });

  it("does not affect other grants when revoking", async () => {
    const beforeCount = (await dataSource.getAuthorizedApplications()).length;

    await dataSource.revokeGrant("grant_002");

    const after = await dataSource.getAuthorizedApplications();
    const grant1 = after.find((a) => a.grantId === "grant_001");
    expect(grant1).toBeDefined();
    expect(grant1?.status).toBe("active");

    const grant3 = after.find((a) => a.grantId === "grant_003");
    expect(grant3).toBeDefined();
    expect(after.length).toBe(beforeCount - 1);
  });
});
