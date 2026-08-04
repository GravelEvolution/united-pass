import { describe, it, expect, afterEach } from "vitest";
import { mockUnitedPassDataSource } from "./united-pass-data-source";

/**
 * Integration tests for the mock UnitedPassDataSource.
 *
 * These tests verify that mutations persist across subsequent queries,
 * catching "page loop breaks" that pure-function tests miss:
 * create → detail → update → disable → rotate → delete.
 */
describe("OAuth application lifecycle", () => {
  const createdAppIds: string[] = [];

  afterEach(async () => {
    for (const appId of createdAppIds.splice(0)) {
      try {
        await mockUnitedPassDataSource.deleteApplication(appId);
      } catch {
        // already deleted or never existed
      }
    }
  });

  it("persists a created application in list and detail", async () => {
    const result = await mockUnitedPassDataSource.createApplication({
      name: "Lifecycle Test App",
      description: "Integration test application",
      audience: "internal",
      ownerName: "Test Owner",
    });
    createdAppIds.push(result.applicationId);

    expect(result.applicationId).toMatch(/^app_/);

    const apps = await mockUnitedPassDataSource.getApplications();
    const found = apps.find((a) => a.applicationId === result.applicationId);
    expect(found).toBeDefined();
    expect(found?.name).toBe("Lifecycle Test App");
    expect(found?.status).toBe("active");
    expect(found?.clientCount).toBe(0);

    const detail = await mockUnitedPassDataSource.getApplicationDetail(result.applicationId);
    expect(detail).not.toBeNull();
    expect(detail?.name).toBe("Lifecycle Test App");
    expect(detail?.audience).toBe("internal");
    expect(detail?.ownerName).toBe("Test Owner");
    expect(detail?.clients).toHaveLength(0);
    expect(detail?.auditEntries.length).toBeGreaterThanOrEqual(1);
    expect(detail?.auditEntries[0]?.eventType).toBe("应用创建");
  });

  it("persists a created OAuth client in application detail", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "Client Test App",
      description: "",
      audience: "external",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    const client = await mockUnitedPassDataSource.createOAuthClient({
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

    const detail = await mockUnitedPassDataSource.getApplicationDetail(app.applicationId);
    expect(detail?.clients).toHaveLength(1);
    expect(detail?.clients[0]?.name).toBe("Web Client");
    expect(detail?.clients[0]?.clientType).toBe("confidential");
    expect(detail?.clients[0]?.grantTypes).toEqual(["authorization_code", "refresh_token"]);
    expect(detail?.clients[0]?.tokenEndpointAuthMethod).toBe("client_secret_post");
    expect(detail?.clients[0]?.clientSecrets).toHaveLength(1);
    expect(detail?.clients[0]?.redirectUris).toHaveLength(1);
    expect(detail?.clients[0]?.redirectUris[0]?.uri).toBe("https://example.com/callback");

    const apps = await mockUnitedPassDataSource.getApplications();
    const found = apps.find((a) => a.applicationId === app.applicationId);
    expect(found?.clientCount).toBe(1);
  });

  it("creates a public client without a secret", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "SPA Test App",
      description: "",
      audience: "external",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    const client = await mockUnitedPassDataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "SPA Client",
      profile: "spa_mobile",
      redirectUris: ["https://app.example.com/auth"],
      logoutUri: "",
      allowedScopes: ["openid"],
      consentMode: "always",
    });

    expect(client.clientSecret).toBeUndefined();

    const detail = await mockUnitedPassDataSource.getApplicationDetail(app.applicationId);
    expect(detail?.clients[0]?.clientType).toBe("public");
    expect(detail?.clients[0]?.clientSecrets).toHaveLength(0);
    expect(detail?.clients[0]?.tokenEndpointAuthMethod).toBe("none");
  });

  it("creates a server-to-server client without redirect URIs or openid", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "M2M Test App",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    const client = await mockUnitedPassDataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "Service Account",
      profile: "server_to_server",
      redirectUris: [],
      logoutUri: "",
      allowedScopes: [],
      consentMode: "always",
    });

    expect(client.clientSecret).toBeDefined();

    const detail = await mockUnitedPassDataSource.getApplicationDetail(app.applicationId);
    const c = detail?.clients[0];
    expect(c?.clientType).toBe("confidential");
    expect(c?.grantTypes).toEqual(["client_credentials"]);
    expect(c?.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(c?.redirectUris).toHaveLength(0);
  });

  it("updates application fields and persists changes", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "Update Test",
      description: "Original",
      audience: "internal",
      ownerName: "Original Owner",
    });
    createdAppIds.push(app.applicationId);

    await mockUnitedPassDataSource.updateApplication(app.applicationId, {
      name: "Updated Name",
      description: "Updated Description",
      audience: "hybrid",
      ownerName: "New Owner",
    });

    const detail = await mockUnitedPassDataSource.getApplicationDetail(app.applicationId);
    expect(detail?.name).toBe("Updated Name");
    expect(detail?.description).toBe("Updated Description");
    expect(detail?.audience).toBe("hybrid");
    expect(detail?.ownerName).toBe("New Owner");

    const apps = await mockUnitedPassDataSource.getApplications();
    const found = apps.find((a) => a.applicationId === app.applicationId);
    expect(found?.name).toBe("Updated Name");
    expect(found?.audience).toBe("hybrid");
  });

  it("disables and re-enables an application with audit trail", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "Disable Test",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    await mockUnitedPassDataSource.updateApplicationStatus(app.applicationId, "disabled");

    let detail = await mockUnitedPassDataSource.getApplicationDetail(app.applicationId);
    expect(detail?.status).toBe("disabled");

    const apps = await mockUnitedPassDataSource.getApplications();
    const found = apps.find((a) => a.applicationId === app.applicationId);
    expect(found?.status).toBe("disabled");

    const disableAudit = detail?.auditEntries.find((e) => e.eventType === "应用停用");
    expect(disableAudit).toBeDefined();
    expect(disableAudit?.result).toBe("success");

    await mockUnitedPassDataSource.updateApplicationStatus(app.applicationId, "active");

    detail = await mockUnitedPassDataSource.getApplicationDetail(app.applicationId);
    expect(detail?.status).toBe("active");

    const enableAudit = detail?.auditEntries.find((e) => e.eventType === "应用启用");
    expect(enableAudit).toBeDefined();
  });

  it("rotates a client secret and adds a new secret record", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "Rotate Test",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    const client = await mockUnitedPassDataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "Web",
      profile: "web_server",
      redirectUris: ["https://example.com/cb"],
      logoutUri: "",
      allowedScopes: ["openid"],
      consentMode: "always",
    });

    const beforeDetail = await mockUnitedPassDataSource.getApplicationDetail(app.applicationId);
    const beforeSecretCount = beforeDetail?.clients[0]?.clientSecrets.length ?? 0;

    const rotation = await mockUnitedPassDataSource.rotateClientSecret(client.clientId);
    expect(rotation.secretId).toMatch(/^sec_/);
    expect(rotation.clientSecret).toBeDefined();
    expect(rotation.previousSecretExpiresAt).toBeDefined();

    const afterDetail = await mockUnitedPassDataSource.getApplicationDetail(app.applicationId);
    const afterSecretCount = afterDetail?.clients[0]?.clientSecrets.length ?? 0;
    expect(afterSecretCount).toBe(beforeSecretCount + 1);
  });

  it("rejects secret rotation for public clients", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "Public Rotate Test",
      description: "",
      audience: "external",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    const client = await mockUnitedPassDataSource.createOAuthClient({
      applicationId: app.applicationId,
      name: "SPA",
      profile: "spa_mobile",
      redirectUris: ["https://app.example.com/auth"],
      logoutUri: "",
      allowedScopes: ["openid"],
      consentMode: "always",
    });

    await expect(mockUnitedPassDataSource.rotateClientSecret(client.clientId)).rejects.toThrow(
      "Public clients do not use client secrets.",
    );
  });

  it("deletes an application and removes it from list and detail", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "Delete Test",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });

    await mockUnitedPassDataSource.deleteApplication(app.applicationId);

    const detail = await mockUnitedPassDataSource.getApplicationDetail(app.applicationId);
    expect(detail).toBeNull();

    const apps = await mockUnitedPassDataSource.getApplications();
    const found = apps.find((a) => a.applicationId === app.applicationId);
    expect(found).toBeUndefined();
  });

  it("rejects operations on non-existent applications", async () => {
    await expect(
      mockUnitedPassDataSource.getApplicationDetail("app_nonexistent"),
    ).resolves.toBeNull();

    await expect(
      mockUnitedPassDataSource.updateApplicationStatus("app_nonexistent", "disabled"),
    ).rejects.toThrow();

    await expect(
      mockUnitedPassDataSource.updateApplication("app_nonexistent", { name: "X" }),
    ).rejects.toThrow();

    await expect(
      mockUnitedPassDataSource.rotateClientSecret("client_nonexistent"),
    ).rejects.toThrow();
  });

  it("atomically creates an application with an initial OAuth client", async () => {
    const result = await mockUnitedPassDataSource.createApplicationWithInitialClient({
      application: {
        name: "Atomic Test App",
        description: "Created atomically",
        audience: "internal",
        ownerName: "Test Owner",
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
    createdAppIds.push(result.applicationId);

    expect(result.applicationId).toMatch(/^app_/);
    expect(result.clientId).toMatch(/^we_/);
    expect(result.clientSecret).toBeDefined();

    const detail = await mockUnitedPassDataSource.getApplicationDetail(result.applicationId);
    expect(detail).not.toBeNull();
    expect(detail?.clients).toHaveLength(1);
    expect(detail?.clients[0]?.name).toBe("Web Client");
    expect(detail?.clients[0]?.clientType).toBe("confidential");

    const apps = await mockUnitedPassDataSource.getApplications();
    const found = apps.find((a) => a.applicationId === result.applicationId);
    expect(found?.clientCount).toBe(1);
  });

  it("atomically creates with a public client and no secret", async () => {
    const result = await mockUnitedPassDataSource.createApplicationWithInitialClient({
      application: {
        name: "Atomic SPA App",
        description: "",
        audience: "external",
        ownerName: "Owner",
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
    createdAppIds.push(result.applicationId);

    expect(result.clientSecret).toBeUndefined();

    const detail = await mockUnitedPassDataSource.getApplicationDetail(result.applicationId);
    expect(detail?.clients[0]?.clientType).toBe("public");
  });
});

describe("OAuth client invariant enforcement", () => {
  const createdAppIds: string[] = [];

  afterEach(async () => {
    for (const appId of createdAppIds.splice(0)) {
      try {
        await mockUnitedPassDataSource.deleteApplication(appId);
      } catch {
        // already deleted or never existed
      }
    }
  });

  it("rejects createOAuthClient for a non-existent parent application", async () => {
    await expect(
      mockUnitedPassDataSource.createOAuthClient({
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
    const app = await mockUnitedPassDataSource.createApplication({
      name: "Scope Test App",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    await expect(
      mockUnitedPassDataSource.createOAuthClient({
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
    const app = await mockUnitedPassDataSource.createApplication({
      name: "M2M Scope Test",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    await expect(
      mockUnitedPassDataSource.createOAuthClient({
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

  it("rejects trusted_first_party consent mode from caller", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "Consent Test App",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    await expect(
      mockUnitedPassDataSource.createOAuthClient({
        applicationId: app.applicationId,
        name: "Trusted Client",
        profile: "web_server",
        redirectUris: ["https://example.com/cb"],
        logoutUri: "",
        allowedScopes: ["openid"],
        consentMode: "trusted_first_party",
      }),
    ).rejects.toThrow("trusted_first_party");
  });

  it("rejects redirect URIs with non-https scheme (except localhost)", async () => {
    const app = await mockUnitedPassDataSource.createApplication({
      name: "URI Test App",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    await expect(
      mockUnitedPassDataSource.createOAuthClient({
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
    const app = await mockUnitedPassDataSource.createApplication({
      name: "Localhost Test",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    const client = await mockUnitedPassDataSource.createOAuthClient({
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
    const app = await mockUnitedPassDataSource.createApplication({
      name: "M2M URI Test",
      description: "",
      audience: "internal",
      ownerName: "Owner",
    });
    createdAppIds.push(app.applicationId);

    await expect(
      mockUnitedPassDataSource.createOAuthClient({
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
      mockUnitedPassDataSource.createApplicationWithInitialClient({
        application: {
          name: "Bad Atomic App",
          description: "",
          audience: "internal",
          ownerName: "Owner",
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

  it("rejects atomic creation with trusted_first_party on external audience", async () => {
    await expect(
      mockUnitedPassDataSource.createApplicationWithInitialClient({
        application: {
          name: "External Trusted",
          description: "",
          audience: "external",
          ownerName: "Owner",
        },
        initialClient: {
          name: "Trusted External",
          profile: "web_server",
          redirectUris: ["https://example.com/cb"],
          logoutUri: "",
          allowedScopes: ["openid"],
          consentMode: "trusted_first_party",
        },
      }),
    ).rejects.toThrow("trusted_first_party");
  });
});

describe("consent resolution and decision", () => {
  it("resolves a valid consent request with scopes and redirect host", async () => {
    const resolution = await mockUnitedPassDataSource.getConsentResolution("consent_demo_001");

    expect(resolution.status).toBe("valid");
    if (resolution.status === "valid") {
      expect(resolution.request.applicationName).toBe("United Workspace");
      expect(resolution.request.redirectHost).toBe("workspace.united.example");
      expect(resolution.request.scopes.length).toBeGreaterThan(0);
      expect(resolution.request.scopes.some((s) => s.scope === "openid")).toBe(true);
    }
  });

  it("resolves expired, not_found, and mismatch states", async () => {
    const expired = await mockUnitedPassDataSource.getConsentResolution("consent_demo_002");
    expect(expired.status).toBe("expired");

    const notFound = await mockUnitedPassDataSource.getConsentResolution("consent_demo_003");
    expect(notFound.status).toBe("client_not_found");

    const mismatch = await mockUnitedPassDataSource.getConsentResolution("consent_demo_004");
    expect(mismatch.status).toBe("redirect_mismatch");
    if (mismatch.status === "redirect_mismatch") {
      expect(mismatch.attemptedRedirect).toBe("https://evil.example/callback");
    }
  });

  it("resolves unauthenticated and scope_not_allowed states", async () => {
    const unauth = await mockUnitedPassDataSource.getConsentResolution("consent_demo_005");
    expect(unauth.status).toBe("unauthenticated");
    if (unauth.status === "unauthenticated") {
      expect(unauth.requestId).toBe("consent_demo_005");
    }

    const scopeNotAllowed = await mockUnitedPassDataSource.getConsentResolution("consent_demo_006");
    expect(scopeNotAllowed.status).toBe("scope_not_allowed");
    if (scopeNotAllowed.status === "scope_not_allowed") {
      expect(scopeNotAllowed.disallowedScopes).toContain("admin:read");
    }
  });

  it("returns client_not_found for unknown requestId", async () => {
    const resolution = await mockUnitedPassDataSource.getConsentResolution("unknown_request");
    expect(resolution.status).toBe("client_not_found");
  });

  it("decideConsent returns a redirect URL for allow and deny", async () => {
    const allowResult = await mockUnitedPassDataSource.decideConsent("consent_demo_001", "allow");
    expect(allowResult.redirectUrl).toContain("callback");
    expect(allowResult.redirectUrl.startsWith("http")).toBe(true);

    const denyResult = await mockUnitedPassDataSource.decideConsent("consent_demo_001", "deny");
    expect(denyResult.redirectUrl).toBe("/account");
    expect(denyResult.redirectUrl.startsWith("/")).toBe(true);
  });
});

describe("authorized application grant lifecycle", () => {
  it("lists authorized applications with grants", async () => {
    const apps = await mockUnitedPassDataSource.getAuthorizedApplications();
    expect(apps.length).toBeGreaterThanOrEqual(3);

    const active = apps.find((a) => a.grantId === "grant_001");
    expect(active?.applicationName).toBe("United Workspace");
    expect(active?.status).toBe("active");
    expect(active?.scopes).toContain("openid");
  });

  it("revokes a grant and removes it from the authorized list", async () => {
    const before = await mockUnitedPassDataSource.getAuthorizedApplications();
    const beforeCount = before.length;
    const grantToRevoke = before.find((a) => a.grantId === "grant_002");
    expect(grantToRevoke).toBeDefined();

    await mockUnitedPassDataSource.revokeGrant("grant_002");

    const after = await mockUnitedPassDataSource.getAuthorizedApplications();
    const revoked = after.find((a) => a.grantId === "grant_002");
    expect(revoked).toBeUndefined();
    expect(after.length).toBe(beforeCount - 1);
  });
});
