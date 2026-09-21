//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-28
// Description: Production standalone browser contract for the real Aliyun CAPTCHA SDK
//

import { defineConfig, devices } from "@playwright/test";

const productionCspPort = Number(process.env.UP_CSP_E2E_PORT ?? "3011");
if (!Number.isInteger(productionCspPort) || productionCspPort < 1 || productionCspPort > 65535) {
  throw new Error("UP_CSP_E2E_PORT must be a valid TCP port");
}

export default defineConfig({
  testDir: "./e2e-production",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: "line",
  timeout: 45_000,
  use: {
    baseURL: `http://127.0.0.1:${productionCspPort}`,
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium-production-csp",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "node scripts/start-production-csp-e2e-server.mjs",
    url: `http://127.0.0.1:${productionCspPort}/login`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      UP_CSP_E2E_PORT: String(productionCspPort),
    },
  },
});
