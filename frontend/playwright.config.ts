//
// Copyright (c) 2026 Chen Jiajie(Ariakage)
//
// Author: Chen Jiajie(Ariakage) <ariakage233@gmail.com>
// Date: 2026-08-05
// Description: Playwright end-to-end test configuration
//

import { defineConfig, devices } from "@playwright/test";

const e2ePort = Number(process.env.UP_E2E_PORT ?? "3000");
if (!Number.isInteger(e2ePort) || e2ePort < 1 || e2ePort > 65535) {
  throw new Error("UP_E2E_PORT must be a valid TCP port");
}

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "html",
  use: {
    baseURL: `http://localhost:${e2ePort}`,
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: `pnpm dev --port ${e2ePort}`,
    url: `http://localhost:${e2ePort}`,
    reuseExistingServer: true,
    timeout: 60_000,
    env: {
      // The e2e suite exercises the frozen mock data source; real HTTP
      // seams (P3.7) must not reach a live backend here.
      NEXT_PUBLIC_USE_MOCK: "true",
    },
  },
});
