import { defineConfig, devices } from '@playwright/test';

/**
 * Strict accessibility (axe-core) gate. Builds, then serves the built site
 * with vite preview under its GitHub Pages base path, and scans a single
 * Chromium project in both themes.
 */
const PORT = 4334;
const BASE = '/crypto-lab-web-of-trust/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Build before previewing. `vite preview` only serves whatever is already in
    // dist/, so without this a failed build leaves the last good bundle in place
    // and the scan passes green against source that no longer compiles.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
