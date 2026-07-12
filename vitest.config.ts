import { defineConfig } from 'vitest/config';

// Pure-logic + real-crypto unit tests for the trust engine. These run in the
// Node environment (Node's WebCrypto provides Ed25519, the same primitive the
// browser build prefers), so `computeValidity` is exercised end-to-end —
// genuine keypairs, genuine signatures — with NO headless browser.
//
// The Playwright accessibility gate lives in e2e/ and is run separately via
// `npm run test:a11y`; it must NOT be collected by vitest.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
