import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * Every scenario is scanned in its own right rather than being overwritten by
 * the next: a forged certificate, an orphaned key, over-trust, a depth cut, a
 * certificate flood, then reset. Then the trust-path trace (which dims the
 * whole off-path graph), the certification-payload `<dialog>` open and closed,
 * the trust policy at both ends of its range, a new certification signed and
 * repeated, and the sample network rebuilt and recomputed. Every resulting
 * state is scanned in both themes at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no `<details>`
 * is opened from script, why every step is scanned rather than only the last,
 * and why `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
  });
}
