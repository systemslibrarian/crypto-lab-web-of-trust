import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the Web of Trust (PGP/OpenPGP trust model)
 * demo.
 *
 * The app is a single mountApp() SPA: it builds a sample keyring and computes
 * validity on load, so the trust graph (SVG), validity table, keyring cards and
 * certification list are all present without interaction. Beyond that we drive
 * every scenario button (each appends lines to the aria-live scenario log),
 * open the inspect modal (a <dialog> with its own injected payload markup), and
 * force every <details> open so axe scans the whole page in one pass, in both
 * the dark (default) and light themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight states (row-enter fade,
// dimmed trace nodes) can't hide text from the contrast checker.
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;scroll-behavior:auto!important;
    }`,
  });
}

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
  });
}

// Drive the interactive surfaces so dynamically-injected regions are in the DOM
// and rendered when axe measures them.
async function driveDemos(page: Page): Promise<void> {
  // Run each scenario — every click appends a line to #scenario-log and, for
  // most, re-renders the validity table + graph with new states (forged,
  // orphan, over-trust, depth cut, flood).
  for (const id of [
    '#scn-forge',
    '#scn-orphan',
    '#scn-overtrust',
    '#scn-depth',
    '#scn-flood',
    '#scn-reset',
  ]) {
    await page.locator(id).click();
  }
  await expect(page.locator('#scenario-log .wot-log-line').first()).toBeVisible();

  // Open the inspect modal (a <dialog>) for the first certification so its
  // injected payload markup is scanned, then close it.
  const inspectBtn = page.locator('[data-action="inspect"]').first();
  if (await inspectBtn.count()) {
    await inspectBtn.click();
    await expect(page.locator('#inspect-modal')).toBeVisible();
    await expect(page.locator('#inspect-body .inspect-block').first()).toBeVisible();
  }
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  // Shared header toggle + the app's auto-built validity table both signal the
  // SPA has mounted and the sample network has been computed.
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#validity-output table')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemos(page);
  await killMotion(page);
  await openAllDetails(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await killMotion(page);
  await openAllDetails(page);
  await scan(page);
});
