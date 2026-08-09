import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaces
 *     pushed `*{opacity:1!important}` through `addStyleTag` twice per test and
 *     stripped every `[hidden]`. Opacity is not incidental in this lab: the
 *     trust-path trace dims whole off-path node groups, revoked identity cards
 *     and certificate rows sit at `.7`, and the fingerprint tag was at `.75`.
 *     The injection made all of it opaque and measured a page nobody is shown.
 *
 *  2. IT DROVE SIX SCENARIOS AND SCANNED ONCE, AT THE END — AND THE LAST ONE
 *     WAS RESET. The six scenario buttons were clicked in a `for` loop with no
 *     scan between them, ending on `#scn-reset`, so the five renderings it
 *     built (forged, orphaned, over-trusted, depth-cut, flooded) were each
 *     destroyed by the next click before anything measured them. The single
 *     end-of-run scan saw the reset state. Every scenario is scanned here in
 *     its own right.
 *
 *  3. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST. Unlike most labs in this
 *     fleet there IS real content at first paint — the sample keyring is built
 *     and validity computed on load — so `boot` asserts the table, the keyring
 *     and the graph, and asserts that the trace, the modal and the scenario
 *     damage are NOT there yet.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * reduced-motion block collapses durations to 0.01ms rather than setting
 * `animation: none`, which is the safe form — a cancelled animation loses its
 * end state, a zero-length one still lands on it.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page, because a silent no-op there would mean
 * an emulation that silently did nothing would leave the gate certifying a
 * different rendering than the one it claims to.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is built by `src/ui.ts` into an empty `#app`, and it builds
  // the sample keyring and computes validity on load — so unlike most labs in
  // this fleet there IS content at first paint, and the scan of it is real.
  await expect(page.locator('#validity-output table')).toBeVisible();
  await expect(page.locator('#keyring-list .identity-card').first()).toBeVisible();
  await expect(page.locator('.graph-node-group[data-name]').first()).toBeVisible();
  // What does not exist yet: any scenario damage, any trace, any modal.
  await expect(page.locator('.graph-svg--tracing')).toHaveCount(0);
  // The <dialog> is built up front and lives in the DOM shut, so its presence
  // proves nothing — its openness is the thing to assert.
  await expect(page.locator('#inspect-modal')).toBeHidden();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it draws a force-directed trust graph as an SVG, prints
 * a validity table with one row per key, and opens a modal holding two hex
 * dumps of a signature payload.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has the same decoy: the
    // validity table sits in an `overflow-x: auto` `.table-shell`, and the
    // modal's hex dumps in their own scrollers.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    almost every tinted surface is a `color-mix()` axe declines to resolve.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish — including `aria-prohibited-attr`, which is where an `aria-label`
 *    on a role-less div hides, a defect that never reaches the violations array
 *    at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}


/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Three things shape this drive:
 *
 *  - THE SCENARIOS OVERWRITE EACH OTHER. The gate this replaces clicked all six
 *    scenario buttons in a `for` loop with no scan between them, ending on
 *    `#scn-reset` — so five of the six renderings it built were destroyed
 *    before anything measured them, and the single end-of-run scan saw the
 *    reset state only. Forged certificates, orphaned keys, over-trust,
 *    depth-cut and flooding each recolour the graph, the validity table and the
 *    log differently; each is scanned here in its own right.
 *
 *  - THE TRACE STATE DIMS THE WHOLE GRAPH. Clicking a node puts
 *    `.graph-svg--tracing` on the SVG, which drops every off-path node group to
 *    `opacity: .25` and every off-path link to `.12`. That is the state where
 *    this lab's contrast is least likely to hold, and it is exactly what
 *    `opacity: 1 !important` erased. Revoked identity cards and certificate
 *    rows are a second case, at `.7`.
 *
 *  - THE MODAL IS A `<dialog>`. It is opened and scanned with the page behind
 *    it inert, then closed and the page scanned again — a `<dialog>` changes
 *    what is exposed to assistive technology, so both sides matter.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint');

  await page.locator('a.cl-skip-link').focus();
  await scanAt('skip link focused');

  // ── The five failure scenarios, each measured before the next replaces it ─
  for (const [id, label] of [
    ['#scn-forge', 'forged certificate injected'],
    ['#scn-orphan', 'key orphaned'],
    ['#scn-overtrust', 'over-trust introduced'],
    ['#scn-depth', 'trust depth cut'],
    ['#scn-flood', 'certificate flood'],
  ] as const) {
    await page.locator(id).click();
    await expect(page.locator('#scenario-log .wot-log-line').first()).toBeVisible();
    await expect(page.locator('#validity-output table')).toBeVisible();
    await scanAt(label);
  }

  await page.locator('#scn-reset').click();
  await expect(page.locator('#validity-output table')).toBeVisible();
  await scanAt('scenarios reset');

  // ── The trust-path trace: the state that dims everything off the path ────
  const node = page.locator('.graph-node-group[data-name]').first();
  await node.click();
  await expect(page.locator('.graph-svg--tracing')).toBeVisible();
  await expect(page.locator('#trace-panel')).toBeVisible();
  await scanAt('trust path traced, off-path graph dimmed');

  await node.click();
  await expect(page.locator('.graph-svg--tracing')).toHaveCount(0);
  await scanAt('trace cleared');

  // ── The certification payload modal ──────────────────────────────────────
  const inspect = page.locator('[data-action="inspect"]').first();
  await expect(inspect).toBeVisible();
  await inspect.click();
  await expect(page.locator('#inspect-modal')).toBeVisible();
  await expect(page.locator('#inspect-body .inspect-block').first()).toBeVisible();
  await scanAt('certification payload modal open');

  await page.keyboard.press('Escape');
  await expect(page.locator('#inspect-modal')).toBeHidden();
  await scanAt('modal closed, page live again');

  // ── The trust policy, recomputed at both ends of its range ───────────────
  await page.locator('#policy-marginals').fill('1');
  await page.locator('#policy-depth').fill('1');
  await page.locator('#recompute-btn').click();
  await expect(page.locator('#validity-output table')).toBeVisible();
  await scanAt('policy tightened to 1 marginal, depth 1');

  await page.locator('#policy-marginals').fill('10');
  await page.locator('#policy-depth').fill('10');
  await page.locator('#recompute-btn').click();
  await expect(page.locator('#validity-output table')).toBeVisible();
  await scanAt('policy loosened to 10 marginals, depth 10');

  // ── Signing a new certification, and the refusal path ────────────────────
  await page.locator('#custom-cert-btn').click();
  await expect(page.locator('#custom-cert-msg')).not.toBeEmpty();
  await scanAt('custom certification signed');

  // Clicking it a second time with the same pair is the duplicate/refusal
  // branch — a different message tone, and the only place it renders.
  await page.locator('#custom-cert-btn').click();
  await expect(page.locator('#custom-cert-msg')).not.toBeEmpty();
  await scanAt('custom certification repeated');

  // ── Rebuilding the sample network from scratch ───────────────────────────
  await page.locator('#build-btn').click();
  await expect(page.locator('#build-status')).not.toBeEmpty();
  await expect(page.locator('#keyring-list .identity-card').first()).toBeVisible();
  await scanAt('sample network rebuilt');

  await page.locator('#compute-btn').click();
  await expect(page.locator('#validity-output table')).toBeVisible();
  await scanAt('web of trust recomputed');
}
