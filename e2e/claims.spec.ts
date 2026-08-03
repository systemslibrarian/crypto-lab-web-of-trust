import { expect, test, type Page, type Locator } from '@playwright/test';

/**
 * Functional claims gate for the Web of Trust demo.
 *
 * The a11y spec proves the page is reachable; this one proves the page is
 * RIGHT. Every headline verdict the UI prints — VALID / INVALID / REVOKED, the
 * depth it was validated at, the marginal quorum arithmetic — is re-derived
 * here from inputs read back out of the DOM (the certification list, the
 * owner-trust pills, the policy inputs, the revocation state) and compared to
 * what the page rendered. Nothing below trusts a hardcoded expected table: the
 * trust walk is re-implemented in this file and run against the page's own
 * declared inputs, so an engine change the UI still reports confidently shows
 * up here as a mismatch.
 *
 * Every failure path the demo offers is exercised: forged certification,
 * orphan key, over-trusted introducer, depth cutoff, SKS-style signature
 * flood, certification revocation and key revocation. Each is asserted to
 * reach the failing state AND to say why.
 */

const ME = 'You';

type Level = 'full' | 'marginal' | 'none';
type Verdict = 'VALID' | 'INVALID' | 'REVOKED';

interface CertRow {
  signer: string;
  subject: string;
  forged: boolean;
  revoked: boolean;
}

interface TableRow {
  name: string;
  verdict: string;
  depth: string;
  reason: string;
}

interface Snapshot {
  names: string[];
  revokedKeys: string[];
  certs: CertRow[];
  trust: Record<string, string>;
  policy: { marginals: number; maxDepth: number };
  rows: TableRow[];
  graphNodes: number;
  graphLinks: number;
  buildStatus: string;
  algoName: string;
}

/**
 * Read every input and every output of the trust computation in ONE evaluate,
 * so the derived expectation and the rendered table describe the same instant.
 */
async function snapshot(page: Page): Promise<Snapshot> {
  return page.evaluate(() => {
    const text = (el: Element | null | undefined): string => (el?.textContent ?? '').trim();
    const names = Array.from(document.querySelectorAll('.identity-card')).map((c) =>
      text(c.querySelector('.identity-name')),
    );
    const revokedKeys = Array.from(document.querySelectorAll('.identity-card--revoked')).map((c) =>
      text(c.querySelector('.identity-name')),
    );
    const certs = Array.from(document.querySelectorAll('.cert-row')).map((r) => ({
      signer: text(r.querySelector('.cert-row-signer')),
      subject: text(r.querySelector('.cert-row-subject')),
      forged: r.classList.contains('cert-row--forged'),
      revoked: r.classList.contains('cert-row--revoked'),
    }));
    const trust: Record<string, string> = {};
    for (const row of Array.from(document.querySelectorAll<HTMLElement>('.trust-row'))) {
      const active = row.querySelector<HTMLElement>('.trust-pill.is-active');
      trust[row.dataset.name ?? ''] = active?.dataset.level ?? 'none';
    }
    const rows = Array.from(document.querySelectorAll('.validity-row')).map((r) => {
      const cells = Array.from(r.querySelectorAll('td')).map((c) => text(c).replace(/\s+/g, ' '));
      return {
        name: cells[0] ?? '',
        verdict: cells[1] ?? '',
        depth: cells[2] ?? '',
        reason: cells[3] ?? '',
      };
    });
    return {
      names,
      revokedKeys,
      certs,
      trust,
      policy: {
        marginals: Number((document.querySelector('#policy-marginals') as HTMLInputElement).value),
        maxDepth: Number((document.querySelector('#policy-depth') as HTMLInputElement).value),
      },
      rows,
      graphNodes: document.querySelectorAll('.graph-node').length,
      graphLinks: document.querySelectorAll('.graph-link').length,
      buildStatus: text(document.querySelector('#build-status')),
      algoName: text(document.querySelector('#algo-name')),
    };
  });
}

interface Derived {
  valid: boolean;
  depth: number;
  revoked: boolean;
  viaFull: string[];
  viaMarginal: string[];
}

/**
 * An independent implementation of the GnuPG-style trust walk, fed ONLY by
 * what the page says its inputs are. Certifications the page marks forged or
 * revoked are dropped (a forged signature does not verify; a retracted edge is
 * out of the walk), as are all certifications made by a revoked key. Owner
 * trust for anyone with no trust row — the flood swarm — is `none`, exactly as
 * the page's own note claims.
 */
function deriveValidity(s: Snapshot): Map<string, Derived> {
  const revoked = new Set(s.revokedKeys);
  const usable = s.certs.filter((c) => !c.forged && !c.revoked && !revoked.has(c.signer));
  const trustOf = (name: string): Level =>
    name === ME ? 'full' : ((s.trust[name] as Level | undefined) ?? 'none');

  const result = new Map<string, Derived>();
  for (const name of revoked) {
    result.set(name, { valid: false, depth: -1, revoked: true, viaFull: [], viaMarginal: [] });
  }
  if (!revoked.has(ME)) {
    result.set(ME, { valid: true, depth: 0, revoked: false, viaFull: [], viaMarginal: [] });
  }

  for (let depth = 1; depth <= s.policy.maxDepth; depth++) {
    const validBefore = new Set(
      [...result.entries()].filter(([, v]) => v.valid).map(([name]) => name),
    );
    let changed = false;
    for (const subject of s.names) {
      if (result.get(subject)?.valid) continue;
      if (revoked.has(subject)) continue;
      const fulls = new Set<string>();
      const marginals = new Set<string>();
      for (const c of usable) {
        if (c.subject !== subject) continue;
        if (!validBefore.has(c.signer)) continue;
        const t = trustOf(c.signer);
        if (t === 'full') fulls.add(c.signer);
        else if (t === 'marginal') marginals.add(c.signer);
      }
      if (fulls.size >= 1 || marginals.size >= s.policy.marginals) {
        result.set(subject, {
          valid: true,
          depth,
          revoked: false,
          viaFull: [...fulls],
          viaMarginal: [...marginals],
        });
        changed = true;
      }
    }
    if (!changed) break;
  }

  for (const name of s.names) {
    if (!result.has(name)) {
      result.set(name, { valid: false, depth: -1, revoked: false, viaFull: [], viaMarginal: [] });
    }
  }
  return result;
}

function expectedVerdict(d: Derived): Verdict {
  if (d.valid) return 'VALID';
  return d.revoked ? 'REVOKED' : 'INVALID';
}

/** Rows the page renders for the named identities (the flood swarm is collapsed). */
function namedRows(s: Snapshot): TableRow[] {
  return s.rows.filter((r) => !r.name.startsWith('Flood'));
}

function rowByName(s: Snapshot, name: string): TableRow {
  const row = namedRows(s).find((r) => r.name === name);
  expect(row, `no validity row rendered for ${name}`).toBeTruthy();
  return row!;
}

function compare(s: Snapshot): string[] {
  const derived = deriveValidity(s);
  const problems: string[] = [];
  for (const row of namedRows(s)) {
    const d = derived.get(row.name);
    if (!d) {
      problems.push(`${row.name}: rendered but not in the derived walk`);
      continue;
    }
    // Exact, not substring: "INVALID" contains "VALID".
    const wantVerdict = expectedVerdict(d);
    if (row.verdict !== wantVerdict) {
      problems.push(`${row.name}: page says "${row.verdict}", derivation says "${wantVerdict}"`);
    }
    const wantDepth = d.valid ? String(d.depth) : '—';
    if (row.depth !== wantDepth) {
      problems.push(`${row.name}: page depth "${row.depth}", derived depth "${wantDepth}"`);
    }
  }
  const expectedNames = s.names.filter((n) => !n.startsWith('Flood'));
  const renderedNames = namedRows(s).map((r) => r.name);
  if (renderedNames.join(',') !== expectedNames.join(',')) {
    problems.push(
      `table lists [${renderedNames.join(',')}], keyring holds [${expectedNames.join(',')}]`,
    );
  }
  return problems;
}

/**
 * Poll until the page's verdict table agrees with the walk derived from the
 * page's own inputs. Polling absorbs the async recompute without weakening the
 * assertion: a genuinely wrong verdict never becomes right.
 */
async function expectVerdictsSelfConsistent(page: Page, label: string): Promise<void> {
  await expect
    .poll(async () => compare(await snapshot(page)), { timeout: 15_000, message: label })
    .toEqual([]);
}

/** The one validity row whose key cell is exactly `name`. */
function rowFor(page: Page, name: string): Locator {
  return page
    .locator('.validity-row')
    .filter({ has: page.locator('td strong', { hasText: new RegExp(`^${name}$`) }) });
}

/** Assert the rendered badge for `name` is exactly the expected verdict. */
async function expectVerdict(page: Page, name: string, want: Verdict): Promise<void> {
  await expect(rowFor(page, name).locator('td').nth(1)).toHaveText(want);
}

async function traceText(page: Page, name: string): Promise<string> {
  await page.locator(`.trace-btn[data-name="${name}"]`).click();
  await expect(page.locator('#trace-panel .trace-title')).toContainText(`why is ${name}`);
  return ((await page.locator('#trace-panel').textContent()) ?? '').replace(/\s+/g, ' ');
}

async function clearTrace(page: Page): Promise<void> {
  await page.locator('[data-action="trace-clear"]').click();
  await expect(page.locator('#trace-panel .trace-hint')).toBeVisible();
}

/** Pull the first captured integer out of a DOM string, e.g. "(need 3)" -> 3. */
function numOf(text: string, re: RegExp): number {
  const m = text.match(re);
  expect(m, `expected ${re} to match in: ${text}`).not.toBeNull();
  return Number(m![1]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  // The sample network builds itself on load; the build status counter is the
  // signal that the keypairs exist and the first computation has run.
  await expect(page.locator('#build-status')).toContainText(/Generated \d+ keypairs/);
  await expect(page.locator('.validity-row').first()).toBeVisible();
});

test('baseline verdicts match a trust walk re-derived from the page inputs', async ({ page }) => {
  await expectVerdictsSelfConsistent(page, 'baseline');

  const s = await snapshot(page);
  // The demo's own headline: nine identities, seven valid from your point of
  // view, two outside the trust frontier.
  expect(s.names).toEqual([
    'You',
    'Alice',
    'Bob',
    'Carol',
    'Dave',
    'Eve',
    'Frank',
    'Heretic',
    'Stranger',
  ]);
  await expect(page.locator('.validity-row--valid')).toHaveCount(7);
  await expect(page.locator('.validity-row--invalid')).toHaveCount(2);

  // GnuPG defaults, as the README claims.
  expect(s.policy).toEqual({ marginals: 3, maxDepth: 5 });

  // The two invalid keys fail for DIFFERENT stated reasons: Heretic has a
  // signer you do not trust, Stranger has no signer at all.
  expect(rowByName(s, 'Heretic').reason).toContain('Signed by Eve');
  expect(rowByName(s, 'Stranger').reason).toContain('No certifications');
  await expectVerdict(page, 'Heretic', 'INVALID');
  await expectVerdict(page, 'Stranger', 'INVALID');
});

test("the marginal quorum in Frank's verdict matches the certifications on file", async ({
  page,
}) => {
  const s = await snapshot(page);
  const frankRow = rowByName(s, 'Frank');

  // Count, from the certification list and the trust pills, how many
  // marginally-trusted signers actually certified Frank.
  const marginalSigners = s.certs
    .filter((c) => c.subject === 'Frank' && !c.forged && !c.revoked)
    .map((c) => c.signer)
    .filter((signer, i, arr) => arr.indexOf(signer) === i)
    .filter((signer) => s.trust[signer] === 'marginal');
  expect([...marginalSigners].sort()).toEqual(['Bob', 'Carol', 'Dave']);

  // The rendered reason must quote that same count, and the same quorum as the
  // policy input.
  expect(numOf(frankRow.reason, /Signed by (\d+) marginally-trusted/)).toBe(marginalSigners.length);
  expect(numOf(frankRow.reason, /\(need (\d+)\)/)).toBe(s.policy.marginals);
  expect(marginalSigners.length).toBeGreaterThanOrEqual(s.policy.marginals);
  await expectVerdict(page, 'Frank', 'VALID');
  expect(frankRow.depth).toBe('2');

  // The trace names those introducers individually and re-states the quorum.
  const trace = await traceText(page, 'Frank');
  for (const signer of marginalSigners) expect(trace).toContain(signer);
  expect(numOf(trace, /against a quorum of (\d+)/)).toBe(s.policy.marginals);
  expect(trace).toContain('depth 0, the ultimate anchor');

  // The highlighted chain is exactly the introduction edges: Bob/Carol/Dave to
  // Frank, plus You to each of them.
  await expect(page.locator('.graph-link--traced')).toHaveCount(marginalSigners.length * 2);
  await clearTrace(page);
  await expect(page.locator('.graph-link--traced')).toHaveCount(0);
});

test('keyring, graph and status counters all report the same network', async ({ page }) => {
  const s = await snapshot(page);
  expect(numOf(s.buildStatus, /Generated (\d+) keypairs/)).toBe(s.names.length);
  expect(s.buildStatus).toContain(s.algoName);
  expect(['Ed25519', 'ECDSA P-256']).toContain(s.algoName);

  // One graph node per key, one graph edge per certification on file.
  expect(s.graphNodes).toBe(s.names.length);
  expect(s.graphLinks).toBe(s.certs.length);
  expect(s.certs.length).toBe(9);

  // Every valid key sits exactly one hop past each of its introducers, and
  // every introducer is itself valid — the depth column has to be a chain.
  const derived = deriveValidity(s);
  for (const row of namedRows(s)) {
    if (row.verdict !== 'VALID' || row.name === ME) continue;
    const d = derived.get(row.name)!;
    expect([...d.viaFull, ...d.viaMarginal].length).toBeGreaterThan(0);
    for (const intro of [...d.viaFull, ...d.viaMarginal]) {
      expect(derived.get(intro)!.valid, `${intro} introduces ${row.name} but is not valid`).toBe(
        true,
      );
      expect(derived.get(intro)!.depth, `${intro} should sit one hop above ${row.name}`).toBe(
        d.depth - 1,
      );
    }
  }
});

test('breaking the quorum invalidates Frank, and lowering it brings him back', async ({ page }) => {
  // Drop Bob to owner-trust none: Frank now has 2 marginals against a quorum of 3.
  await page.locator('.trust-row[data-name="Bob"] .trust-pill[data-level="none"]').click();
  await expectVerdict(page, 'Frank', 'INVALID');
  await expectVerdictsSelfConsistent(page, 'Bob demoted to none');

  const trace = await traceText(page, 'Frank');
  // The trace must name the rule for EACH dead edge, not just the verdict.
  expect(trace).toContain('you assign Bob owner-trust none');
  expect(trace).toMatch(/Carol → Frank: counts 1 toward the marginal quorum of 3/);
  expect(trace).toMatch(/Dave → Frank: counts 1 toward the marginal quorum of 3/);
  await clearTrace(page);

  // Policy, not crypto, made that call: lower the quorum to 2 and Frank returns.
  await page.locator('#policy-marginals').fill('2');
  await page.locator('#recompute-btn').click();
  await expectVerdict(page, 'Frank', 'VALID');
  await expect(rowFor(page, 'Frank')).toContainText('need 2');
  await expectVerdictsSelfConsistent(page, 'marginalsNeeded lowered to 2');

  const after = await snapshot(page);
  expect(numOf(rowByName(after, 'Frank').reason, /Signed by (\d+) marginally-trusted/)).toBe(
    after.policy.marginals,
  );
});

test('a forged certification never validates its subject, whatever the trust settings say', async ({
  page,
}) => {
  const before = await snapshot(page);
  expect(before.trust['Alice']).toBe('full'); // the forger is FULLY trusted...

  await page.locator('#scn-forge').click();
  await expect(page.locator('#scenario-log')).toContainText('Forged certification rejected');
  await expect(page.locator('#scenario-log')).toContainText('signature failed to verify');
  await expect(page.locator('.cert-row--forged')).toHaveCount(1);

  // ...and Alice's own key is valid, so nothing but the failed signature check
  // is keeping Stranger out.
  await expectVerdict(page, 'Alice', 'VALID');
  await expectVerdict(page, 'Stranger', 'INVALID');
  await expectVerdictsSelfConsistent(page, 'after forged certification');

  const trace = await traceText(page, 'Stranger');
  expect(trace).toContain('the signature does not verify');
  expect(trace).toContain('crypto vetoes policy');
  await clearTrace(page);

  // The inspector must label the same certification as forged.
  const forgedIdx = (await snapshot(page)).certs.findIndex((c) => c.forged);
  await page.locator(`.cert-row[data-cert-idx="${forgedIdx}"] [data-action="inspect"]`).click();
  await expect(page.locator('#inspect-body')).toContainText('forged — signature will NOT verify');
  await page.locator('#inspect-modal .inspect-close').click();
});

test('the orphan key has no path at all, and the page says so', async ({ page }) => {
  await page.locator('#scn-orphan').click();
  await expect(page.locator('#scenario-log')).toContainText(
    'Stranger has no certifications from trusted introducers',
  );
  await expectVerdict(page, 'Stranger', 'INVALID');

  const trace = await traceText(page, 'Stranger');
  expect(trace).toContain('Nobody has certified Stranger');
  expect(trace).toContain('bootstrap problem');
});

test('the inspector shows the exact bytes that were signed', async ({ page }) => {
  const fingerprints = await page.evaluate(() =>
    Object.fromEntries(
      Array.from(document.querySelectorAll('.identity-card')).map((c) => [
        (c.querySelector('.identity-name')?.textContent ?? '').trim(),
        (c.querySelector('.identity-fp')?.textContent ?? '')
          .replace('short ID · 8 B', '')
          .replace(/\s+/g, '')
          .toLowerCase(),
      ]),
    ),
  );

  await page.locator('.cert-row[data-cert-idx="0"] [data-action="inspect"]').click();
  await expect(page.locator('#inspect-modal')).toBeVisible();
  const body = ((await page.locator('#inspect-body').textContent()) ?? '').replace(/\s+/g, ' ');

  // The payload is exactly `certify:<subject>:<subject fingerprint>` — with the
  // fingerprint read off the subject's own keyring card, not hardcoded.
  const subject = (
    await page.locator('.cert-row[data-cert-idx="0"] .cert-row-subject').textContent()
  )!.trim();
  const expectedPayload = `certify:${subject}:${fingerprints[subject]}`;
  expect(fingerprints[subject]).toMatch(/^[0-9a-f]{16}$/); // 8 bytes, as the page claims
  expect(body).toContain(expectedPayload);

  // The stated byte counts must match the bytes actually rendered.
  const payloadLen = numOf(body, /Signed payload \((\d+) bytes\)/);
  expect(payloadLen).toBe(new TextEncoder().encode(expectedPayload).length);

  const payloadHex = (await page
    .locator('#inspect-body .inspect-block--hex')
    .first()
    .textContent())!.replace(/\s+/g, '');
  const expectedHex = Array.from(new TextEncoder().encode(expectedPayload))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  expect(payloadHex).toBe(expectedHex);
  expect(payloadHex.length).toBe(payloadLen * 2);

  // The signature block is a real 64-byte signature rendered consistently.
  const sigLen = numOf(body, /Signature \((\d+) bytes\)/);
  expect(sigLen).toBe(64);
  const sigHex = (await page
    .locator('#inspect-body .inspect-block--hex')
    .nth(1)
    .textContent())!.replace(/\s+/g, '');
  expect(sigHex.length).toBe(sigLen * 2);
  await page.locator('#inspect-modal .inspect-close').click();
});

test('over-trusting one introducer validates the key only they signed', async ({ page }) => {
  await expectVerdict(page, 'Heretic', 'INVALID');
  const before = await snapshot(page);
  expect(before.trust['Eve']).toBe('none');
  expect(rowByName(before, 'Heretic').reason).toContain('Signed by Eve');

  await page.locator('#scn-overtrust').click();
  await expect(page.locator('#scenario-log')).toContainText('Eve is now fully trusted');
  await expectVerdict(page, 'Heretic', 'VALID');
  await expect(rowFor(page, 'Heretic')).toContainText('Signed by fully-trusted Eve');
  await expectVerdictsSelfConsistent(page, 'Eve over-trusted');

  const after = await snapshot(page);
  expect(after.trust['Eve']).toBe('full');
  // Heretic sits exactly one hop beyond Eve; the orphan key still has no path.
  expect(Number(rowByName(after, 'Heretic').depth)).toBe(Number(rowByName(after, 'Eve').depth) + 1);
  await expectVerdict(page, 'Stranger', 'INVALID');
});

test('cutting maxDepth to 1 drops exactly the keys further than one hop away', async ({ page }) => {
  const before = await snapshot(page);
  const deeperThanOne = namedRows(before)
    .filter((r) => r.verdict === 'VALID' && Number(r.depth) > 1)
    .map((r) => r.name);
  expect([...deeperThanOne].sort()).toEqual(['Eve', 'Frank']);

  await page.locator('#scn-depth').click();
  await expect(page.locator('#scenario-log')).toContainText('maxDepth = 1');
  await expect(page.locator('#policy-depth')).toHaveValue('1');
  await expectVerdictsSelfConsistent(page, 'maxDepth cut to 1');

  const after = await snapshot(page);
  for (const row of namedRows(after)) {
    if (row.verdict !== 'VALID') continue;
    expect(Number(row.depth), `${row.name} survived a depth-1 cut`).toBeLessThanOrEqual(1);
  }
  for (const name of deeperThanOne) {
    await expectVerdict(page, name, 'INVALID');
    await expect(page.locator('#scenario-log')).toContainText(name);
  }

  // The reason is the cap, not a missing or bad signature: the trace must name
  // the depth rule and the exact policy number.
  const trace = await traceText(page, 'Eve');
  expect(trace).toMatch(/would need depth 2 — beyond your maxDepth of 1/);
});

test('revoking one certification drops that edge and nothing else', async ({ page }) => {
  const certs = (await snapshot(page)).certs;
  const idx = certs.findIndex((c) => c.signer === 'Alice' && c.subject === 'Eve');
  expect(idx).toBeGreaterThanOrEqual(0);

  await page.locator(`.cert-row[data-cert-idx="${idx}"] [data-action="revoke-cert"]`).click();
  await expect(page.locator('#scenario-log')).toContainText('retracted their certification of Eve');
  await expect(page.locator('.cert-row--revoked')).toHaveCount(1);

  await expectVerdict(page, 'Eve', 'INVALID');
  // Frank's quorum is untouched, so a single retraction must not cascade.
  await expectVerdict(page, 'Frank', 'VALID');
  await expectVerdictsSelfConsistent(page, 'Alice retracted her certification of Eve');

  const trace = await traceText(page, 'Eve');
  expect(trace).toContain('Alice revoked this certification');
  expect(trace).toContain('dropped from the walk');
});

test('revoking a key retires it and stops its signatures counting', async ({ page }) => {
  await page
    .locator('.identity-card', { hasText: 'Bob' })
    .locator('[data-action="revoke-key"]')
    .click();
  await expect(page.locator('#scenario-log')).toContainText('Bob self-revoked their key');
  await expect(page.locator('.identity-card--revoked')).toHaveCount(1);

  // You personally signed Bob — and it still does not save him. RFC 4880 5.2.1.
  await expectVerdict(page, 'Bob', 'REVOKED');
  await expect(rowFor(page, 'Bob')).toContainText('a revoked key is not to be used');

  // Bob was one of Frank's three marginal introducers; losing him takes the
  // quorum from 3 to 2 and Frank falls out with it.
  await expectVerdict(page, 'Frank', 'INVALID');
  await expectVerdictsSelfConsistent(page, 'Bob key revoked');

  const frankTrace = await traceText(page, 'Frank');
  expect(frankTrace).toContain("Bob's key is revoked");
  expect(frankTrace).toContain('certifications from a revoked key no longer count');
  await clearTrace(page);

  // Regression: tracing the revoked key ITSELF used to fall through to the
  // "the trace and the engine disagree (bug)" branch, because the edge
  // You -> Bob is a perfectly good certification and only the SUBJECT's
  // revocation invalidates him. The trace must explain the revocation.
  const bobTrace = await traceText(page, 'Bob');
  expect(bobTrace).not.toContain('the trace and the engine disagree');
  expect(bobTrace).toContain('self-revoked');
  expect(bobTrace).toContain('RFC 4880');
});

test('an SKS-style flood of real signatures changes no verdict', async ({ page }) => {
  const before = await snapshot(page);
  const verdictsBefore = namedRows(before).map((r) => `${r.name}=${r.verdict}@${r.depth}`);

  await page.locator('#scn-flood').click();
  await expect(page.locator('.identity-card')).toHaveCount(before.names.length + 50, {
    timeout: 60_000,
  });
  await expect(page.locator('#scenario-log')).toContainText('STAYS INVALID');

  const after = await snapshot(page);
  const flooders = after.names.filter((n) => n.startsWith('Flood'));
  expect(flooders.length).toBe(50);
  // Every flood signature is real and every one certifies Stranger.
  const floodCerts = after.certs.filter((c) => c.signer.startsWith('Flood'));
  expect(floodCerts.length).toBe(flooders.length);
  expect(floodCerts.every((c) => c.subject === 'Stranger' && !c.forged)).toBe(true);
  // ...and not one of them is offered owner-trust, which is why none count.
  expect(Object.keys(after.trust).some((n) => n.startsWith('Flood'))).toBe(false);
  expect(numOf(await page.locator('.wot-flood-note').innerText(), /(\d+) flood signers hidden/)).toBe(
    flooders.length,
  );

  // The verdicts and depths are exactly what they were before the flood.
  expect(namedRows(after).map((r) => `${r.name}=${r.verdict}@${r.depth}`)).toEqual(verdictsBefore);
  await expectVerdictsSelfConsistent(page, 'after 50-signature flood');

  // The table collapses the swarm rather than growing unbounded.
  await expect(page.locator('.validity-row--flood')).toHaveCount(1);
  expect(after.rows.length).toBeLessThanOrEqual(12);
  await expect(page.locator('.validity-row--flood')).toContainText(
    `Flood00–Flood${flooders.length - 1}`,
  );

  const trace = await traceText(page, 'Stranger');
  expect(numOf(trace, /(\d+) flood signers → Stranger/)).toBe(flooders.length);
  expect(trace).toContain('every one of those signatures verifies');
  expect(trace).toContain('you assign none of the signers owner-trust');
});

test('the custom certification control is live: signing a stranger validates them', async ({
  page,
}) => {
  const before = await snapshot(page);
  await expectVerdict(page, 'Stranger', 'INVALID');

  await page.locator('#custom-signer').selectOption('You');
  await page.locator('#custom-subject').selectOption('Stranger');
  await page.locator('#custom-cert-btn').click();
  await expect(page.locator('#custom-cert-msg')).toHaveText("You signed Stranger's key.");

  await expectVerdict(page, 'Stranger', 'VALID');
  await expect(rowFor(page, 'Stranger')).toContainText('Signed by fully-trusted You');
  await expectVerdictsSelfConsistent(page, 'after a custom You -> Stranger certification');

  const after = await snapshot(page);
  expect(after.certs.length).toBe(before.certs.length + 1);
  expect(after.graphLinks).toBe(before.graphLinks + 1);
  expect(rowByName(after, 'Stranger').depth).toBe('1');
});

test('reset restores the baseline network after a scenario has mutated it', async ({ page }) => {
  await page.locator('#scn-overtrust').click();
  await expectVerdict(page, 'Heretic', 'VALID');

  await page.locator('#scn-reset').click();
  await expect(page.locator('#scenario-log')).toContainText('Baseline restored');
  await expect(page.locator('.validity-row--valid')).toHaveCount(7);

  const s = await snapshot(page);
  expect(s.trust['Eve']).toBe('none');
  expect(s.policy).toEqual({ marginals: 3, maxDepth: 5 });
  expect(s.certs.length).toBe(9);
  expect(s.certs.some((c) => c.forged || c.revoked)).toBe(false);
  await expectVerdict(page, 'Heretic', 'INVALID');
  await expectVerdictsSelfConsistent(page, 'after reset');
});
