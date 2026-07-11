// Headless smoke test — desktop + mobile viewports, real interactions.
// Run after `npm run preview` is serving on http://localhost:4173.
import { chromium, devices } from 'playwright';

const URL = 'http://localhost:4173/crypto-lab-web-of-trust/';

function assert(cond, msg) {
	if (!cond) {
		console.error('FAIL:', msg);
		process.exitCode = 1;
	} else {
		console.log('ok  :', msg);
	}
}

async function buildNetwork(page) {
	await page.click('#build-btn');
	await page.waitForFunction(
		() => /Generated \d+ keypairs/.test(document.querySelector('#build-status')?.textContent ?? ''),
		{ timeout: 10000 },
	);
}

async function run(label, deviceOpts) {
	console.log(`\n=== ${label} ===`);
	const browser = await chromium.launch();
	const ctx = await browser.newContext(deviceOpts ?? {});
	const page = await ctx.newPage();

	const errors = [];
	page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
	page.on('console', (m) => {
		if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
	});

	await page.goto(URL, { waitUntil: 'networkidle' });

	const h1 = await page.locator('h1').first().textContent();
	assert(h1?.trim() === 'Web of Trust', `h1 reads "Web of Trust" (got "${h1}")`);

	const skip = await page.locator('a.skip-link').first().textContent();
	assert(skip?.trim() === 'Skip to content', 'skip link present');

	// The shared crypto-lab header hides the in-page #theme-toggle and provides
	// its own #cl-theme-toggle in the top bar — test that one.
	const themeBtn = page.locator('#cl-theme-toggle');
	await themeBtn.waitFor();
	const themeBefore = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
	await themeBtn.click();
	const themeAfter = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
	assert(themeBefore !== themeAfter, `theme toggle flips data-theme (${themeBefore} → ${themeAfter})`);
	assert(themeAfter === 'light' || themeAfter === 'dark', `data-theme set (${themeAfter})`);
	await themeBtn.click(); // restore

	// Build the sample network
	await buildNetwork(page);
	const identityCount = await page.locator('.identity-card').count();
	assert(identityCount === 9, `9 identities after build (got ${identityCount})`);
	const meCard = await page.locator('.identity-card--me').count();
	assert(meCard === 1, `exactly one "you" card (got ${meCard})`);

	// Auto-recompute kicks in after build — wait for validity table
	await page.waitForFunction(() => document.querySelectorAll('.validity-row').length > 0);
	const validRows = await page.locator('.validity-row--valid').count();
	const invalidRows = await page.locator('.validity-row--invalid').count();
	assert(validRows >= 6, `>=6 valid keys in baseline (got ${validRows})`);
	assert(invalidRows >= 2, `>=2 invalid keys in baseline — Heretic, Stranger (got ${invalidRows})`);

	// Trust radiogroup: arrow-key navigation
	const aliceGroup = page.locator('.trust-row[data-name="Alice"] .trust-row-buttons');
	await aliceGroup.waitFor();
	const activePill = aliceGroup.locator('.trust-pill[tabindex="0"]');
	await activePill.focus();
	const beforeLevel = await activePill.getAttribute('data-level');
	await page.keyboard.press('ArrowRight');
	const afterLevel = await page.evaluate(
		() => document.activeElement?.getAttribute('data-level') ?? '',
	);
	assert(beforeLevel !== afterLevel, `ArrowRight moves focus to next trust pill (${beforeLevel} → ${afterLevel})`);
	const aliceTrust = await page.evaluate(() => {
		const btn = document.querySelector('.trust-row[data-name="Alice"] .trust-pill.is-active');
		return btn?.getAttribute('data-level') ?? '';
	});
	assert(aliceTrust === afterLevel, `ArrowRight also selects (Alice now ${aliceTrust})`);
	await page.keyboard.press('Home');
	const homeLevel = await page.evaluate(
		() => document.activeElement?.getAttribute('data-level') ?? '',
	);
	assert(homeLevel === 'full', `Home jumps to first pill (got ${homeLevel})`);

	// Forged certification scenario — Stranger must stay invalid
	await page.click('#scn-forge');
	await page.waitForTimeout(300);
	const forgeLog = await page.locator('.wot-log-line').first().textContent();
	assert(/Forged certification rejected/.test(forgeLog ?? ''), 'forged cert was rejected by signature check');
	const strangerRow = page.locator('.validity-row').filter({ hasText: 'Stranger' });
	const strangerBadge = await strangerRow.locator('.scenario-status--invalid').count();
	assert(strangerBadge === 1, 'Stranger stays INVALID after forged cert');

	// Over-trust Eve → Heretic should flip valid
	await page.click('#scn-overtrust');
	await page.waitForTimeout(300);
	const heretic = page.locator('.validity-row').filter({ hasText: 'Heretic' });
	const hereticValid = await heretic.locator('.scenario-status--valid').count();
	assert(hereticValid === 1, 'Heretic becomes valid when Eve is over-trusted');

	// Depth cutoff
	await page.click('#scn-depth');
	await page.waitForTimeout(300);
	const depthLog = await page.locator('.wot-log-line').first().textContent();
	assert(/maxDepth = 1/.test(depthLog ?? ''), 'depth-cutoff scenario logs the new maxDepth');

	// Reset baseline
	await page.click('#scn-reset');
	await page.waitForFunction(
		() => document.querySelectorAll('.validity-row--valid').length >= 6,
		{ timeout: 10000 },
	);

	// SVG trust graph rendered (Item 1)
	const svgNodes = await page.locator('.graph-node').count();
	assert(svgNodes >= 9, `SVG graph rendered with >=9 nodes (got ${svgNodes})`);
	const svgEdges = await page.locator('.graph-link').count();
	assert(svgEdges >= 9, `SVG graph has >=9 edges (got ${svgEdges})`);

	// Trust-path tracing: click Frank's node, trace explains the whole chain
	const frankNode = page.locator('.graph-node-group[data-name="Frank"]');
	await frankNode.scrollIntoViewIfNeeded();
	await frankNode.click();
	await page.waitForFunction(
		() => /Frank/.test(document.querySelector('#trace-panel')?.textContent ?? ''),
		{ timeout: 5000 },
	);
	const traceText = await page.locator('#trace-panel').textContent();
	assert(/why is Frank/i.test(traceText ?? ''), 'trace panel explains why Frank is valid');
	assert(/depth 0/.test(traceText ?? ''), 'trace walks back to the depth-0 anchor (You)');
	const tracedEdges = await page.locator('.graph-link--traced').count();
	assert(tracedEdges >= 4, `trace highlights the introduction-chain edges (got ${tracedEdges})`);
	await page.click('[data-action="trace-clear"]');
	await page.waitForFunction(() => document.querySelectorAll('.graph-link--traced').length === 0);
	const hintVisible = await page.locator('#trace-panel .trace-hint').count();
	assert(hintVisible === 1, 'clearing the trace restores the hint');

	// Item 4: cert payload inspector opens modal
	const firstInspectBtn = page.locator('[data-action="inspect"]').first();
	await firstInspectBtn.scrollIntoViewIfNeeded();
	await firstInspectBtn.click();
	await page.waitForFunction(() => document.querySelector('#inspect-modal')?.open === true, { timeout: 3000 });
	const payloadVisible = await page.locator('#inspect-body .inspect-block').first().textContent();
	assert(/certify:/.test(payloadVisible ?? ''), 'inspect modal shows certify: payload bytes');
	const hexBlocks = await page.locator('#inspect-body .inspect-block--hex').count();
	assert(hexBlocks >= 2, `inspect modal renders hex blocks for payload and signature (got ${hexBlocks})`);
	await page.click('#inspect-modal .inspect-close');
	await page.waitForFunction(() => document.querySelector('#inspect-modal')?.open !== true);

	// Reset to a clean baseline so the revocation assertions aren't
	// confused by depth-cutoff state from the previous scenario.
	await page.click('#scn-reset');
	await page.waitForFunction(
		() => document.querySelectorAll('.validity-row--valid').length >= 6,
		{ timeout: 10000 },
	);

	// Item 2: revoke a certification — Eve was signed by Alice; revoke that
	// cert and Eve must become invalid on recompute.
	const aliceEveRevoke = page
		.locator('.cert-row')
		.filter({ has: page.locator('.cert-row-signer', { hasText: /^Alice$/ }) })
		.filter({ has: page.locator('.cert-row-subject', { hasText: /^Eve$/ }) })
		.locator('[data-action="revoke-cert"]');
	await aliceEveRevoke.scrollIntoViewIfNeeded();
	await aliceEveRevoke.click();
	await page.waitForTimeout(400);
	const eveValidityRow = page
		.locator('.validity-row')
		.filter({ has: page.locator('td strong', { hasText: /^Eve$/ }) });
	const eveInvalid = await eveValidityRow.locator('.scenario-status--invalid').count();
	assert(eveInvalid === 1, 'after revoking Alice→Eve, Eve is INVALID');

	// Item 2: revoke a key (Bob) → Bob's signatures are dropped, but Bob
	// himself stays valid because You signed Bob directly.
	const bobRevoke = page.locator('.identity-card').filter({ hasText: 'Bob' }).locator('[data-action="revoke-key"]');
	await bobRevoke.scrollIntoViewIfNeeded();
	await bobRevoke.click();
	await page.waitForTimeout(400);
	const bobCard = page.locator('.identity-card--revoked').filter({ hasText: 'Bob' });
	assert((await bobCard.count()) === 1, 'Bob shows up as revoked after self-revocation');

	// Item 3: SKS-style flood scenario. Reset first so the assertions start
	// clean (revoked Bob / Eve carry over otherwise).
	await page.click('#scn-reset');
	await page.waitForFunction(
		() => document.querySelectorAll('.validity-row--valid').length >= 6,
		{ timeout: 10000 },
	);
	await page.click('#scn-flood');
	await page.waitForFunction(
		() => document.querySelectorAll('.identity-card').length >= 50,
		{ timeout: 30000 },
	);
	const totalIdents = await page.locator('.identity-card').count();
	assert(totalIdents >= 59, `flood added >=50 identities (total now ${totalIdents})`);
	const floodLog = await page.locator('.wot-log-line').first().textContent();
	assert(/STAYS INVALID/.test(floodLog ?? ''), 'flood log explains Stranger stays invalid');
	const strangerAfterFlood = page.locator('.validity-row').filter({ hasText: 'Stranger' }).first();
	const strangerStillInvalid = await strangerAfterFlood.locator('.scenario-status--invalid').count();
	assert(strangerStillInvalid === 1, 'Stranger remains INVALID after 50-signature flood');

	// Flood collapse: trust controls and validity table must stay legible
	const floodTrustRows = await page.locator('.trust-row[data-name^="Flood"]').count();
	assert(floodTrustRows === 0, 'flood signers are hidden from trust controls');
	const floodNote = await page.locator('.wot-flood-note').count();
	assert(floodNote === 1, 'trust controls explain the hidden flood signers');
	const floodSummaryRows = await page.locator('.validity-row--flood').count();
	assert(floodSummaryRows === 1, 'validity table collapses flooders into one summary row');
	const validityRowCount = await page.locator('.validity-row').count();
	assert(validityRowCount <= 12, `validity table stays legible after flood (got ${validityRowCount} rows)`);

	// Reset before tail-of-page assertions
	await page.click('#scn-reset');
	await page.waitForFunction(
		() => document.querySelectorAll('.validity-row--valid').length >= 6,
		{ timeout: 10000 },
	);

	// Concept cards / comparison table
	const compareRows = await page.locator('#concepts table tbody tr').count();
	assert(compareRows >= 5, `WoT-vs-PKI comparison has >=5 rows (got ${compareRows})`);
	const conceptCards = await page.locator('#concepts .panel-card').count();
	assert(conceptCards >= 4, `concept cards present (got ${conceptCards})`);
	const realCards = await page.locator('#realworld .panel-card').count();
	assert(realCards >= 8, `real-world + pitfalls cards present (got ${realCards})`);

	// Guided tour present in the scenarios section
	const tourSummary = await page.locator('.guided-tour summary').textContent();
	assert(/Guided tour/.test(tourSummary ?? ''), 'guided tour details block present');

	// Scripture footer is last visible paragraph (excluding the inspect
	// modal, which is a sibling of the footer in DOM order but lives in a
	// <dialog> and is only shown on demand).
	const lastText = await page.evaluate(() => {
		const ps = Array.from(document.querySelectorAll('p')).filter((p) => !p.closest('dialog'));
		return ps[ps.length - 1]?.textContent?.trim() ?? '';
	});
	assert(/glory of God/.test(lastText), 'scripture footer is last paragraph');

	// No horizontal overflow
	const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
	const clientWidth = await page.evaluate(() => document.documentElement.clientWidth);
	assert(scrollWidth <= clientWidth + 1, `no horizontal overflow (sw=${scrollWidth} cw=${clientWidth})`);

	// Touch-target check for trust pills (WCAG 2.5.5)
	const pillBox = await page.locator('.trust-pill').first().boundingBox();
	if (pillBox) {
		assert(pillBox.height >= 44 && pillBox.width >= 44, `trust pills >=44x44 (got ${Math.round(pillBox.width)}x${Math.round(pillBox.height)})`);
	}

	if (errors.length) {
		console.error('CONSOLE / PAGE ERRORS:');
		errors.forEach((e) => console.error('  ' + e));
		process.exitCode = 1;
	} else {
		console.log('ok  : no console errors');
	}

	await browser.close();
}

await run('desktop 1280x800', { viewport: { width: 1280, height: 800 } });
await run('mobile iPhone 12', devices['iPhone 12']);
await run('narrow 360x740', { viewport: { width: 360, height: 740 } });

if (process.exitCode) {
	console.error('\nSMOKE: FAIL');
} else {
	console.log('\nSMOKE: PASS');
}
