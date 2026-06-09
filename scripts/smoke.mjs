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

	const themeBtn = page.locator('#theme-toggle');
	await themeBtn.waitFor();
	const initLabel = await themeBtn.getAttribute('aria-label');
	await themeBtn.click();
	const afterLabel = await themeBtn.getAttribute('aria-label');
	assert(initLabel !== afterLabel, `theme toggle flips aria-label (${initLabel} → ${afterLabel})`);
	const theme = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
	assert(theme === 'light' || theme === 'dark', `data-theme set (${theme})`);
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

	// Concept cards / comparison table
	const compareRows = await page.locator('#concepts table tbody tr').count();
	assert(compareRows >= 5, `WoT-vs-PKI comparison has >=5 rows (got ${compareRows})`);
	const conceptCards = await page.locator('#concepts .panel-card').count();
	assert(conceptCards >= 4, `concept cards present (got ${conceptCards})`);
	const realCards = await page.locator('#realworld .panel-card').count();
	assert(realCards >= 8, `real-world + pitfalls cards present (got ${realCards})`);

	// Scripture footer is last visible paragraph
	const lastText = await page.evaluate(() => {
		const all = document.querySelectorAll('p');
		return all[all.length - 1]?.textContent?.trim() ?? '';
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
