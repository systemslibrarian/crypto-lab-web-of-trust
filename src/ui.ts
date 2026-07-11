// ui.ts — Web of Trust interactive UI.
//
// Mounts a single `mountApp(root)` that renders the whole demo. State (the
// Keyring instance, the owner-trust map, the policy, and the latest validity
// result) lives in a closure and is mutated by event handlers. Sections that
// react to state changes re-render their own container; the rest are static.

import {
	Keyring,
	certifyPayloadBytes,
	computeValidity,
	shortFp,
	signingAlgoName,
	type Certification,
	type KeyValidity,
	type TrustLevel,
	type TrustPolicy,
} from './engine.ts';
import {
	FAILURE_LESSONS,
	REAL_WORLD,
	TRUST_CONCEPTS,
	WOT_VS_PKI,
} from './data.ts';

function el<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	className?: string,
	html?: string,
): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	if (className) node.className = className;
	if (html !== undefined) node.innerHTML = html;
	return node;
}

const ME = 'You';

interface AppState {
	ring: Keyring;
	ownerTrust: Map<string, TrustLevel>;
	policy: TrustPolicy;
	validity: Map<string, KeyValidity> | null;
	built: boolean;
	// Key currently selected for trust-path tracing (graph node / table click),
	// or null when no trace is shown.
	traced: string | null;
	rerenderKeyring: () => void;
	rerenderTrust: () => void;
	rerenderValidity: () => void;
	rerenderScenarios: () => void;
	logScenario: (msg: string) => void;
	buildNow: () => Promise<void>;
}

function defaultOwnerTrust(): Map<string, TrustLevel> {
	const m = new Map<string, TrustLevel>();
	m.set('Alice', 'full');
	m.set('Bob', 'marginal');
	m.set('Carol', 'marginal');
	m.set('Dave', 'marginal');
	m.set('Eve', 'none');
	m.set('Frank', 'none');
	m.set('Heretic', 'none');
	m.set('Stranger', 'none');
	return m;
}

async function buildSampleNetwork(state: AppState): Promise<void> {
	const ring = new Keyring();
	const names = ['You', 'Alice', 'Bob', 'Carol', 'Dave', 'Eve', 'Frank', 'Heretic', 'Stranger'];
	for (const n of names) {
		await ring.createIdentity(n);
	}
	const edges: Array<[string, string]> = [
		['You', 'Alice'],
		['You', 'Bob'],
		['You', 'Carol'],
		['You', 'Dave'],
		['Alice', 'Eve'],
		['Bob', 'Frank'],
		['Carol', 'Frank'],
		['Dave', 'Frank'],
		['Eve', 'Heretic'],
	];
	for (const [s, t] of edges) {
		const r = await ring.certify(s, t);
		if ('error' in r) throw new Error(`Failed to certify ${s} -> ${t}: ${r.error}`);
	}
	state.ring = ring;
	state.ownerTrust = defaultOwnerTrust();
	state.policy = { marginalsNeeded: 3, maxDepth: 5 };
	state.validity = null;
	state.traced = null;
	state.built = true;
}

async function recompute(state: AppState): Promise<void> {
	if (!state.built) return;
	state.validity = await computeValidity(state.ring, {
		me: ME,
		ownerTrust: state.ownerTrust,
		policy: state.policy,
	});
	state.rerenderValidity();
}

// ---------- 1. Hero ----------------------------------------------------------

function renderHero(): HTMLElement {
	const hero = el('section', 'hero-panel');
	hero.innerHTML = `
		<button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to light mode">🌙</button>
		<div class="hero-copy">
			<p class="eyebrow">Trust · Web of Trust</p>
			<h1>Web of Trust</h1>
			<p class="hero-text">
				PKI trusts a central authority — a root CA that ships in your browser. PGP trusts
				<em>people</em>. You sign keys you have personally verified, and trust propagates
				through the social graph within limits you set. There is no root, no monopoly, and
				no single point of failure — and also no way to talk to a stranger nobody has
				vouched for. This demo runs the GnuPG trust computation on real Ed25519
				signatures (with an automatic ECDSA P-256 fallback) so you can build a keyring,
				assign trust, and watch the model decide which keys are valid from your point of
				view.
			</p>
			<details class="why-details">
				<summary>How is this different from a CA?</summary>
				<p>
					A CA is hierarchical: a small set of roots issues to intermediates, which
					issue to leaves. Your browser trusts the roots because the OS vendor put them
					there. The Web of Trust is a directed graph through people: <em>you</em>
					decide whose signatures count, and how much. A CA failure mints a trusted
					certificate for any name on the internet; a WoT failure validates whatever
					one careless introducer signs. The mechanism trades centralized risk for
					distributed responsibility.
				</p>
			</details>
		</div>
		<div class="hero-metric-card">
			<p class="hero-metric-label">At a glance</p>
			<p class="hero-metric-value">Real <span id="algo-name">${signingAlgoName()}</span> signatures · no central authority · you decide whom to trust</p>
			<p class="hero-metric-note">Every certification in this demo is a real cryptographic signature, verified before it counts. Forging one fails because the math fails, not because policy says so.</p>
		</div>
	`;
	return hero;
}

// ---------- 2. Keyring -------------------------------------------------------

function renderKeyringSection(state: AppState): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'keyring';
	section.setAttribute('aria-labelledby', 'keyring-heading');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 1</p>
				<h2 id="keyring-heading">The keyring</h2>
				<p class="panel-copy">Every identity here is a real keypair generated in your browser — a small social graph is created automatically when the page loads. <strong>Rebuild</strong> any time for fresh keys, or add your own certification below.</p>
			</div>
		</div>
		<div class="wot-actions">
			<button id="build-btn" class="tab-button" type="button">Rebuild sample network</button>
			<span id="build-status" class="wot-build-status"></span>
		</div>
		<div id="keyring-list" class="wot-keyring"></div>
		<div id="custom-cert" class="wot-custom-cert" hidden>
			<h3>Add a custom certification</h3>
			<p class="panel-copy">Pick a signer and a subject. The signer's private key (in this browser session) produces a real signature over the subject's name + fingerprint.</p>
			<div class="wot-cert-row">
				<label>
					<span>Signer</span>
					<select id="custom-signer"></select>
				</label>
				<label>
					<span>Subject</span>
					<select id="custom-subject"></select>
				</label>
				<button id="custom-cert-btn" class="tab-button" type="button">Sign</button>
			</div>
			<p id="custom-cert-msg" class="wot-msg" aria-live="polite"></p>
		</div>
		<div id="cert-list" class="wot-cert-list"></div>
	`;

	const buildBtn = section.querySelector<HTMLButtonElement>('#build-btn')!;
	const buildStatus = section.querySelector<HTMLElement>('#build-status')!;
	const list = section.querySelector<HTMLElement>('#keyring-list')!;
	const customWrap = section.querySelector<HTMLElement>('#custom-cert')!;
	const signerSel = section.querySelector<HTMLSelectElement>('#custom-signer')!;
	const subjectSel = section.querySelector<HTMLSelectElement>('#custom-subject')!;
	const customBtn = section.querySelector<HTMLButtonElement>('#custom-cert-btn')!;
	const customMsg = section.querySelector<HTMLElement>('#custom-cert-msg')!;
	const certList = section.querySelector<HTMLElement>('#cert-list')!;

	function refresh(): void {
		if (!state.built) {
			list.innerHTML = `<p class="panel-copy wot-empty">Generating the sample network…</p>`;
			certList.innerHTML = '';
			customWrap.hidden = true;
			return;
		}
		customWrap.hidden = false;
		list.innerHTML = state.ring
			.allNames()
			.map((name) => {
				const ident = state.ring.identity(name)!;
				const isMe = name === ME;
				const revoked = isKeyRevoked(state, name);
				const cls = [
					'identity-card',
					isMe ? 'identity-card--me' : '',
					revoked ? 'identity-card--revoked' : '',
				]
					.filter(Boolean)
					.join(' ');
				const badge = isMe
					? '<span class="identity-badge">that’s you</span>'
					: revoked
						? '<span class="identity-badge identity-badge--rev">revoked</span>'
						: '';
				const action =
					isMe || revoked
						? ''
						: `<button type="button" class="identity-revoke-btn" data-action="revoke-key" data-name="${name}" aria-label="Revoke ${name}'s key (self-revocation)">revoke key</button>`;
				return `
					<div class="${cls}">
						<div class="identity-card-head">
							<span class="identity-name">${name}</span>
							${badge}
						</div>
						<p class="identity-fp">${shortFp(ident.fingerprint)}</p>
						${action}
					</div>
				`;
			})
			.join('');

		const opts = state.ring
			.allNames()
			.map((n) => `<option value="${n}">${n}</option>`)
			.join('');
		signerSel.innerHTML = opts;
		subjectSel.innerHTML = opts;
		signerSel.value = ME;
		subjectSel.value = state.ring.allNames().find((n) => n !== ME) ?? '';

		certList.innerHTML = renderCertList(state);
	}

	state.rerenderKeyring = refresh;
	refresh();

	async function doBuild(): Promise<void> {
		buildBtn.disabled = true;
		buildBtn.setAttribute('aria-busy', 'true');
		buildStatus.textContent = 'Generating keypairs…';
		try {
			await buildSampleNetwork(state);
			buildStatus.textContent = `Generated ${state.ring.allNames().length} keypairs using ${signingAlgoName()}.`;
			// The hero names the algorithm before feature detection has run;
			// now that keys exist, the detected algorithm is authoritative.
			const algoSpan = document.getElementById('algo-name');
			if (algoSpan) algoSpan.textContent = signingAlgoName();
			state.rerenderKeyring();
			state.rerenderTrust();
			state.rerenderScenarios();
			await recompute(state);
		} catch (err) {
			buildStatus.textContent = `Failed: ${(err as Error).message}`;
		} finally {
			buildBtn.disabled = false;
			buildBtn.removeAttribute('aria-busy');
		}
	}
	state.buildNow = doBuild;

	buildBtn.addEventListener('click', () => {
		void doBuild();
	});

	customBtn.addEventListener('click', () => {
		void (async () => {
			if (!state.built) return;
			const signer = signerSel.value;
			const subject = subjectSel.value;
			if (!signer || !subject || signer === subject) {
				customMsg.textContent = 'Pick two different identities.';
				return;
			}
			customBtn.disabled = true;
			try {
				const r = await state.ring.certify(signer, subject);
				if ('error' in r) {
					customMsg.textContent = r.error;
				} else {
					customMsg.textContent = `${signer} signed ${subject}'s key.`;
					state.rerenderKeyring();
					await recompute(state);
				}
			} finally {
				customBtn.disabled = false;
			}
		})();
	});

	// Delegated click handlers for inspect / revoke-cert / revoke-key buttons
	// rendered inside the keyring + cert-list. Using delegation keeps the
	// handlers attached across rerenders.
	section.addEventListener('click', (e) => {
		const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('[data-action]');
		if (!btn) return;
		const action = btn.dataset.action;
		if (action === 'inspect') {
			const idx = Number(btn.dataset.certIdx);
			if (Number.isInteger(idx)) openInspectModal(state, idx);
			return;
		}
		if (action === 'revoke-cert') {
			const idx = Number(btn.dataset.certIdx);
			const cert = state.ring.certs[idx];
			if (!cert) return;
			btn.disabled = true;
			void (async () => {
				const r = await state.ring.revokeCert(cert.signerName, cert.subjectName);
				if (!('error' in r)) {
					state.logScenario(
						`${cert.signerName} retracted their certification of ${cert.subjectName}. The signature is real (verifies under ${cert.signerName}'s key); the edge is now dropped from the trust walk.`,
					);
				}
				state.rerenderKeyring();
				await recompute(state);
			})();
			return;
		}
		if (action === 'revoke-key') {
			const name = btn.dataset.name;
			if (!name) return;
			btn.disabled = true;
			void (async () => {
				const r = await state.ring.revokeKey(name);
				if (!('error' in r)) {
					state.logScenario(
						`${name} self-revoked their key (signed with the key being retired). Any certifications they previously issued are now ignored.`,
					);
				}
				state.rerenderKeyring();
				await recompute(state);
			})();
			return;
		}
	});

	return section;
}

function isCertRevoked(state: AppState, c: Certification): boolean {
	return state.ring.revocations.some(
		(r) => r.type === 'cert' && r.signerName === c.signerName && r.subjectName === c.subjectName,
	);
}

function isKeyRevoked(state: AppState, name: string): boolean {
	return state.ring.revocations.some((r) => r.type === 'key' && r.subjectName === name);
}

function renderCertList(state: AppState): string {
	if (!state.ring.certs.length) {
		return `<p class="panel-copy wot-empty">No certifications yet.</p>`;
	}
	const rows = state.ring.certs
		.map((c, i) => {
			const flagged = (c as Certification & { _forged?: boolean })._forged;
			const revoked = isCertRevoked(state, c);
			const cls = [
				'cert-row',
				flagged ? 'cert-row--forged' : '',
				revoked ? 'cert-row--revoked' : '',
			]
				.filter(Boolean)
				.join(' ');
			const tag = flagged
				? '<span class="cert-row-tag">forged</span>'
				: revoked
					? '<span class="cert-row-tag cert-row-tag--rev">revoked</span>'
					: `<span class="cert-row-idx">#${i + 1}</span>`;
			return `
				<li class="${cls}" data-cert-idx="${i}">
					<span class="cert-row-signer">${c.signerName}</span>
					<span class="cert-row-arrow" aria-hidden="true">→</span>
					<span class="cert-row-subject">${c.subjectName}</span>
					${tag}
					<span class="cert-row-actions">
						<button type="button" class="cert-row-btn" data-action="inspect" data-cert-idx="${i}" aria-label="Inspect certification ${c.signerName} to ${c.subjectName}">inspect</button>
						${revoked || flagged ? '' : `<button type="button" class="cert-row-btn cert-row-btn--danger" data-action="revoke-cert" data-cert-idx="${i}" aria-label="Revoke certification ${c.signerName} to ${c.subjectName}">revoke</button>`}
					</span>
				</li>
			`;
		})
		.join('');
	return `
		<h3 class="wot-section-h">Certifications on file</h3>
		<ul class="cert-list">${rows}</ul>
	`;
}

function bytesToHex(b: Uint8Array): string {
	return Array.from(b)
		.map((x) => x.toString(16).padStart(2, '0'))
		.join('');
}

function base64ToBytes(s: string): Uint8Array {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

function groupHex(hex: string, groupSize = 4, perLine = 8): string {
	const groups: string[] = [];
	for (let i = 0; i < hex.length; i += groupSize) groups.push(hex.slice(i, i + groupSize));
	const lines: string[] = [];
	for (let i = 0; i < groups.length; i += perLine) {
		lines.push(groups.slice(i, i + perLine).join(' '));
	}
	return lines.join('\n');
}

function openInspectModal(state: AppState, certIdx: number): void {
	const cert = state.ring.certs[certIdx];
	if (!cert) return;
	const signerIdent = state.ring.identity(cert.signerName);
	const subjectIdent = state.ring.identity(cert.subjectName);
	const dlg = document.querySelector<HTMLDialogElement>('#inspect-modal');
	const body = document.querySelector<HTMLElement>('#inspect-body');
	if (!dlg || !body || !subjectIdent || !signerIdent) return;
	const payload = certifyPayloadBytes(subjectIdent);
	const payloadHex = bytesToHex(payload);
	const payloadText = new TextDecoder().decode(payload);
	const sigBytes = base64ToBytes(cert.signatureB64);
	const sigHex = bytesToHex(sigBytes);
	const flagged = (cert as Certification & { _forged?: boolean })._forged === true;
	body.innerHTML = `
		<dl class="inspect-meta">
			<dt>Signer</dt><dd>${signerIdent.name} <code>${shortFp(signerIdent.fingerprint)}</code></dd>
			<dt>Subject</dt><dd>${subjectIdent.name} <code>${shortFp(subjectIdent.fingerprint)}</code></dd>
			<dt>Algorithm</dt><dd>${signingAlgoName()}</dd>
			<dt>Status</dt><dd>${flagged ? '<span class="scenario-status--invalid">forged — signature will NOT verify</span>' : '<span class="scenario-status--valid">real signature, verifies under signer\'s key</span>'}</dd>
		</dl>
		<h4>Signed payload (${payload.length} bytes)</h4>
		<p class="inspect-caption">UTF-8 text:</p>
		<pre class="inspect-block">${payloadText}</pre>
		<p class="inspect-caption">Hex:</p>
		<pre class="inspect-block inspect-block--hex">${groupHex(payloadHex)}</pre>
		<h4>Signature (${sigBytes.length} bytes)</h4>
		<p class="inspect-caption">Base64 (as stored):</p>
		<pre class="inspect-block inspect-block--wrap">${cert.signatureB64}</pre>
		<p class="inspect-caption">Hex:</p>
		<pre class="inspect-block inspect-block--hex">${groupHex(sigHex)}</pre>
	`;
	dlg.showModal();
}

// ---------- 3. Trust settings ------------------------------------------------

function renderTrustSection(state: AppState): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'trust';
	section.setAttribute('aria-labelledby', 'trust-heading');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 2</p>
				<h2 id="trust-heading">Your trust settings</h2>
				<p class="panel-copy">Owner-trust is <em>your</em> opinion of each person as an introducer. The policy sliders match GnuPG's defaults: 3 marginals make a quorum, trust may chain 5 hops deep.</p>
			</div>
		</div>
		<div id="trust-controls" class="wot-trust-controls"></div>
		<div class="wot-policy">
			<label>
				<span>marginalsNeeded</span>
				<input id="policy-marginals" type="number" min="1" max="10" value="3" />
			</label>
			<label>
				<span>maxDepth</span>
				<input id="policy-depth" type="number" min="1" max="10" value="5" />
			</label>
			<button id="recompute-btn" class="tab-button" type="button">Recompute</button>
		</div>
	`;

	const controls = section.querySelector<HTMLElement>('#trust-controls')!;
	const marginalsInput = section.querySelector<HTMLInputElement>('#policy-marginals')!;
	const depthInput = section.querySelector<HTMLInputElement>('#policy-depth')!;
	const recomputeBtn = section.querySelector<HTMLButtonElement>('#recompute-btn')!;

	function refresh(): void {
		if (!state.built) {
			controls.innerHTML = `<p class="panel-copy wot-empty">Build the sample network first.</p>`;
			return;
		}
		const levels: TrustLevel[] = ['full', 'marginal', 'none'];
		const floodCount = state.ring.allNames().filter((n) => n.startsWith('Flood')).length;
		controls.innerHTML = state.ring
			.allNames()
			.filter((n) => n !== ME && !n.startsWith('Flood'))
			.map((name) => {
				const t = state.ownerTrust.get(name) ?? 'none';
				return `
					<div class="trust-row" data-name="${name}">
						<span class="trust-row-name">${name}</span>
						<div class="trust-row-buttons" role="radiogroup" aria-label="Owner-trust for ${name}">
							${levels
								.map((level) => {
									const active = t === level;
									return `
								<button type="button"
									class="trust-pill trust-pill--${level} ${active ? 'is-active' : ''}"
									role="radio"
									aria-checked="${active}"
									tabindex="${active ? '0' : '-1'}"
									data-level="${level}">
									${level}
								</button>`;
								})
								.join('')}
						</div>
					</div>
				`;
			})
			.join('') +
			(floodCount
				? `<p class="panel-copy wot-flood-note">${floodCount} flood signers hidden from these controls — you never assigned them owner-trust, so they all default to <em>none</em>.</p>`
				: '');
		marginalsInput.value = String(state.policy.marginalsNeeded);
		depthInput.value = String(state.policy.maxDepth);

		// Ensure every radiogroup has at least one focusable radio even if the
		// stored owner-trust does not match any rendered level (shouldn't happen,
		// but defensive — a radiogroup with no tabindex=0 is a keyboard trap).
		controls.querySelectorAll<HTMLElement>('.trust-row-buttons').forEach((group) => {
			if (!group.querySelector('.trust-pill[tabindex="0"]')) {
				group.querySelector<HTMLButtonElement>('.trust-pill')?.setAttribute('tabindex', '0');
			}
		});
	}

	state.rerenderTrust = refresh;
	refresh();

	function selectLevel(row: HTMLElement, level: TrustLevel, focusAfter: boolean): void {
		const name = row.dataset.name!;
		state.ownerTrust.set(name, level);
		refresh();
		if (focusAfter) {
			const newRow = controls.querySelector<HTMLElement>(`.trust-row[data-name="${CSS.escape(name)}"]`);
			newRow?.querySelector<HTMLButtonElement>(`.trust-pill[data-level="${level}"]`)?.focus();
		}
		void recompute(state);
	}

	controls.addEventListener('click', (e) => {
		const btn = (e.target as HTMLElement).closest('.trust-pill') as HTMLButtonElement | null;
		if (!btn) return;
		const row = btn.closest('.trust-row') as HTMLElement | null;
		if (!row) return;
		selectLevel(row, btn.dataset.level as TrustLevel, false);
	});

	controls.addEventListener('keydown', (e: KeyboardEvent) => {
		const btn = (e.target as HTMLElement).closest('.trust-pill') as HTMLButtonElement | null;
		if (!btn) return;
		const row = btn.closest('.trust-row') as HTMLElement | null;
		if (!row) return;
		const group = btn.closest('.trust-row-buttons') as HTMLElement | null;
		if (!group) return;
		const pills = Array.from(group.querySelectorAll<HTMLButtonElement>('.trust-pill'));
		const idx = pills.indexOf(btn);
		let next = -1;
		switch (e.key) {
			case 'ArrowRight':
			case 'ArrowDown':
				next = (idx + 1) % pills.length;
				break;
			case 'ArrowLeft':
			case 'ArrowUp':
				next = (idx - 1 + pills.length) % pills.length;
				break;
			case 'Home':
				next = 0;
				break;
			case 'End':
				next = pills.length - 1;
				break;
			case ' ':
			case 'Enter':
				e.preventDefault();
				selectLevel(row, btn.dataset.level as TrustLevel, true);
				return;
			default:
				return;
		}
		if (next < 0) return;
		e.preventDefault();
		const target = pills[next]!;
		selectLevel(row, target.dataset.level as TrustLevel, true);
	});

	function readPolicy(): void {
		const m = clampInt(marginalsInput.value, 1, 10, 3);
		const d = clampInt(depthInput.value, 1, 10, 5);
		state.policy = { marginalsNeeded: m, maxDepth: d };
	}

	marginalsInput.addEventListener('change', () => {
		readPolicy();
		void recompute(state);
	});
	depthInput.addEventListener('change', () => {
		readPolicy();
		void recompute(state);
	});
	recomputeBtn.addEventListener('click', () => {
		readPolicy();
		void recompute(state);
	});

	return section;
}

function clampInt(s: string, min: number, max: number, fallback: number): number {
	const n = parseInt(s, 10);
	if (!Number.isFinite(n)) return fallback;
	return Math.min(max, Math.max(min, n));
}

// ---------- 4. Compute validity ----------------------------------------------

function renderValiditySection(state: AppState): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'validity';
	section.setAttribute('aria-labelledby', 'validity-heading');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 3</p>
				<h2 id="validity-heading">Compute web of trust</h2>
				<p class="panel-copy">Runs <code>computeValidity</code> on the current keyring, owner-trust, and policy. Each certification is cryptographically verified before it counts. Depth 0 is you; higher depths are reachable through chains of introducers.</p>
			</div>
		</div>
		<div class="wot-actions">
			<button id="compute-btn" class="tab-button" type="button">Compute web of trust</button>
		</div>
		<div id="validity-output" class="wot-validity-output" aria-live="polite"></div>
	`;

	const computeBtn = section.querySelector<HTMLButtonElement>('#compute-btn')!;
	const output = section.querySelector<HTMLElement>('#validity-output')!;

	function refresh(): void {
		if (!state.built) {
			output.innerHTML = `<p class="panel-copy wot-empty">Build the sample network and click <strong>Compute web of trust</strong>.</p>`;
			return;
		}
		if (!state.validity) {
			output.innerHTML = `<p class="panel-copy wot-empty">Click <strong>Compute web of trust</strong> to evaluate the current graph.</p>`;
			return;
		}
		output.innerHTML = renderValidity(state);
	}

	state.rerenderValidity = refresh;
	refresh();

	computeBtn.addEventListener('click', () => {
		void recompute(state);
	});

	// Trust-path tracing: click a graph node or a key name in the table to
	// highlight the chain of introducers behind that key's validity. Delegated
	// so the handlers survive the innerHTML rerenders.
	function toggleTrace(name: string, refocusGraph: boolean): void {
		state.traced = state.traced === name ? null : name;
		refresh();
		if (refocusGraph) {
			output
				.querySelector<SVGGElement>(`.graph-node-group[data-name="${CSS.escape(name)}"]`)
				?.focus();
		}
	}

	output.addEventListener('click', (e) => {
		const target = e.target as HTMLElement;
		if (target.closest('[data-action="trace-clear"]')) {
			state.traced = null;
			refresh();
			return;
		}
		const traceEl = target.closest<HTMLElement>('[data-action="trace"], .graph-node-group[data-name]');
		const name = traceEl?.dataset.name;
		if (name) toggleTrace(name, false);
	});

	output.addEventListener('keydown', (e: KeyboardEvent) => {
		if (e.key !== 'Enter' && e.key !== ' ') return;
		const g = (e.target as HTMLElement).closest<HTMLElement>('.graph-node-group[data-name]');
		if (!g || !g.dataset.name) return;
		e.preventDefault();
		toggleTrace(g.dataset.name, true);
	});

	return section;
}

function renderValidity(state: AppState): string {
	const v = state.validity!;
	if (state.traced && !state.ring.allNames().includes(state.traced)) state.traced = null;
	const allNames = state.ring.allNames();
	const named = allNames.filter((n) => !n.startsWith('Flood'));
	const flooders = allNames.filter((n) => n.startsWith('Flood'));

	const rows = named
		.map((name) => {
			const kv = v.get(name)!;
			const badge = kv.valid
				? `<span class="scenario-status--valid">VALID</span>`
				: `<span class="scenario-status--invalid">INVALID</span>`;
			const depth = kv.depth === -1 ? '—' : String(kv.depth);
			return `
				<tr class="validity-row ${kv.valid ? 'validity-row--valid' : 'validity-row--invalid'}">
					<td><button type="button" class="trace-btn" data-action="trace" data-name="${name}" aria-pressed="${state.traced === name}" title="Trace the trust path to ${name}"><strong>${name}</strong></button></td>
					<td>${badge}</td>
					<td class="mono-cell">${depth}</td>
					<td>${kv.reason}</td>
				</tr>
			`;
		})
		.join('');

	// The flood swarm stays visible in the keyring and the graph (the clutter
	// IS the lesson) but is collapsed to one row here so the table stays legible.
	const floodRow = flooders.length
		? `
			<tr class="validity-row validity-row--invalid validity-row--flood">
				<td><strong>Flood00–Flood${String(flooders.length - 1).padStart(2, '0')}</strong></td>
				<td><span class="scenario-status--invalid">INVALID</span></td>
				<td class="mono-cell">—</td>
				<td>${flooders.length} flood signers collapsed into one row — real keys, real signatures, zero owner-trust.</td>
			</tr>
		`
		: '';

	const trace = state.traced ? computeTrace(state, state.traced) : null;

	return `
		<div class="table-shell" tabindex="0" role="region" aria-label="Key validity table (scrollable)">
			<table class="math-table">
				<thead>
					<tr><th>Key</th><th>Validity</th><th>Depth</th><th>Reason</th></tr>
				</thead>
				<tbody>${rows}${floodRow}</tbody>
			</table>
		</div>
		<h3 class="wot-section-h">Trust graph</h3>
		<p class="panel-copy">Center = you. Rings are validation depth (1 hop, 2 hops…). Edge color encodes the signer's owner-trust: <em>green</em> = full, <em>yellow</em> = marginal, <em>grey</em> = none (carries no validity). <strong>Click any node — or a key name in the table — to trace exactly how trust (or distrust) reached it.</strong></p>
		${renderGraphSvg(state, trace)}
		<div id="trace-panel" class="trace-panel">
			${trace ? renderTraceHtml(trace) : `<p class="panel-copy trace-hint">No trace selected — click a node in the graph or a key name in the table to see the chain of introducers behind its verdict.</p>`}
		</div>
	`;
}

// ---------- Trust-path tracing ------------------------------------------------

interface TraceInfo {
	target: string;
	valid: boolean;
	nodes: Set<string>;
	edges: Set<string>; // "signer=>subject"
	lines: string[];
}

// Reconstruct WHY a key got its verdict. For a valid key, walk back through
// the recorded viaFull/viaMarginal introducers layer by layer until You
// (depth 0). For an invalid key, list every incoming certification and name
// the exact rule that stopped each one from counting.
function computeTrace(state: AppState, target: string): TraceInfo | null {
	const v = state.validity;
	if (!v) return null;
	const kv = v.get(target);
	if (!kv) return null;
	const nodes = new Set<string>([target]);
	const edges = new Set<string>();
	const lines: string[] = [];

	if (target === ME) {
		lines.push(
			'<strong>You</strong> are the ultimate anchor at depth 0. Validity is always computed from your point of view — every trust chain in this graph must end at your key.',
		);
		return { target, valid: true, nodes, edges, lines };
	}

	if (kv.valid) {
		const entries: Array<{ depth: number; text: string }> = [];
		const queue = [target];
		const seen = new Set([target]);
		while (queue.length) {
			const cur = queue.shift()!;
			const ckv = v.get(cur);
			if (!ckv || ckv.depth === 0) continue;
			for (const intro of [...ckv.viaFull, ...ckv.viaMarginal]) {
				edges.add(`${intro}=>${cur}`);
				nodes.add(intro);
				if (!seen.has(intro)) {
					seen.add(intro);
					queue.push(intro);
				}
			}
			const parts: string[] = [];
			if (ckv.viaFull.length) parts.push(`fully-trusted <strong>${ckv.viaFull.join(', ')}</strong> (one is enough)`);
			if (ckv.viaMarginal.length)
				parts.push(
					`${ckv.viaMarginal.length} marginally-trusted introducers (<strong>${ckv.viaMarginal.join(', ')}</strong>) against a quorum of ${state.policy.marginalsNeeded}`,
				);
			entries.push({
				depth: ckv.depth,
				text: `<strong>${cur}</strong> validated at depth ${ckv.depth} — signed by ${parts.join(' and by ')}.`,
			});
		}
		entries.sort((a, b) => b.depth - a.depth);
		lines.push(...entries.map((e) => e.text));
		lines.push(`<strong>You</strong> — depth 0, the ultimate anchor. Every chain above ends here.`);
		return { target, valid: true, nodes, edges, lines };
	}

	// Invalid: explain every incoming edge.
	lines.push(`<strong>${target}</strong> is INVALID — ${kv.reason}`);
	const incoming = state.ring.certs.filter((c) => c.subjectName === target);
	const seenSigners = new Set<string>();
	let floodCount = 0;
	for (const c of incoming) {
		nodes.add(c.signerName);
		edges.add(`${c.signerName}=>${c.subjectName}`);
		if (c.signerName.startsWith('Flood')) {
			floodCount++;
			continue;
		}
		if (seenSigners.has(c.signerName)) continue;
		seenSigners.add(c.signerName);
		lines.push(explainDeadEdge(state, c));
	}
	if (floodCount) {
		lines.push(
			`${floodCount} flood signers → ${target}: every one of those signatures verifies, but you assign none of the signers owner-trust — so none count. Cryptographically boring, operationally devastating: that was the SKS attack.`,
		);
	}
	if (!incoming.length) {
		lines.push(
			`Nobody has certified ${target}'s key at all — the bootstrap problem. Until someone you (transitively) trust signs it, the trust walk has nothing to follow.`,
		);
	}
	return { target, valid: false, nodes, edges, lines };
}

// One sentence naming the exact rule that keeps a real certification edge
// from conferring validity on its subject.
function explainDeadEdge(state: AppState, c: Certification): string {
	const v = state.validity!;
	const edge = `${c.signerName} → ${c.subjectName}`;
	if ((c as Certification & { _forged?: boolean })._forged === true) {
		return `${edge}: the signature does not verify. A forged certification is discarded before trust is even consulted — crypto vetoes policy.`;
	}
	if (isCertRevoked(state, c)) {
		return `${edge}: ${c.signerName} revoked this certification, so the edge is dropped from the walk.`;
	}
	if (isKeyRevoked(state, c.signerName)) {
		return `${edge}: ${c.signerName}'s key is revoked — certifications from a revoked key no longer count.`;
	}
	const skv = v.get(c.signerName);
	if (!skv?.valid) {
		return `${edge}: the signature is real, but ${c.signerName}'s own key is not valid from your point of view — an invalid key cannot introduce others.`;
	}
	if (skv.depth >= state.policy.maxDepth) {
		return `${edge}: ${c.signerName} is valid at depth ${skv.depth}, but validating ${c.subjectName} would need depth ${skv.depth + 1} — beyond your maxDepth of ${state.policy.maxDepth}.`;
	}
	const t = c.signerName === ME ? 'full' : state.ownerTrust.get(c.signerName) ?? 'none';
	if (t === 'none') {
		return `${edge}: the signature is real and ${c.signerName}'s key is valid, but you assign ${c.signerName} owner-trust <em>none</em> — their vouching carries no weight.`;
	}
	if (t === 'marginal') {
		return `${edge}: counts 1 toward the marginal quorum of ${state.policy.marginalsNeeded} — not enough on its own.`;
	}
	return `${edge}: should have conferred validity — if you can read this, the trace and the engine disagree (bug).`;
}

function renderTraceHtml(trace: TraceInfo): string {
	const badge = trace.valid
		? `<span class="scenario-status--valid">VALID</span>`
		: `<span class="scenario-status--invalid">INVALID</span>`;
	return `
		<div class="trace-head">
			<h4 class="trace-title">Trace — why is ${trace.target} ${badge}?</h4>
			<button type="button" class="cert-row-btn" data-action="trace-clear">clear trace</button>
		</div>
		<ol class="trace-lines">${trace.lines.map((l) => `<li>${l}</li>`).join('')}</ol>
	`;
}

interface NodePos {
	x: number;
	y: number;
	name: string;
	depth: number;
	valid: boolean;
	revoked: boolean;
	isMe: boolean;
	isFlood: boolean;
}

function renderGraphSvg(state: AppState, trace: TraceInfo | null): string {
	const v = state.validity!;
	const allNames = state.ring.allNames();
	const flooders = allNames.filter((n) => n.startsWith('Flood'));
	const named = allNames.filter((n) => !n.startsWith('Flood'));

	const W = 760;
	const H = 460;
	const cx = W / 2;
	const cy = H / 2 - 10;
	const ringRadius: Record<number, number> = { 1: 110, 2: 175, 3: 225, 4: 265 };

	// Bucket nodes by validation depth (or 'invalid')
	const byDepth = new Map<number, string[]>();
	for (const n of named) {
		const kv = v.get(n);
		const key = kv?.valid ? kv.depth : -1;
		if (!byDepth.has(key)) byDepth.set(key, []);
		byDepth.get(key)!.push(n);
	}

	const positions = new Map<string, NodePos>();

	// You at the center
	const youName = named.find((n) => n === ME);
	if (youName) {
		positions.set(youName, {
			x: cx,
			y: cy,
			name: youName,
			depth: 0,
			valid: true,
			revoked: isKeyRevoked(state, youName),
			isMe: true,
			isFlood: false,
		});
	}

	// Each depth ring (valid > 0) distributes evenly around the full circle,
	// starting from straight up. Invalid nodes (depth = -1) sit on the bottom
	// arc so they're visually outside the trust frontier.
	for (const [depth, names] of byDepth.entries()) {
		if (depth === 0) continue;
		const count = names.length;
		if (depth >= 1) {
			const r = ringRadius[Math.min(depth, 4)] ?? 265;
			names.forEach((name, i) => {
				const angle = -Math.PI / 2 + (2 * Math.PI * i) / count;
				const x = cx + r * Math.cos(angle);
				const y = cy + r * Math.sin(angle);
				const kv = v.get(name)!;
				positions.set(name, {
					x,
					y,
					name,
					depth: kv.depth,
					valid: kv.valid,
					revoked: isKeyRevoked(state, name),
					isMe: false,
					isFlood: false,
				});
			});
		} else {
			// Invalid: spread across bottom arc
			const r = 200;
			const spread = Math.min(Math.PI * 0.8, 0.5 + count * 0.18);
			const start = Math.PI / 2 - spread / 2;
			names.forEach((name, i) => {
				const angle = count === 1 ? Math.PI / 2 : start + (spread * i) / (count - 1);
				const x = cx + r * Math.cos(angle);
				const y = cy + r * Math.sin(angle);
				positions.set(name, {
					x,
					y,
					name,
					depth: -1,
					valid: false,
					revoked: isKeyRevoked(state, name),
					isMe: false,
					isFlood: false,
				});
			});
		}
	}

	// Flooders cluster tightly around Stranger so the swarm is visible.
	if (flooders.length) {
		const anchor = positions.get('Stranger') ?? { x: cx + 100, y: cy + 140 } as NodePos;
		flooders.forEach((name, i) => {
			const angle = (2 * Math.PI * i) / flooders.length;
			const r = 40 + (i % 3) * 6;
			positions.set(name, {
				x: anchor.x + r * Math.cos(angle),
				y: anchor.y + r * Math.sin(angle),
				name,
				depth: -1,
				valid: false,
				revoked: false,
				isMe: false,
				isFlood: true,
			});
		});
	}

	// Edges
	const edges = state.ring.certs
		.map((c) => {
			const a = positions.get(c.signerName);
			const b = positions.get(c.subjectName);
			if (!a || !b) return '';
			const forged = (c as Certification & { _forged?: boolean })._forged === true;
			const revoked = isCertRevoked(state, c);
			const signerKeyRevoked = isKeyRevoked(state, c.signerName);
			const signerTrust = c.signerName === ME ? 'full' : state.ownerTrust.get(c.signerName) ?? 'none';
			const onTracePath = trace?.edges.has(`${c.signerName}=>${c.subjectName}`) === true;
			const cls = [
				'graph-link',
				`graph-link--${signerTrust}`,
				forged ? 'graph-link--forged' : '',
				revoked || signerKeyRevoked ? 'graph-link--revoked' : '',
				a.isFlood ? 'graph-link--flood' : '',
				onTracePath ? 'graph-link--traced' : '',
			]
				.filter(Boolean)
				.join(' ');

			const dx = b.x - a.x;
			const dy = b.y - a.y;
			const len = Math.hypot(dx, dy) || 1;
			const radiusA = a.isMe ? 24 : a.isFlood ? 6 : 18;
			const radiusB = b.isMe ? 24 : b.isFlood ? 6 : 18;
			const sx = a.x + (dx / len) * radiusA;
			const sy = a.y + (dy / len) * radiusA;
			const tx = b.x - (dx / len) * radiusB;
			const ty = b.y - (dy / len) * radiusB;
			const titleNote = forged
				? ' (forged)'
				: revoked
					? ' (revoked)'
					: signerKeyRevoked
						? ' (signer key revoked)'
						: '';
			return `<line class="${cls}" x1="${sx.toFixed(1)}" y1="${sy.toFixed(1)}" x2="${tx.toFixed(1)}" y2="${ty.toFixed(1)}" marker-end="url(#wot-arrow)"><title>${c.signerName} → ${c.subjectName}${titleNote}</title></line>`;
		})
		.join('');

	// Nodes. Named nodes are interactive (click / Enter / Space traces the
	// trust path); the flood swarm is deliberately not focusable — 50 tab
	// stops would be a keyboard trap of its own.
	const nodes = [...positions.values()]
		.map((p) => {
			const fp = state.ring.identity(p.name)?.fingerprint ?? '';
			const ot = p.isMe ? 'you' : state.ownerTrust.get(p.name) ?? 'none';
			const onTracePath = trace?.nodes.has(p.name) === true;
			const isTarget = trace?.target === p.name;
			const cls = [
				'graph-node',
				p.valid ? 'graph-node--valid' : 'graph-node--invalid',
				`graph-node--ot-${ot}`,
				p.revoked ? 'graph-node--revoked' : '',
				p.isFlood ? 'graph-node--flood' : '',
				p.isMe ? 'graph-node--me' : '',
			]
				.filter(Boolean)
				.join(' ');
			const groupCls = [
				'graph-node-group',
				onTracePath ? 'graph-node-group--traced' : '',
				isTarget ? 'graph-node-group--target' : '',
			]
				.filter(Boolean)
				.join(' ');
			const r = p.isMe ? 24 : p.isFlood ? 6 : 18;
			const label = p.isFlood
				? ''
				: `<text class="graph-label" x="${p.x.toFixed(1)}" y="${(p.y + r + 14).toFixed(1)}" text-anchor="middle">${p.name}</text>`;
			const title = `${p.name}${p.isFlood ? ' (untrusted flood signer)' : ''} · ${shortFp(fp)} · ${p.valid ? `valid at depth ${p.depth}` : 'invalid'}${p.revoked ? ' · key revoked' : ''}`;
			const interactive = p.isFlood
				? ''
				: ` data-name="${p.name}" tabindex="0" role="button" aria-pressed="${isTarget}" aria-label="Trace trust path to ${p.name}"`;
			return `<g class="${groupCls}"${interactive}><circle class="${cls}" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${r}"><title>${title}</title></circle>${label}</g>`;
		})
		.join('');

	const floodNote = flooders.length
		? `<p class="graph-flood-note">${flooders.length} flood signer${flooders.length === 1 ? '' : 's'} drawn as a small cluster around <strong>Stranger</strong> — each carries a real signature, but none of them have owner-trust, so the trust walk ignores them.</p>`
		: '';

	return `
		<div class="graph-shell">
			<svg class="graph-svg${trace ? ' graph-svg--tracing' : ''}" viewBox="0 0 ${W} ${H}" role="group" aria-label="Trust graph with ${named.length} named identities${flooders.length ? ` plus ${flooders.length} flood signers` : ''} and ${state.ring.certs.length} certifications. Nodes are buttons that trace the trust path.">
				<defs>
					<marker id="wot-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
						<path d="M0,0 L10,5 L0,10 z" fill="currentColor" />
					</marker>
				</defs>
				${edges}
				${nodes}
			</svg>
			${floodNote}
			<ul class="graph-legend">
				<li><span class="graph-legend-dot graph-legend-dot--valid"></span>Valid key</li>
				<li><span class="graph-legend-dot graph-legend-dot--invalid"></span>Invalid key</li>
				<li><span class="graph-legend-dot graph-legend-dot--rev"></span>Revoked key</li>
				<li><span class="graph-legend-line graph-legend-line--full"></span>Edge from full-trust introducer</li>
				<li><span class="graph-legend-line graph-legend-line--marginal"></span>Edge from marginal introducer</li>
				<li><span class="graph-legend-line graph-legend-line--none"></span>Edge from untrusted signer</li>
				<li><span class="graph-legend-line graph-legend-line--forged"></span>Forged / revoked edge</li>
			</ul>
		</div>
	`;
}

// ---------- 5. Break trust scenarios -----------------------------------------

function renderScenariosSection(state: AppState): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'scenarios';
	section.setAttribute('aria-labelledby', 'scenarios-heading');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 4</p>
				<h2 id="scenarios-heading">Break trust</h2>
				<p class="panel-copy">Five ways the web of trust bends and breaks. Each button mutates the current state, recomputes validity, and logs what happened. <strong>Reset baseline</strong> rebuilds the original network.</p>
			</div>
		</div>
		<div id="scenario-buttons" class="wot-scenario-buttons"></div>
		<details class="why-details guided-tour">
			<summary>Guided tour — seven experiments, in order</summary>
			<ol>
				<li><strong>Read the baseline.</strong> Frank is valid at depth 2 only because Bob, Carol, <em>and</em> Dave all signed him — exactly the 3-marginal quorum. Click Frank's node in the trust graph above to see the full trace.</li>
				<li><strong>Break the quorum.</strong> In <em>Your trust settings</em>, drop Bob to <em>none</em>. Frank flips INVALID (2 marginals &lt; 3). Now lower <code>marginalsNeeded</code> to 2 — Frank comes back. Policy, not crypto, made both calls.</li>
				<li><strong>Over-trust Eve.</strong> Heretic is signed only by Eve. One click of full trust and Heretic is VALID — a single careless introducer expands your entire trust frontier.</li>
				<li><strong>Forge a certification.</strong> The forged Alice → Stranger cert fails signature verification, so no trust setting can ever make it count. Crypto vetoes policy.</li>
				<li><strong>Cut depth to 1.</strong> Every link is still trusted, but the chain is capped — keys beyond one hop drop out even though nothing else changed.</li>
				<li><strong>Flood Stranger.</strong> Fifty <em>real</em> signatures from unknown keys change nothing about validity — the damage is the operational mess (scroll the keyring). That is the SKS keyserver story.</li>
				<li><strong>Revoke.</strong> In <em>The keyring</em>, revoke the Alice → Eve certification and watch Eve drop out; then revoke Bob's key and see every certification he issued stop counting.</li>
			</ol>
		</details>
		<div id="scenario-log" class="wot-scenario-log" aria-live="polite"></div>
	`;

	const buttons = section.querySelector<HTMLElement>('#scenario-buttons')!;
	const log = section.querySelector<HTMLElement>('#scenario-log')!;
	const logLines: string[] = [];

	state.logScenario = (msg: string) => {
		const stamp = new Date().toLocaleTimeString();
		logLines.unshift(`[${stamp}] ${msg}`);
		log.innerHTML = logLines.slice(0, 8).map((l) => `<p class="wot-log-line">${l}</p>`).join('');
	};

	function refresh(): void {
		if (!state.built) {
			buttons.innerHTML = `<p class="panel-copy wot-empty">Build the sample network to enable scenarios.</p>`;
			return;
		}
		buttons.innerHTML = `
			<button id="scn-forge" class="tab-button" type="button">Forged certification (Alice → Stranger)</button>
			<button id="scn-orphan" class="tab-button" type="button">No trust path (highlight Stranger)</button>
			<button id="scn-overtrust" class="tab-button" type="button">Over-trust Eve (full) — watch Heretic</button>
			<button id="scn-depth" class="tab-button" type="button">Cut depth to 1</button>
			<button id="scn-flood" class="tab-button" type="button">Flood Stranger with 50 sigs (SKS-style)</button>
			<button id="scn-reset" class="tab-button" type="button">Reset baseline</button>
		`;

		section.querySelector<HTMLButtonElement>('#scn-forge')!.addEventListener('click', () => {
			void scenarioForge(state);
		});
		section.querySelector<HTMLButtonElement>('#scn-orphan')!.addEventListener('click', () => {
			void scenarioOrphan(state);
		});
		section.querySelector<HTMLButtonElement>('#scn-overtrust')!.addEventListener('click', () => {
			void scenarioOvertrust(state);
		});
		section.querySelector<HTMLButtonElement>('#scn-depth')!.addEventListener('click', () => {
			void scenarioDepth(state);
		});
		section.querySelector<HTMLButtonElement>('#scn-flood')!.addEventListener('click', () => {
			void scenarioFlood(state);
		});
		section.querySelector<HTMLButtonElement>('#scn-reset')!.addEventListener('click', () => {
			void scenarioReset(state);
		});
	}

	state.rerenderScenarios = refresh;
	refresh();

	return section;
}

async function scenarioForge(state: AppState): Promise<void> {
	// A forged certification: claim Alice signed Stranger, but use random bytes
	// for the signature. The verifier will reject it; Stranger stays INVALID.
	const fake = new Uint8Array(64);
	crypto.getRandomValues(fake);
	let s = '';
	for (let i = 0; i < fake.length; i++) s += String.fromCharCode(fake[i]);
	const forged: Certification & { _forged?: boolean } = {
		signerName: 'Alice',
		subjectName: 'Stranger',
		signatureB64: btoa(s),
		_forged: true,
	};
	state.ring.certs.push(forged);
	state.rerenderKeyring();
	await recompute(state);
	const kv = state.validity?.get('Stranger');
	state.logScenario(
		kv?.valid
			? 'Forged cert ACCEPTED — engine bug; this should never happen.'
			: 'Forged certification rejected: signature failed to verify. Stranger stays INVALID. The crypto enforces this, not policy.',
	);
}

async function scenarioOrphan(state: AppState): Promise<void> {
	// Just point out the existing orphan key. No state change needed.
	await recompute(state);
	const kv = state.validity?.get('Stranger');
	state.logScenario(
		kv && !kv.valid
			? `Stranger has no certifications from trusted introducers — "${kv.reason}". WoT cannot validate someone nobody you trust has vouched for.`
			: 'Stranger appears valid in the current graph — adjust trust to recreate the orphan case.',
	);
}

async function scenarioOvertrust(state: AppState): Promise<void> {
	// Promote Eve from none → full. Heretic (signed only by Eve) flips to valid.
	state.ownerTrust.set('Eve', 'full');
	state.rerenderTrust();
	await recompute(state);
	const kv = state.validity?.get('Heretic');
	state.logScenario(
		kv?.valid
			? 'Eve is now fully trusted. Heretic — signed only by Eve — is suddenly VALID. One over-trusted introducer just expanded your trust frontier.'
			: 'Heretic still invalid — check Eve’s own validity (she must be a valid key for her signatures to count).',
	);
}

async function scenarioDepth(state: AppState): Promise<void> {
	state.policy = { ...state.policy, maxDepth: 1 };
	state.rerenderTrust();
	await recompute(state);
	const dropped = state.ring
		.allNames()
		.filter((n) => {
			const kv = state.validity!.get(n);
			return kv && !kv.valid && n !== 'Stranger' && n !== 'Heretic';
		});
	state.logScenario(
		`maxDepth = 1. Only keys you personally signed remain valid. Dropped from the trusted set: ${dropped.length ? dropped.join(', ') : '(none additional)'}.`,
	);
}

async function scenarioFlood(state: AppState): Promise<void> {
	// Pedagogical model of the SKS keyserver flooding attack. Real attackers
	// uploaded hundreds of thousands of valid signatures to one key, breaking
	// GnuPG's import path. The cryptographic story is dull: each signature
	// is real, but from a key nobody trusts — so validity is unchanged. The
	// damage was OPERATIONAL: keyserver bandwidth, gpg parse time. We model
	// the cryptographic invariance here and measure the validity-compute time
	// before/after so the operational cost is visible.
	const N = 50;
	const tBefore = performance.now();
	await computeValidity(state.ring, { me: ME, ownerTrust: state.ownerTrust, policy: state.policy });
	const baselineMs = performance.now() - tBefore;

	for (let i = 0; i < N; i++) {
		const name = `Flood${String(i).padStart(2, '0')}`;
		await state.ring.createIdentity(name);
		// Each flooder is not assigned owner-trust → defaults to 'none'.
		const r = await state.ring.certify(name, 'Stranger');
		if ('error' in r) {
			state.logScenario(`Flooding failed at iteration ${i}: ${r.error}`);
			state.rerenderKeyring();
			state.rerenderTrust();
			await recompute(state);
			return;
		}
	}

	const tAfter = performance.now();
	const validity = await computeValidity(state.ring, {
		me: ME,
		ownerTrust: state.ownerTrust,
		policy: state.policy,
	});
	const afterMs = performance.now() - tAfter;
	state.validity = validity;
	state.rerenderKeyring();
	state.rerenderTrust();
	state.rerenderValidity();

	const stranger = validity.get('Stranger');
	const slowdown = baselineMs > 0 ? (afterMs / baselineMs).toFixed(1) : '∞';
	state.logScenario(
		stranger?.valid
			? `${N} flood signatures unexpectedly validated Stranger — owner-trust may be misconfigured.`
			: `${N} real signatures from untrusted Flood00..${String(N - 1).padStart(2, '0')} added to Stranger. Stranger STAYS INVALID — none of the flooders are trusted introducers. computeValidity went from ${baselineMs.toFixed(0)}ms → ${afterMs.toFixed(0)}ms (≈${slowdown}× slower). Crypto is unchanged; the SKS pain was operational.`,
	);
}

async function scenarioReset(state: AppState): Promise<void> {
	await buildSampleNetwork(state);
	state.rerenderKeyring();
	state.rerenderTrust();
	state.rerenderScenarios();
	await recompute(state);
	state.logScenario('Baseline restored. Fresh keys generated; owner-trust and policy reset to defaults.');
}

// ---------- 6. WoT vs PKI / concepts -----------------------------------------

function renderConceptsSection(): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'concepts';
	section.setAttribute('aria-labelledby', 'concepts-heading');

	const compareRows = WOT_VS_PKI.map(
		(r) => `
		<tr>
			<th scope="row">${r.axis}</th>
			<td>${r.wot}</td>
			<td>${r.pki}</td>
		</tr>
	`,
	).join('');

	const concepts = TRUST_CONCEPTS.map(
		(c) => `
		<div class="panel-card">
			<h3>${c.title}</h3>
			<p class="panel-copy">${c.body}</p>
		</div>
	`,
	).join('');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 5</p>
				<h2 id="concepts-heading">Web of Trust vs PKI</h2>
				<p class="panel-copy">Two answers to the same question — "how do I decide which public keys are real?" — taken in opposite directions. The sibling <a href="https://systemslibrarian.github.io/crypto-lab-pki-chain/">crypto-lab-pki-chain</a> demo walks the hierarchical side.</p>
			</div>
		</div>
		<div class="table-shell" tabindex="0" role="region" aria-label="Web of Trust vs hierarchical PKI comparison (scrollable)">
			<table class="math-table">
				<thead>
					<tr><th>Axis</th><th>Web of Trust</th><th>Hierarchical PKI</th></tr>
				</thead>
				<tbody>${compareRows}</tbody>
			</table>
		</div>
		<h3 class="wot-section-h">The GnuPG trust vocabulary</h3>
		<div class="reuse-grid">${concepts}</div>
	`;
	return section;
}

// ---------- 7. Real world / pitfalls -----------------------------------------

function renderRealWorldSection(): HTMLElement {
	const section = el('section', 'lab-section');
	section.id = 'realworld';
	section.setAttribute('aria-labelledby', 'realworld-heading');

	const real = REAL_WORLD.map(
		(r) => `
		<div class="panel-card">
			<h3>${r.title}</h3>
			<p class="panel-copy">${r.body}</p>
		</div>
	`,
	).join('');

	const lessons = FAILURE_LESSONS.map(
		(l) => `
		<div class="panel-card">
			<h3>${l.title}</h3>
			<p class="panel-copy">${l.body}</p>
		</div>
	`,
	).join('');

	section.innerHTML = `
		<div class="section-heading-row">
			<div>
				<p class="section-kicker">Section · 6</p>
				<h2 id="realworld-heading">In the real world</h2>
				<p class="panel-copy">Where the model is actually deployed today, and where it has cracked.</p>
			</div>
		</div>
		<div class="reuse-grid">${real}</div>
		<h3 class="wot-section-h">Pitfalls to keep in mind</h3>
		<div class="reuse-grid">${lessons}</div>
	`;
	return section;
}

// ---------- 8. Footer (scripture) -------------------------------------------

function renderFooter(): HTMLElement {
	const footer = el('footer', 'lab-section');
	const reviewed = '2026-07';
	footer.innerHTML = `
		<div class="footer-meta">
			<div class="footer-meta-item">
				<p class="hero-metric-label">Last reviewed</p>
				<p class="mono-inline">${reviewed}</p>
			</div>
			<div class="footer-meta-item">
				<p class="hero-metric-label">Status</p>
				<p class="panel-copy">Educational model. The crypto (Ed25519 / ECDSA P-256 via Web Crypto) is real; the trust logic mirrors GnuPG's. The OpenPGP packet format is not modelled — use GnuPG, Sequoia-PGP, or a vetted library for production key management.</p>
			</div>
		</div>
		<p class="footer-related">
			Related demos:
			<a href="https://systemslibrarian.github.io/crypto-lab-pki-chain/">crypto-lab-pki-chain</a> ·
			<a href="https://systemslibrarian.github.io/crypto-lab-ed25519-forge/">crypto-lab-ed25519-forge</a> ·
			<a href="https://systemslibrarian.github.io/crypto-lab-ssh-handshake/">crypto-lab-ssh-handshake</a> ·
			<a href="https://systemslibrarian.github.io/crypto-lab-merkle-vault/">crypto-lab-merkle-vault</a>
		</p>
		<p class="scripture">"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31</p>
	`;
	return footer;
}

// ---------- Inspect modal ----------------------------------------------------

function renderInspectModal(): HTMLDialogElement {
	const dlg = document.createElement('dialog');
	dlg.id = 'inspect-modal';
	dlg.className = 'inspect-modal';
	dlg.setAttribute('aria-labelledby', 'inspect-modal-title');
	dlg.innerHTML = `
		<div class="inspect-modal-head">
			<h3 id="inspect-modal-title">Certification payload</h3>
			<button type="button" class="inspect-close" aria-label="Close inspector">×</button>
		</div>
		<div id="inspect-body" class="inspect-body"></div>
	`;
	dlg.addEventListener('click', (e) => {
		if ((e.target as HTMLElement).closest('.inspect-close')) {
			dlg.close();
		}
	});
	return dlg;
}

// ---------- mountApp ---------------------------------------------------------

export function mountApp(root: HTMLDivElement): void {
	const state: AppState = {
		ring: new Keyring(),
		ownerTrust: defaultOwnerTrust(),
		policy: { marginalsNeeded: 3, maxDepth: 5 },
		validity: null,
		built: false,
		traced: null,
		rerenderKeyring: () => {},
		rerenderTrust: () => {},
		rerenderValidity: () => {},
		rerenderScenarios: () => {},
		logScenario: () => {},
		buildNow: async () => {},
	};

	const shell = el('div', 'page-shell');
	shell.id = 'playground-heading';

	shell.appendChild(renderHero());
	shell.appendChild(renderKeyringSection(state));
	shell.appendChild(renderTrustSection(state));
	shell.appendChild(renderValiditySection(state));
	shell.appendChild(renderScenariosSection(state));
	shell.appendChild(renderConceptsSection());
	shell.appendChild(renderRealWorldSection());
	shell.appendChild(renderFooter());
	shell.appendChild(renderInspectModal());

	root.replaceChildren(shell);

	// The demo should be alive on arrival — generate the sample network
	// immediately instead of waiting for a click.
	void state.buildNow();
}
