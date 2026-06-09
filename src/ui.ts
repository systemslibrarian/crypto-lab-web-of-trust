// ui.ts — Web of Trust interactive UI.
//
// Mounts a single `mountApp(root)` that renders the whole demo. State (the
// Keyring instance, the owner-trust map, the policy, and the latest validity
// result) lives in a closure and is mutated by event handlers. Sections that
// react to state changes re-render their own container; the rest are static.

import {
	Keyring,
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
	rerenderKeyring: () => void;
	rerenderTrust: () => void;
	rerenderValidity: () => void;
	rerenderScenarios: () => void;
	logScenario: (msg: string) => void;
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
			<p class="hero-metric-value">Real ${signingAlgoName()} signatures · no central authority · you decide whom to trust</p>
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
				<p class="panel-copy">Every identity here is a real keypair generated in your browser. Click <strong>Build sample network</strong> to populate a small social graph, or add a custom certification once it exists.</p>
			</div>
		</div>
		<div class="wot-actions">
			<button id="build-btn" class="tab-button" type="button">Build sample network</button>
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
			list.innerHTML = `<p class="panel-copy wot-empty">No keys yet — click <strong>Build sample network</strong> to generate one.</p>`;
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
				return `
					<div class="identity-card ${isMe ? 'identity-card--me' : ''}">
						<div class="identity-card-head">
							<span class="identity-name">${name}</span>
							${isMe ? '<span class="identity-badge">that’s you</span>' : ''}
						</div>
						<p class="identity-fp">${shortFp(ident.fingerprint)}</p>
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

	buildBtn.addEventListener('click', () => {
		void (async () => {
			buildBtn.disabled = true;
			buildBtn.setAttribute('aria-busy', 'true');
			buildStatus.textContent = 'Generating keypairs…';
			try {
				await buildSampleNetwork(state);
				buildStatus.textContent = `Generated ${state.ring.allNames().length} keypairs using ${signingAlgoName()}.`;
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
		})();
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

	return section;
}

function renderCertList(state: AppState): string {
	if (!state.ring.certs.length) {
		return `<p class="panel-copy wot-empty">No certifications yet.</p>`;
	}
	const rows = state.ring.certs
		.map((c, i) => {
			const flagged = (c as Certification & { _forged?: boolean })._forged;
			return `
				<li class="cert-row ${flagged ? 'cert-row--forged' : ''}">
					<span class="cert-row-signer">${c.signerName}</span>
					<span class="cert-row-arrow" aria-hidden="true">→</span>
					<span class="cert-row-subject">${c.subjectName}</span>
					${flagged ? '<span class="cert-row-tag">forged</span>' : `<span class="cert-row-idx">#${i + 1}</span>`}
				</li>
			`;
		})
		.join('');
	return `
		<h3 class="wot-section-h">Certifications on file</h3>
		<ul class="cert-list">${rows}</ul>
	`;
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
		controls.innerHTML = state.ring
			.allNames()
			.filter((n) => n !== ME)
			.map((name) => {
				const t = state.ownerTrust.get(name) ?? 'none';
				return `
					<div class="trust-row" data-name="${name}">
						<span class="trust-row-name">${name}</span>
						<div class="trust-row-buttons" role="radiogroup" aria-label="Owner-trust for ${name}">
							${(['full', 'marginal', 'none'] as TrustLevel[])
								.map(
									(level) => `
								<button type="button"
									class="trust-pill trust-pill--${level} ${t === level ? 'is-active' : ''}"
									role="radio"
									aria-checked="${t === level}"
									data-level="${level}">
									${level}
								</button>`,
								)
								.join('')}
						</div>
					</div>
				`;
			})
			.join('');
		marginalsInput.value = String(state.policy.marginalsNeeded);
		depthInput.value = String(state.policy.maxDepth);
	}

	state.rerenderTrust = refresh;
	refresh();

	controls.addEventListener('click', (e) => {
		const btn = (e.target as HTMLElement).closest('.trust-pill') as HTMLButtonElement | null;
		if (!btn) return;
		const row = btn.closest('.trust-row') as HTMLElement | null;
		if (!row) return;
		const name = row.dataset.name!;
		const level = btn.dataset.level as TrustLevel;
		state.ownerTrust.set(name, level);
		refresh();
		void recompute(state);
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

	return section;
}

function renderValidity(state: AppState): string {
	const v = state.validity!;
	const rows = state.ring
		.allNames()
		.map((name) => {
			const kv = v.get(name)!;
			const badge = kv.valid
				? `<span class="scenario-status--valid">VALID</span>`
				: `<span class="scenario-status--invalid">INVALID</span>`;
			const depth = kv.depth === -1 ? '—' : String(kv.depth);
			return `
				<tr class="validity-row ${kv.valid ? 'validity-row--valid' : 'validity-row--invalid'}">
					<td><strong>${name}</strong></td>
					<td>${badge}</td>
					<td class="mono-cell">${depth}</td>
					<td>${kv.reason}</td>
				</tr>
			`;
		})
		.join('');

	const graph = state.ring.certs
		.map((c) => {
			const ok = !(c as Certification & { _forged?: boolean })._forged;
			return `<li class="graph-edge ${ok ? '' : 'graph-edge--bad'}"><code>${c.signerName}</code> → <code>${c.subjectName}</code>${ok ? '' : ' <span class="cert-row-tag">forged</span>'}</li>`;
		})
		.join('');

	return `
		<div class="table-shell">
			<table class="math-table">
				<thead>
					<tr><th>Key</th><th>Validity</th><th>Depth</th><th>Reason</th></tr>
				</thead>
				<tbody>${rows}</tbody>
			</table>
		</div>
		<h3 class="wot-section-h">Certification graph</h3>
		<ul class="graph-edges">${graph}</ul>
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
				<p class="panel-copy">Four ways the web of trust bends and breaks. Each button mutates the current state, recomputes validity, and logs what happened. <strong>Reset baseline</strong> rebuilds the original network.</p>
			</div>
		</div>
		<div id="scenario-buttons" class="wot-scenario-buttons"></div>
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
		<div class="table-shell">
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
	const reviewed = '2026-06';
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
		<p class="scripture">"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31</p>
	`;
	return footer;
}

// ---------- mountApp ---------------------------------------------------------

export function mountApp(root: HTMLDivElement): void {
	const state: AppState = {
		ring: new Keyring(),
		ownerTrust: defaultOwnerTrust(),
		policy: { marginalsNeeded: 3, maxDepth: 5 },
		validity: null,
		built: false,
		rerenderKeyring: () => {},
		rerenderTrust: () => {},
		rerenderValidity: () => {},
		rerenderScenarios: () => {},
		logScenario: () => {},
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

	root.replaceChildren(shell);
}
