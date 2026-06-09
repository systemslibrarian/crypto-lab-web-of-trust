import './style.css';
import './extra.css';
import { Keyring, computeValidity, type Certification } from './engine.ts';
import { mountApp } from './ui.ts';

// Dev-only self-test. Builds a tiny keyring, certifies You -> Alice, asserts
// Alice is valid, then pushes a forged certification claiming Alice signed a
// Stranger and asserts that the stranger remains invalid because the bogus
// signature does not verify. Runs only in dev to keep the deployed bundle
// silent on success.
if (import.meta.env.DEV) {
	console.group('crypto-lab-web-of-trust: engine self-test');
	void (async () => {
		try {
			const ring = new Keyring();
			await ring.createIdentity('You');
			await ring.createIdentity('Alice');
			await ring.createIdentity('Stranger');
			const cert = await ring.certify('You', 'Alice');
			if ('error' in cert) {
				console.error('certify failed:', cert.error);
				console.groupEnd();
				return;
			}

			const baseline = await computeValidity(ring, {
				me: 'You',
				ownerTrust: new Map(),
				policy: { marginalsNeeded: 3, maxDepth: 5 },
			});
			const aliceValid = baseline.get('Alice')?.valid === true;
			console.log('Alice valid after You -> Alice:', aliceValid);
			if (!aliceValid) console.error('SELF-TEST FAIL: Alice should be valid.');

			const fake = new Uint8Array(64);
			crypto.getRandomValues(fake);
			let s = '';
			for (let i = 0; i < fake.length; i++) s += String.fromCharCode(fake[i]);
			const forged: Certification = {
				signerName: 'Alice',
				subjectName: 'Stranger',
				signatureB64: btoa(s),
			};
			ring.certs.push(forged);
			const after = await computeValidity(ring, {
				me: 'You',
				ownerTrust: new Map([['Alice', 'full']]),
				policy: { marginalsNeeded: 3, maxDepth: 5 },
			});
			const strangerStillInvalid = after.get('Stranger')?.valid === false;
			console.log('Stranger remains invalid after forged cert:', strangerStillInvalid);
			if (!strangerStillInvalid) console.error('SELF-TEST FAIL: forged cert was accepted.');

			// Revocation: when Alice revokes her cert of Alice (n/a here), test
			// instead by certifying Alice -> Stranger, then revoking it.
			await ring.certify('Alice', 'Stranger');
			const beforeRev = await computeValidity(ring, {
				me: 'You',
				ownerTrust: new Map([['Alice', 'full']]),
				policy: { marginalsNeeded: 3, maxDepth: 5 },
			});
			console.log('Stranger valid after Alice signs:', beforeRev.get('Stranger')?.valid === true);
			await ring.revokeCert('Alice', 'Stranger');
			const afterRev = await computeValidity(ring, {
				me: 'You',
				ownerTrust: new Map([['Alice', 'full']]),
				policy: { marginalsNeeded: 3, maxDepth: 5 },
			});
			const revWorks = afterRev.get('Stranger')?.valid === false;
			console.log('Stranger invalid after Alice revokes her cert:', revWorks);
			if (!revWorks) console.error('SELF-TEST FAIL: revocation was not applied.');
		} catch (err) {
			console.error('self-test threw:', err);
		} finally {
			console.groupEnd();
		}
	})();
}

mountApp(document.querySelector<HTMLDivElement>('#app')!);

(function initThemeToggle() {
	const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
	if (!button) return;

	function apply(theme: string): void {
		document.documentElement.setAttribute('data-theme', theme);
		localStorage.setItem('theme', theme);
		const isDark = theme === 'dark';
		button!.textContent = isDark ? '\u{1F319}' : '☀️';
		button!.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
	}

	const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
	apply(current);

	button.addEventListener('click', () => {
		const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
		apply(next);
	});
})();
