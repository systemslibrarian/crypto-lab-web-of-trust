import { Keyring, PublicKeyring, computeValidity, type Revocation, type TrustQuery } from './engine.ts';

export function renderObservers(): HTMLElement {
    const section = document.createElement('section');
    section.className = 'lab-section';
    section.id = 'independent-observers';
    section.setAttribute('aria-labelledby', 'observers-heading');
    section.innerHTML = `<h2 id="observers-heading">Same signatures. Different received records.</h2>
    <p class="panel-copy">Two public keyring copies start with You → Archivist → Curator. Both observers trust Archivist as an introducer. Issue a signed key revocation, then deliver it separately. A signature proves authorship; it cannot deliver itself.</p>
    <div class="wot-scenario-buttons">
      <button class="tab-button" data-action="reset">Create / reset observer copies</button>
      <button class="tab-button" data-action="issue" disabled>Issue Archivist’s revocation</button>
      <button class="tab-button" data-action="a" disabled>Deliver to observer A</button>
      <button class="tab-button" data-action="b" disabled>Deliver to observer B</button>
      <button class="tab-button" data-action="forge" disabled>Send forged revocation to B</button>
    </div>
    <p data-event role="status">Create the copies to begin. This separate experiment does not change the keyring above.</p>
    <div class="observer-grid"><article class="panel" data-view="a"><h3>Observer A</h3><div data-records></div></article><article class="panel" data-view="b"><h3>Observer B</h3><div data-records></div></article></div>
    <label class="observer-trust"><input type="checkbox" data-trust checked disabled> Observer B locally trusts Archivist to introduce other keys</label>
    <details class="why-details"><summary>What this model establishes</summary>
    <p>Each observer holds its own public keys, certifications, received revocations and local owner-trust decision. The issuing keyring holds the private keys. Delivery verifies the signature and, for a key revocation, checks that the signer is the key owner. Rejected records never enter the received list. “Event” is an exercise sequence number, not a network timestamp. No network or keyserver is contacted.</p>
    <p>Revocation does not erase old copies or recover a leaked message. This teaching model conservatively drops all certifications from a revoked key. It omits expiration, designated revokers and revocation reason codes: actual OpenPGP distinguishes compromise from retirement or supersession. It uses real Web Crypto signatures over invented records, not OpenPGP packets.</p>
    <p>Sources: Philip R. Zimmermann, <cite>The Official PGP User’s Guide</cite> (1995), printed pp. 31–34; Simson Garfinkel, <cite>PGP: Pretty Good Privacy</cite> (1995), printed pp. 183–184. For the current format and reason-code distinction, see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.31">RFC 9580 §5.2.3.31</a>.</p></details>`;
    let authority: Keyring;
    let views: Record<string, PublicKeyring> = {};
    let queries: Record<string, TrustQuery> = {};
    let issued: Revocation | undefined;
    let event = 0;
    let receivedAt: Record<string, number> = {};
    const status = section.querySelector<HTMLElement>('[data-event]')!;
    const trust = section.querySelector<HTMLInputElement>('[data-trust]')!;
    const buttons = [...section.querySelectorAll<HTMLButtonElement>('button')];
    function enable() {
        for (const button of buttons) button.disabled = button.dataset.action === 'reset' ? false : !views.a || (button.dataset.action !== 'issue' && !issued);
        section.querySelector<HTMLButtonElement>('[data-action="issue"]')!.disabled = !views.a || !!issued;
        trust.disabled = !views.a;
    }
    async function paint() {
        for (const name of ['a', 'b']) {
            const ring = views[name];
            const validity = await computeValidity(ring, queries[name]);
            const curator = validity.get('Curator')!;
            const target = section.querySelector<HTMLElement>(`[data-view="${name}"] [data-records]`)!;
            target.replaceChildren();
            for (const text of [
                `Last accepted update: event ${receivedAt[name]}. Public keys: ${ring.allNames().join(', ')}.`,
                `Certifications received: ${ring.certs.map(c => `${c.signerName} → ${c.subjectName}`).join('; ')}.`,
                `Revocations received: ${ring.revocations.map(r => `${r.subjectName} (owner signature verified)`).join('; ') || 'none'}.`,
                `Local owner trust in Archivist: ${queries[name].ownerTrust.get('Archivist')}.`,
                `Curator: ${curator.valid ? 'VALID' : 'INVALID'} — ${curator.reason}`,
            ]) { const p = document.createElement('p'); p.textContent = text; target.append(p); }
        }
    }
    async function run(action: string) {
        buttons.forEach(b => { b.disabled = true; }); trust.disabled = true;
        try {
            event++;
            if (action === 'reset') {
                authority = new Keyring();
                for (const name of ['You', 'Archivist', 'Curator']) await authority.createIdentity(name);
                await authority.certify('You', 'Archivist'); await authority.certify('Archivist', 'Curator');
                views = { a: new PublicKeyring(authority), b: new PublicKeyring(authority) };
                queries = Object.fromEntries(['a', 'b'].map(name => [name, { me: 'You', ownerTrust: new Map([['Archivist', 'full']]), policy: { maxDepth: 5, marginalsNeeded: 3 } }]));
                event = 0; receivedAt = { a: 0, b: 0 }; issued = undefined; trust.checked = true;
                status.textContent = 'Event 0: both copies have the same two certifications; no revocation has been issued.';
            } else if (action === 'issue') {
                const result = await authority.revokeKey('Archivist');
                if ('error' in result) throw new Error(result.error);
                issued = result;
                status.textContent = `Event ${event}: revocation signed. Neither observer has received it.`;
            } else if (action === 'trust') {
                queries.b.ownerTrust.set('Archivist', trust.checked ? 'full' : 'none');
                status.textContent = `Event ${event}: only B’s local owner-trust decision changed. No signed record was delivered.`;
            } else {
                const name = action === 'a' ? 'a' : 'b';
                const record = { ...issued! };
                if (action === 'forge') {
                    const bytes = atob(record.signatureB64);
                    record.signatureB64 = btoa(String.fromCharCode(bytes.charCodeAt(0) ^ 1) + bytes.slice(1));
                }
                const result = await views[name].receive(record);
                if (result === 'accepted') receivedAt[name] = event;
                status.textContent = `Event ${event}: observer ${name.toUpperCase()} ${result} the ${action === 'forge' ? 'forged' : 'signed'} revocation. ${result === 'rejected' ? 'Signature verification failed; stored records and verdicts are unchanged.' : 'The other observer’s records are unchanged.'}`;
            }
            await paint();
        } catch (error) { status.textContent = `Could not complete the experiment: ${error instanceof Error ? error.message : String(error)}. Reset to try again.`; }
        finally { enable(); }
    }
    buttons.forEach(b => b.addEventListener('click', () => { void run(b.dataset.action!); }));
    trust.addEventListener('change', () => { void run('trust'); });
    return section;
}
