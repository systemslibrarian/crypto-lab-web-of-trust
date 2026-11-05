import { expect, it } from 'vitest';
import { Keyring, PublicKeyring, computeValidity, type TrustQuery, type Revocation } from '../src/engine.ts';

async function fixture() {
    const issuer = new Keyring();
    for (const name of ['You', 'Archivist', 'Curator']) await issuer.createIdentity(name);
    await issuer.certify('You', 'Archivist');
    await issuer.certify('Archivist', 'Curator');
    const a = new PublicKeyring(issuer), b = new PublicKeyring(issuer);
    const query = (): TrustQuery => ({ me: 'You', ownerTrust: new Map([['Archivist', 'full']]), policy: { maxDepth: 5, marginalsNeeded: 3 } });
    return { issuer, a, b, qa: query(), qb: query() };
}
const valid = async (ring: PublicKeyring, q: TrustQuery) => (await computeValidity(ring, q)).get('Curator')!.valid;

it('delivers verified revocations separately; copies cannot mutate each other', async () => {
    const { issuer, a, b, qa, qb } = await fixture();
    expect(await valid(a, qa)).toBe(true); expect(await valid(b, qb)).toBe(true);
    const rev = await issuer.revokeKey('Archivist') as Revocation;
    expect(a.revocations).toHaveLength(0); expect(b.revocations).toHaveLength(0);
    expect(await a.receive(rev)).toBe('accepted');
    expect(await valid(a, qa)).toBe(false); expect(await valid(b, qb)).toBe(true);
    rev.signatureB64 = 'changed after delivery';
    expect(await valid(a, qa)).toBe(false);
    const held = a.revocations; held.length = 0;
    a.identity('Archivist')!.publicKeyJwk.x = 'mutated';
    expect(await valid(a, qa)).toBe(false);
    expect(await b.receive(a.revocations[0])).toBe('accepted');
    expect(await b.receive(a.revocations[0])).toBe('duplicate');
    expect(b.revocations).toHaveLength(1); expect(await valid(b, qb)).toBe(false);
    expect('revokeKey' in a).toBe(false); expect('privateKey' in a.identity('Archivist')!).toBe(false);
});

it('rejects forged records without changing stored records or verdicts', async () => {
    const { issuer, b, qb } = await fixture();
    const rev = await issuer.revokeKey('Archivist') as Revocation;
    const bytes = atob(rev.signatureB64);
    rev.signatureB64 = btoa(String.fromCharCode(bytes.charCodeAt(0) ^ 1) + bytes.slice(1));
    expect(await b.receive(rev)).toBe('rejected');
    expect(b.revocations).toHaveLength(0); expect(await valid(b, qb)).toBe(true);
});

it('keeps owner trust independent of signed records', async () => {
    const { a, b, qa, qb } = await fixture();
    qb.ownerTrust.set('Archivist', 'none');
    expect(await valid(a, qa)).toBe(true); expect(await valid(b, qb)).toBe(false);
    expect(a.certs).toEqual(b.certs); expect(a.revocations).toEqual(b.revocations);
});

it('rejects a cryptographically valid key-revocation signature from a different owner', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const bytes = new TextEncoder().encode('revoke-key:Victim:1234');
    const signature = await crypto.subtle.sign('Ed25519', kp.privateKey, bytes);
    expect(await crypto.subtle.verify('Ed25519', kp.publicKey, signature, bytes)).toBe(true);
    const source = {
        certs: [], revocations: [], allNames: () => ['Attacker', 'Victim'],
        identity: (name: string) => ({ name, publicKeyJwk: jwk, fingerprint: '1234' }),
        verifyCert: async () => false, verifyRevocation: async () => false,
    };
    const ring = new PublicKeyring(source);
    const rev: Revocation = { type: 'key', signerName: 'Attacker', subjectName: 'Victim', signatureB64: btoa(String.fromCharCode(...new Uint8Array(signature))) };
    expect(await ring.receive(rev)).toBe('rejected');
    expect(ring.revocations).toHaveLength(0);
});
