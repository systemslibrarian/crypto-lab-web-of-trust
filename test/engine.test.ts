// engine.test.ts — pure-logic + real-crypto unit tests for the GnuPG-style
// trust walk in src/engine.ts.
//
// WHY THIS FILE EXISTS
// --------------------
// The trust computation (computeValidity) is the correctness heart of this
// demo: it decides which keys are VALID from your point of view given
// full/marginal owner-trust, a marginals quorum, a maxDepth cutoff, and two
// kinds of revocation. Previously that logic was only exercised by a headless
// browser smoke test, so its exact boundaries — the quorum edge, the depth
// cutoff, revoked-key vs revoked-edge filtering, and the reported depth — were
// not auditable without spinning up a browser.
//
// These tests build hand-crafted keyrings with REAL keypairs and REAL
// signatures (Node's WebCrypto provides the same Ed25519 primitive the browser
// build prefers) and assert exact depth / quorum boundaries. They deliberately
// avoid the browser and the sample-network fixture entirely.

import { beforeAll, describe, expect, it } from 'vitest';
import {
  Keyring,
  computeValidity,
  type TrustLevel,
  type TrustQuery,
  type KeyValidity,
} from '../src/engine.ts';

// --- helpers ---------------------------------------------------------------

/** Build a keyring populated with the named identities (real keypairs). */
async function ringOf(names: string[]): Promise<Keyring> {
  const ring = new Keyring();
  for (const n of names) await ring.createIdentity(n);
  return ring;
}

/** Convenience: run computeValidity with a compact ownerTrust spec. */
function query(
  me: string,
  ownerTrust: Record<string, TrustLevel>,
  policy: { marginalsNeeded: number; maxDepth: number },
): TrustQuery {
  return { me, ownerTrust: new Map(Object.entries(ownerTrust)), policy };
}

function v(map: Map<string, KeyValidity>, name: string): KeyValidity {
  const r = map.get(name);
  if (!r) throw new Error(`no validity result for ${name}`);
  return r;
}

// Sanity-check the crypto primitive once so a failure here is diagnosable and
// distinct from a logic failure below.
beforeAll(async () => {
  const ring = await ringOf(['Probe', 'Peer']);
  const cert = await ring.certify('Probe', 'Peer');
  expect('error' in cert).toBe(false);
  expect(await ring.verifyCert(cert as never)).toBe(true);
});

// --- real crypto: signatures are genuinely verified -----------------------

describe('certification signatures are real', () => {
  it('a freshly issued certification verifies', async () => {
    const ring = await ringOf(['Alice', 'Bob']);
    const cert = await ring.certify('Alice', 'Bob');
    expect('error' in cert).toBe(false);
    expect(await ring.verifyCert(cert as never)).toBe(true);
  });

  it('a certification whose signature bytes are tampered does NOT verify', async () => {
    const ring = await ringOf(['Alice', 'Bob']);
    const cert = (await ring.certify('Alice', 'Bob')) as { signatureB64: string };
    // Flip one base64 char to corrupt the signature.
    const flipped = cert.signatureB64[0] === 'A' ? 'B' : 'A';
    const forged = { ...cert, signerName: 'Alice', subjectName: 'Bob', signatureB64: flipped + cert.signatureB64.slice(1) };
    expect(await ring.verifyCert(forged as never)).toBe(false);
  });

  it("a certification cannot be re-attributed to a different signer (Alice's sig claimed as Bob's)", async () => {
    const ring = await ringOf(['Alice', 'Bob', 'Carol']);
    const cert = (await ring.certify('Alice', 'Carol')) as { signatureB64: string };
    // Same signature bytes, but claim BOB signed it. Verifying under Bob's key must fail.
    const reattributed = { signerName: 'Bob', subjectName: 'Carol', signatureB64: cert.signatureB64 };
    expect(await ring.verifyCert(reattributed as never)).toBe(false);
  });

  it("a certification cannot be replayed against a different subject", async () => {
    const ring = await ringOf(['Alice', 'Bob', 'Carol']);
    const cert = (await ring.certify('Alice', 'Bob')) as { signatureB64: string };
    // Alice's signature over "certify Bob" must not validate as "certify Carol".
    const swapped = { signerName: 'Alice', subjectName: 'Carol', signatureB64: cert.signatureB64 };
    expect(await ring.verifyCert(swapped as never)).toBe(false);
  });
});

// --- computeValidity: the anchor ------------------------------------------

describe('computeValidity — ultimate anchor', () => {
  it('your own key is valid at depth 0 regardless of certifications', async () => {
    const ring = await ringOf(['You', 'Alice']);
    const map = await computeValidity(ring, query('You', {}, { marginalsNeeded: 3, maxDepth: 5 }));
    expect(v(map, 'You').valid).toBe(true);
    expect(v(map, 'You').depth).toBe(0);
    expect(v(map, 'You').reason).toMatch(/ultimate/i);
  });

  it('a key you personally sign is valid at depth 1 (You is an implicit full introducer)', async () => {
    const ring = await ringOf(['You', 'Alice']);
    await ring.certify('You', 'Alice');
    // Note: NO owner-trust granted to You for Alice; the anchor is implicitly full.
    const map = await computeValidity(ring, query('You', {}, { marginalsNeeded: 3, maxDepth: 5 }));
    const a = v(map, 'Alice');
    expect(a.valid).toBe(true);
    expect(a.depth).toBe(1);
    expect(a.viaFull).toContain('You');
  });
});

// --- computeValidity: full vs marginal quorum ------------------------------

describe('computeValidity — full vs marginal quorum', () => {
  it('one FULL-trusted introducer validates a key', async () => {
    const ring = await ringOf(['You', 'Alice', 'Target']);
    await ring.certify('You', 'Alice'); // Alice valid at depth 1
    await ring.certify('Alice', 'Target');
    const map = await computeValidity(
      ring,
      query('You', { Alice: 'full' }, { marginalsNeeded: 3, maxDepth: 5 }),
    );
    const t = v(map, 'Target');
    expect(t.valid).toBe(true);
    expect(t.viaFull).toEqual(['Alice']);
    expect(t.depth).toBe(2);
  });

  it('a single MARGINAL introducer is NOT enough when marginalsNeeded=3', async () => {
    const ring = await ringOf(['You', 'Alice', 'Target']);
    await ring.certify('You', 'Alice');
    await ring.certify('Alice', 'Target');
    const map = await computeValidity(
      ring,
      query('You', { Alice: 'marginal' }, { marginalsNeeded: 3, maxDepth: 5 }),
    );
    expect(v(map, 'Target').valid).toBe(false);
  });

  it('quorum boundary: N-1 marginals fails, exactly N marginals passes (marginalsNeeded=3)', async () => {
    const signers = ['M1', 'M2', 'M3'];
    const ring = await ringOf(['You', ...signers, 'Target']);
    for (const s of signers) await ring.certify('You', s); // each marginal signer valid at depth 1

    const ownerTrust = Object.fromEntries(signers.map((s) => [s, 'marginal' as TrustLevel]));
    const policy = { marginalsNeeded: 3, maxDepth: 5 };

    // Two marginals → below quorum → invalid.
    await ring.certify('M1', 'Target');
    await ring.certify('M2', 'Target');
    let map = await computeValidity(ring, query('You', ownerTrust, policy));
    expect(v(map, 'Target').valid).toBe(false);
    expect(v(map, 'Target').viaMarginal).toHaveLength(0); // not reported valid at all

    // Add the third marginal → exactly at quorum → valid.
    await ring.certify('M3', 'Target');
    map = await computeValidity(ring, query('You', ownerTrust, policy));
    const t = v(map, 'Target');
    expect(t.valid).toBe(true);
    expect(t.viaMarginal.sort()).toEqual(['M1', 'M2', 'M3']);
    expect(t.viaFull).toHaveLength(0);
    expect(t.depth).toBe(2);
  });

  it('marginalsNeeded=2 makes two marginals sufficient (policy is honored, not hard-coded)', async () => {
    const ring = await ringOf(['You', 'M1', 'M2', 'Target']);
    await ring.certify('You', 'M1');
    await ring.certify('You', 'M2');
    await ring.certify('M1', 'Target');
    await ring.certify('M2', 'Target');
    const ownerTrust: Record<string, TrustLevel> = { M1: 'marginal', M2: 'marginal' };

    const strict = await computeValidity(ring, query('You', ownerTrust, { marginalsNeeded: 3, maxDepth: 5 }));
    expect(v(strict, 'Target').valid).toBe(false);

    const lax = await computeValidity(ring, query('You', ownerTrust, { marginalsNeeded: 2, maxDepth: 5 }));
    expect(v(lax, 'Target').valid).toBe(true);
  });

  it("a 'none'-trusted signer contributes nothing even if their own key is valid", async () => {
    const ring = await ringOf(['You', 'Alice', 'Target']);
    await ring.certify('You', 'Alice'); // Alice is valid...
    await ring.certify('Alice', 'Target');
    // ...but you assign Alice NO owner-trust, so she can't introduce Target.
    const map = await computeValidity(ring, query('You', { Alice: 'none' }, { marginalsNeeded: 3, maxDepth: 5 }));
    expect(v(map, 'Alice').valid).toBe(true);
    expect(v(map, 'Target').valid).toBe(false);
  });

  it('mixing one full and some marginals still validates via the full path', async () => {
    const ring = await ringOf(['You', 'F', 'M', 'Target']);
    await ring.certify('You', 'F');
    await ring.certify('You', 'M');
    await ring.certify('F', 'Target');
    await ring.certify('M', 'Target');
    const map = await computeValidity(
      ring,
      query('You', { F: 'full', M: 'marginal' }, { marginalsNeeded: 3, maxDepth: 5 }),
    );
    const t = v(map, 'Target');
    expect(t.valid).toBe(true);
    expect(t.viaFull).toEqual(['F']);
  });
});

// --- computeValidity: depth ------------------------------------------------

describe('computeValidity — depth reporting and maxDepth cutoff', () => {
  // A pure chain You -> A -> B -> C -> D, every link a full introducer.
  async function chain(): Promise<Keyring> {
    const ring = await ringOf(['You', 'A', 'B', 'C', 'D']);
    await ring.certify('You', 'A');
    await ring.certify('A', 'B');
    await ring.certify('B', 'C');
    await ring.certify('C', 'D');
    return ring;
  }
  const allFull: Record<string, TrustLevel> = { A: 'full', B: 'full', C: 'full', D: 'full' };

  it('reports the exact shortest depth along a full chain', async () => {
    const ring = await chain();
    const map = await computeValidity(ring, query('You', allFull, { marginalsNeeded: 3, maxDepth: 5 }));
    expect(v(map, 'A').depth).toBe(1);
    expect(v(map, 'B').depth).toBe(2);
    expect(v(map, 'C').depth).toBe(3);
    expect(v(map, 'D').depth).toBe(4);
    expect(v(map, 'D').valid).toBe(true);
  });

  it('maxDepth=2 cuts the chain: A and B valid, C and D not reached', async () => {
    const ring = await chain();
    const map = await computeValidity(ring, query('You', allFull, { marginalsNeeded: 3, maxDepth: 2 }));
    expect(v(map, 'A').valid).toBe(true);
    expect(v(map, 'A').depth).toBe(1);
    expect(v(map, 'B').valid).toBe(true);
    expect(v(map, 'B').depth).toBe(2);
    expect(v(map, 'C').valid).toBe(false);
    expect(v(map, 'C').depth).toBe(-1);
    expect(v(map, 'D').valid).toBe(false);
  });

  it('maxDepth=1 validates only keys You personally signed', async () => {
    const ring = await chain();
    const map = await computeValidity(ring, query('You', allFull, { marginalsNeeded: 3, maxDepth: 1 }));
    expect(v(map, 'A').valid).toBe(true);
    expect(v(map, 'B').valid).toBe(false);
  });

  it('a shorter alternate path lowers the reported depth', async () => {
    // You -> A -> Deep (depth 2) AND You -> Deep directly (depth 1).
    const ring = await ringOf(['You', 'A', 'Deep']);
    await ring.certify('You', 'A');
    await ring.certify('A', 'Deep');
    await ring.certify('You', 'Deep');
    const map = await computeValidity(ring, query('You', { A: 'full' }, { marginalsNeeded: 3, maxDepth: 5 }));
    expect(v(map, 'Deep').valid).toBe(true);
    // Reached at depth 1 via the direct You->Deep edge, not depth 2 via A.
    expect(v(map, 'Deep').depth).toBe(1);
  });
});

// --- computeValidity: revocation ------------------------------------------

describe('computeValidity — revocation filtering', () => {
  it('revoking a signer KEY drops every certification that signer made', async () => {
    // You -> Alice, Alice -> X, Alice -> Y. Revoke Alice's key: X and Y lose
    // their introducer. Alice herself stays valid (You signed her directly).
    const ring = await ringOf(['You', 'Alice', 'X', 'Y']);
    await ring.certify('You', 'Alice');
    await ring.certify('Alice', 'X');
    await ring.certify('Alice', 'Y');
    const q = query('You', { Alice: 'full' }, { marginalsNeeded: 3, maxDepth: 5 });

    const before = await computeValidity(ring, q);
    expect(v(before, 'X').valid).toBe(true);
    expect(v(before, 'Y').valid).toBe(true);

    await ring.revokeKey('Alice');
    const after = await computeValidity(ring, q);
    expect(v(after, 'Alice').valid).toBe(true); // still directly signed by You
    expect(v(after, 'X').valid).toBe(false);
    expect(v(after, 'Y').valid).toBe(false);
  });

  it('revoking a single EDGE drops only that certification, not the signer\'s others', async () => {
    const ring = await ringOf(['You', 'Alice', 'X', 'Y']);
    await ring.certify('You', 'Alice');
    await ring.certify('Alice', 'X');
    await ring.certify('Alice', 'Y');
    const q = query('You', { Alice: 'full' }, { marginalsNeeded: 3, maxDepth: 5 });

    await ring.revokeCert('Alice', 'X'); // retract only Alice->X
    const map = await computeValidity(ring, q);
    expect(v(map, 'X').valid).toBe(false); // this edge gone
    expect(v(map, 'Y').valid).toBe(true); // Alice's other cert survives
    expect(v(map, 'Alice').valid).toBe(true);
  });

  it('a revocation with a forged signature has NO effect (must verify to take hold)', async () => {
    const ring = await ringOf(['You', 'Alice', 'X']);
    await ring.certify('You', 'Alice');
    await ring.certify('Alice', 'X');
    const q = query('You', { Alice: 'full' }, { marginalsNeeded: 3, maxDepth: 5 });

    // Inject a bogus, unsigned revocation directly into the ring.
    ring.revocations.push({ type: 'cert', signerName: 'Alice', subjectName: 'X', signatureB64: 'AAAA' });
    const map = await computeValidity(ring, q);
    // Forged revocation ignored → X stays valid.
    expect(v(map, 'X').valid).toBe(true);
  });

  it('a key revocation signed by the wrong key does not take effect', async () => {
    const ring = await ringOf(['You', 'Alice', 'Mallory', 'X']);
    await ring.certify('You', 'Alice');
    await ring.certify('Alice', 'X');
    const q = query('You', { Alice: 'full' }, { marginalsNeeded: 3, maxDepth: 5 });

    // Mallory tries to revoke Alice's key by signing the key-revocation payload
    // for Alice with Mallory's own key. verifyRevocation checks the signature
    // under signerName's key AND the payload names the subject, so a self-
    // revocation forged by a third party must be rejected.
    const mallorysRevoke = (await ring.revokeKey('Mallory')) as { signatureB64: string };
    ring.revocations.push({
      type: 'key',
      signerName: 'Alice',
      subjectName: 'Alice',
      signatureB64: mallorysRevoke.signatureB64,
    });
    const map = await computeValidity(ring, q);
    expect(v(map, 'X').valid).toBe(true); // Alice not actually revoked
  });
});

// --- computeValidity: forgery rejection end-to-end ------------------------

describe('computeValidity — forged certifications never confer validity', () => {
  it('a certification with a corrupted signature is not counted in the walk', async () => {
    const ring = await ringOf(['You', 'Alice', 'Stranger']);
    await ring.certify('You', 'Alice');
    const good = (await ring.certify('Alice', 'Stranger')) as { signatureB64: string };
    const q = query('You', { Alice: 'full' }, { marginalsNeeded: 3, maxDepth: 5 });

    // Baseline: with the real signature, Stranger is valid.
    expect(v(await computeValidity(ring, q), 'Stranger').valid).toBe(true);

    // Corrupt the stored signature bytes in place.
    good.signatureB64 = (good.signatureB64[0] === 'A' ? 'B' : 'A') + good.signatureB64.slice(1);
    const map = await computeValidity(ring, q);
    expect(v(map, 'Stranger').valid).toBe(false);
    expect(v(map, 'Stranger').reason).toMatch(/no trusted path|unknown/i);
  });

  it('an entirely unsigned (fabricated) certification is rejected', async () => {
    const ring = await ringOf(['You', 'Alice', 'Ghost']);
    await ring.certify('You', 'Alice');
    // Push a cert that was never actually signed.
    ring.certs.push({ signerName: 'Alice', subjectName: 'Ghost', signatureB64: 'Zm9yZ2Vk' });
    const map = await computeValidity(ring, query('You', { Alice: 'full' }, { marginalsNeeded: 3, maxDepth: 5 }));
    expect(v(map, 'Ghost').valid).toBe(false);
  });
});

// --- computeValidity: unreachable keys & reasons ---------------------------

describe('computeValidity — unreachable keys and reason strings', () => {
  it('a key with no certifications is reported as unknown', async () => {
    const ring = await ringOf(['You', 'Nobody']);
    const map = await computeValidity(ring, query('You', {}, { marginalsNeeded: 3, maxDepth: 5 }));
    expect(v(map, 'Nobody').valid).toBe(false);
    expect(v(map, 'Nobody').depth).toBe(-1);
    expect(v(map, 'Nobody').reason).toMatch(/unknown key/i);
  });

  it('a key signed only by an untrusted-and-invalid signer notes no trusted path', async () => {
    // Orphan signs Target, but nobody vouches for Orphan and Orphan has no trust.
    const ring = await ringOf(['You', 'Orphan', 'Target']);
    await ring.certify('Orphan', 'Target');
    const map = await computeValidity(ring, query('You', { Orphan: 'full' }, { marginalsNeeded: 3, maxDepth: 5 }));
    expect(v(map, 'Orphan').valid).toBe(false);
    const t = v(map, 'Target');
    expect(t.valid).toBe(false);
    expect(t.reason).toMatch(/no trusted path/i);
  });
});
