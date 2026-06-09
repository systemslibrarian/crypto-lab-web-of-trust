// engine.ts — a model of the PGP/OpenPGP Web of Trust using REAL signatures
// via Web Crypto. Each identity has a signing keypair. Users sign each OTHER's
// keys (certifications). Whether YOU should trust a key is then computed from
// the GnuPG-style trust model:
//   * owner-trust: how much you trust a key's owner to vouch for others
//     (full / marginal / none) — this is YOUR opinion, not cryptographic.
//   * a key is VALID if it is signed by >= 1 fully-trusted introducer, OR by
//     >= `marginalsNeeded` marginally-trusted introducers, within `maxDepth`.
//   * all certifications are REAL signatures and are verified before counting.
// This is NOT the OpenPGP packet format; it models the trust logic faithfully.

const enc = new TextEncoder();

// Prefer Ed25519; fall back to ECDSA P-256 if the runtime lacks it.
let ALGO: EcKeyGenParams | { name: 'Ed25519' };
let SIGN: AlgorithmIdentifier | EcdsaParams;
let usingEd = true;
try {
    // feature-detect at module load is awkward; we resolve lazily in init()
} catch {
    /* noop */
}

async function init(): Promise<void> {
    if (ALGO) return;
    try {
        const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
            'sign',
            'verify',
        ])) as CryptoKeyPair;
        void kp;
        ALGO = { name: 'Ed25519' };
        SIGN = { name: 'Ed25519' };
        usingEd = true;
    } catch {
        ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
        SIGN = { name: 'ECDSA', hash: 'SHA-256' };
        usingEd = false;
    }
}

export function signingAlgoName(): string {
    return usingEd ? 'Ed25519' : 'ECDSA P-256';
}

function b64(buf: ArrayBuffer): string {
    const u = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s);
}
function unb64(s: string): Uint8Array {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

export type TrustLevel = 'full' | 'marginal' | 'none';

export interface Identity {
    name: string;
    publicKeyJwk: JsonWebKey;
    fingerprint: string; // short hex of the public key
}

interface PrivateIdentity extends Identity {
    privateKey: CryptoKey;
}

// A certification: signer asserts "this key really belongs to <subjectName>".
export interface Certification {
    signerName: string;
    subjectName: string;
    signatureB64: string;
}

async function fingerprintOf(jwk: JsonWebKey): Promise<string> {
    const material = (jwk.x ?? '') + (jwk.y ?? '');
    const d = await crypto.subtle.digest('SHA-256', enc.encode(material) as BufferSource);
    return Array.from(new Uint8Array(d))
        .slice(0, 8)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

// the bytes a certification signs: subject name + subject public key
function certBytes(subject: Identity): Uint8Array {
    return enc.encode(`certify:${subject.name}:${subject.fingerprint}`);
}

export class Keyring {
    private people = new Map<string, PrivateIdentity>();
    certs: Certification[] = [];

    async createIdentity(name: string): Promise<Identity> {
        await init();
        const kp = (await crypto.subtle.generateKey(ALGO, true, ['sign', 'verify'])) as CryptoKeyPair;
        const publicKeyJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
        const fingerprint = await fingerprintOf(publicKeyJwk);
        const id: PrivateIdentity = { name, publicKeyJwk, fingerprint, privateKey: kp.privateKey };
        this.people.set(name, id);
        return { name, publicKeyJwk, fingerprint };
    }

    identity(name: string): Identity | undefined {
        const p = this.people.get(name);
        if (!p) return undefined;
        return { name: p.name, publicKeyJwk: p.publicKeyJwk, fingerprint: p.fingerprint };
    }

    allNames(): string[] {
        return [...this.people.keys()];
    }

    // signer certifies subject's key (a real signature)
    async certify(signerName: string, subjectName: string): Promise<Certification | { error: string }> {
        const signer = this.people.get(signerName);
        const subject = this.people.get(subjectName);
        if (!signer || !subject) return { error: 'Unknown identity.' };
        await init();
        const sig = await crypto.subtle.sign(SIGN, signer.privateKey, certBytes(subject) as BufferSource);
        const cert: Certification = { signerName, subjectName, signatureB64: b64(sig) };
        this.certs.push(cert);
        return cert;
    }

    // verify a single certification's signature is real and valid
    async verifyCert(cert: Certification): Promise<boolean> {
        const signer = this.people.get(cert.signerName);
        const subject = this.people.get(cert.subjectName);
        if (!signer || !subject) return false;
        try {
            await init();
            const key = await crypto.subtle.importKey('jwk', signer.publicKeyJwk, ALGO, false, ['verify']);
            return await crypto.subtle.verify(
                SIGN,
                key,
                unb64(cert.signatureB64) as BufferSource,
                certBytes(subject) as BufferSource,
            );
        } catch {
            return false;
        }
    }
}

// --- trust computation -----------------------------------------------------
export interface TrustPolicy {
    marginalsNeeded: number; // how many marginal introducers = one valid key (GnuPG default 3)
    maxDepth: number; // how far trust may chain (GnuPG default 5)
}

export interface TrustQuery {
    me: string; // the name of "you" (your key is your ultimate anchor)
    ownerTrust: Map<string, TrustLevel>; // YOUR trust in each owner as an introducer
    policy: TrustPolicy;
}

export interface KeyValidity {
    name: string;
    valid: boolean;
    reason: string;
    depth: number; // shortest validation depth from you
    viaFull: string[]; // fully-trusted introducers who signed it
    viaMarginal: string[]; // marginally-trusted introducers who signed it
}

// Compute which keys are VALID from your point of view. Only certifications
// that VERIFY cryptographically are counted. A key is valid if reachable from
// you through introducers you trust, per the policy, within maxDepth.
export async function computeValidity(
    ring: Keyring,
    query: TrustQuery,
): Promise<Map<string, KeyValidity>> {
    // keep only real, verifying certifications
    const goodCerts: Certification[] = [];
    for (const c of ring.certs) {
        if (await ring.verifyCert(c)) goodCerts.push(c);
    }

    const result = new Map<string, KeyValidity>();
    // your own key is ultimately valid at depth 0
    result.set(query.me, { name: query.me, valid: true, reason: 'Your own key (ultimate trust).', depth: 0, viaFull: [], viaMarginal: [] });

    // iteratively expand validity up to maxDepth. A signer can confer validity
    // only if THEIR key is already valid AND you assign them owner-trust.
    // iteratively expand validity up to maxDepth. Each pass uses only the keys
    // that were valid BEFORE the pass began (snapshot), so a key validated in
    // pass N is at depth N and cannot also confer validity within the same pass.
    for (let depth = 1; depth <= query.policy.maxDepth; depth++) {
        const validBefore = new Set([...result.entries()].filter(([, v]) => v.valid).map(([k]) => k));
        let changed = false;
        for (const subject of ring.allNames()) {
            if (result.has(subject) && result.get(subject)!.valid) continue;

            const fulls: string[] = [];
            const marginals: string[] = [];
            for (const c of goodCerts) {
                if (c.subjectName !== subject) continue;
                if (!validBefore.has(c.signerName)) continue; // signer valid in a PRIOR layer
                // You (the anchor) are an implicit fully-trusted introducer for keys
                // you personally sign; otherwise use your assigned owner-trust.
                const t = c.signerName === query.me ? 'full' : query.ownerTrust.get(c.signerName) ?? 'none';
                if (t === 'full') fulls.push(c.signerName);
                else if (t === 'marginal') marginals.push(c.signerName);
            }

            const valid = fulls.length >= 1 || marginals.length >= query.policy.marginalsNeeded;
            if (valid) {
                const reason = fulls.length
                    ? `Signed by fully-trusted ${fulls.join(', ')}.`
                    : `Signed by ${marginals.length} marginally-trusted introducers (need ${query.policy.marginalsNeeded}).`;
                result.set(subject, { name: subject, valid: true, reason, depth, viaFull: fulls, viaMarginal: marginals });
                changed = true;
            }
        }
        if (!changed) break;
    }

    // anything still unset is not valid
    for (const name of ring.allNames()) {
        if (!result.has(name)) {
            // report why: collect any signers but note insufficient trust/path
            const signers = ring.certs.filter((c) => c.subjectName === name).map((c) => c.signerName);
            const reason = signers.length
                ? `Signed by ${signers.join(', ')}, but no trusted path reaches them.`
                : 'No certifications — unknown key.';
            result.set(name, { name, valid: false, reason, depth: -1, viaFull: [], viaMarginal: [] });
        }
    }

    return result;
}

export function shortFp(fp: string): string {
    return fp.toUpperCase().match(/.{1,4}/g)?.join(' ') ?? fp;
}
