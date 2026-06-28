# crypto-lab-web-of-trust

## What It Is

An interactive model of the PGP/OpenPGP **Web of Trust** using real signatures via the Web Crypto API. Identities sign each other's keys (certifications) with Ed25519 — and the engine automatically falls back to ECDSA P-256 on runtimes that lack Ed25519 — and then the GnuPG-style trust computation decides which keys are VALID from your point of view, based on owner-trust (full / marginal / none), a marginals-needed quorum, and a maximum trust depth. Only certifications whose signatures actually verify cryptographically are counted. The point is to make a decentralized trust model concrete: deciding which public keys are real **without** a central authority, by walking a graph of signatures through people you have chosen to trust. Every primitive — keypair generation, signing, signature verification, and the trust walk — is real TypeScript running in the browser. What is deliberately **not** modelled is the OpenPGP packet / armor format: certifications here are plain JSON, not RFC 4880 binary packets. This is a faithful model of the trust logic, not a re-implementation of GnuPG's wire format.

## When to Use It

- **Understanding GPG / PGP trust** — make owner-trust, key validity, marginals-needed, and trust depth concrete by watching them change live.
- **Contrasting decentralized vs hierarchical trust** — read alongside the sibling [`crypto-lab-pki-chain`](https://systemslibrarian.github.io/crypto-lab-pki-chain/) demo, which walks the CA / PKI model in the opposite direction.
- **Teaching owner-trust vs validity** — these are different things, and the distinction is the most common GnuPG stumbling block.
- **Reasoning about key-signing parties** — see why the bootstrap matters and what a single over-trusted introducer does to your trust frontier.
- **Do NOT use this for production key management** — Web of Trust does not scale to trusting strangers at web scale; that is exactly why TLS uses hierarchical PKI instead. This toy model is for learning, not for managing real keys. For real OpenPGP use GnuPG (`gpg`), Sequoia-PGP, or a vetted library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-web-of-trust](https://systemslibrarian.github.io/crypto-lab-web-of-trust/)**

The page walks through six sections. **The keyring** generates a small social graph of real keypairs in your browser (You, Alice, Bob, Carol, Dave, Eve, Frank, Heretic, Stranger) and the certifications between them, and lets you add your own. **Your trust settings** let you assign owner-trust (full / marginal / none) to each non-you identity and adjust the policy — `marginalsNeeded` (default 3) and `maxDepth` (default 5) — matching GnuPG's defaults. **Compute web of trust** runs the validity computation and shows every key with a valid / invalid badge, the depth it was validated at, and the reason. **Break trust** runs four scenarios: a forged certification (the bogus signature fails to verify and the target stays invalid — the crypto enforces this, not policy), an orphan key nobody trusted has signed, an over-trusted introducer that suddenly validates a downstream key, and a depth cutoff that drops distant keys. The remaining sections compare Web of Trust to hierarchical PKI and explain where the model is actually deployed today (GnuPG, key-signing parties, Linux distribution signing, the SKS keyserver flooding incident, sigstore-style attestations).

## What Can Go Wrong

- A single over-trusted introducer becomes a chokepoint: marking the wrong identity "fully trusted" can validate every key it has signed, including malicious ones.
- The bootstrap problem: a brand-new key nobody has certified has no path to validity, which is why key-signing parties and trusted introducers matter.
- Web of Trust does not scale to trusting strangers — the model breaks down at web scale, which is precisely why TLS adopted hierarchical PKI instead.
- Forged certifications are caught only because signatures are verified cryptographically; trust policy alone never makes a bad signature valid.
- Keyserver and distribution risks are real: the SKS keyserver certificate-flooding incident showed how unauthenticated certification attachment can be abused; revocation and key hygiene remain hard in practice.

## Real-World Usage

- GnuPG (`gpg`) and Sequoia-PGP implement the OpenPGP Web of Trust for email and file signing/encryption.
- Key-signing parties and trusted-introducer setups bootstrap validity within communities and organizations.
- Linux distributions sign packages and releases with PGP keys, with trust rooted in maintainer keys.
- The SKS keyserver network historically distributed OpenPGP certifications (and exposed the flooding-attack weakness).
- Modern attestation systems such as sigstore echo the same web-of-attestation idea in a different form.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-web-of-trust
cd crypto-lab-web-of-trust
npm install
npm run dev
```

## Related Demos
- [crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/) — the hierarchical CA/PKI trust model, the direct contrast to Web of Trust.
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — the Ed25519 signatures that back each certification here.
- [crypto-lab-ssh-handshake](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/) — trust-on-first-use, another decentralized key-trust model.
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — Merkle inclusion proofs and Certificate Transparency, the auditability layer for PKI.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
