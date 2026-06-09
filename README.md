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

[**https://systemslibrarian.github.io/crypto-lab-web-of-trust/**](https://systemslibrarian.github.io/crypto-lab-web-of-trust/)

The page walks through six sections. **The keyring** generates a small social graph of real keypairs in your browser (You, Alice, Bob, Carol, Dave, Eve, Frank, Heretic, Stranger) and the certifications between them, and lets you add your own. **Your trust settings** let you assign owner-trust (full / marginal / none) to each non-you identity and adjust the policy — `marginalsNeeded` (default 3) and `maxDepth` (default 5) — matching GnuPG's defaults. **Compute web of trust** runs the validity computation and shows every key with a valid / invalid badge, the depth it was validated at, and the reason. **Break trust** runs four scenarios: a forged certification (the bogus signature fails to verify and the target stays invalid — the crypto enforces this, not policy), an orphan key nobody trusted has signed, an over-trusted introducer that suddenly validates a downstream key, and a depth cutoff that drops distant keys. The remaining sections compare Web of Trust to hierarchical PKI and explain where the model is actually deployed today (GnuPG, key-signing parties, Linux distribution signing, the SKS keyserver flooding incident, sigstore-style attestations).

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-web-of-trust.git
cd crypto-lab-web-of-trust
npm install
npm run dev      # local dev server with HMR
npm run build    # type-check + production build to dist/
npm run preview  # serve the built dist/ locally
```

No environment variables, no API keys, no servers. Everything runs client-side in the browser.

## Part of the Crypto-Lab Suite

This is one demo in a wider portfolio of interactive cryptography labs — see [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) for the rest, including the five PQC families overview, hybrid TLS, harvest-now-decrypt-later timelines, and deep-dives on individual schemes.

---

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31
