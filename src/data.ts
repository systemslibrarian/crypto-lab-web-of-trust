// data.ts — narrative corpus for the Web-of-Trust demo.
//
// The crypto and trust logic live in engine.ts. Everything here is plain
// content the UI renders into cards and tables: how WoT contrasts with the
// hierarchical PKI model (the sibling crypto-lab-pki-chain demo), the GnuPG
// trust vocabulary, the real-world pitfalls of the model, and where it is
// still used in practice.

export interface ComparisonRow {
	axis: string;
	wot: string;
	pki: string;
}

// Side-by-side: Web of Trust vs the hierarchical CA / PKI model.
// Sibling demo: crypto-lab-pki-chain covers the PKI side at length.
export const WOT_VS_PKI: ComparisonRow[] = [
	{
		axis: 'Root of trust',
		wot: 'You. There is no central authority — you decide which keys to trust as introducers.',
		pki: 'A small set of root CAs your OS or browser ships in a root store.',
	},
	{
		axis: 'How a new key becomes trusted',
		wot: 'Someone you trust signs it (a certification). Trust flows through the social graph.',
		pki: 'A CA validates the request and issues a certificate. The CA signature is the chain link.',
	},
	{
		axis: 'How trust is delegated',
		wot: 'You assign owner-trust (full / marginal / none) to each key. Marginal trust accumulates.',
		pki: 'Implicit: any CA in the root store can issue for any name. CAA records and Certificate Transparency are the limits.',
	},
	{
		axis: 'Shape of the trust structure',
		wot: 'A directed graph through people. Many paths can reach the same key.',
		pki: 'A tree: root → intermediate(s) → leaf. One chain per certificate.',
	},
	{
		axis: 'Revocation',
		wot: 'Owner publishes a revocation certificate; you re-fetch keys / refresh from a keyserver.',
		pki: 'CRL or OCSP from the issuing CA; short-lived certificates increasingly preferred.',
	},
	{
		axis: 'Failure mode',
		wot: 'A user assigning full trust to a careless introducer validates whatever that introducer signs.',
		pki: 'A single mis-issuing CA can mint a trusted certificate for any name on the internet.',
	},
	{
		axis: 'Where it is actually used',
		wot: 'GnuPG / OpenPGP email signing, package signing, key-signing parties.',
		pki: 'TLS for the web (essentially universal), code-signing for OS binaries, S/MIME.',
	},
];

export interface ConceptCard {
	title: string;
	body: string;
}

// Owner-trust vs key validity, marginals-needed, depth. These are the
// distinctions that confuse new GnuPG users — they are deliberately separated
// in the engine so the UI can demonstrate the difference.
export const TRUST_CONCEPTS: ConceptCard[] = [
	{
		title: 'Owner-trust vs key validity',
		body: 'They are different things. Validity is "is this public key really this person\'s?" Owner-trust is "do I rely on this person to vouch for other people\'s keys?" A key can be valid (you know it\'s really Alice) without you trusting Alice as an introducer (you don\'t want Alice\'s signatures alone to validate strangers).',
	},
	{
		title: 'Full / marginal / none',
		body: 'Full trust: one signature from this person is enough to validate a key. Marginal: their signature counts toward a quorum. None: their signatures do not contribute to validity at all. You assign these yourself — they are your opinion, not a property of the key.',
	},
	{
		title: 'Marginals needed (GnuPG default 3)',
		body: 'A key becomes valid if it has at least one fully-trusted signer OR at least N marginally-trusted signers, where N is your `marginalsNeeded` setting. Lower N is more permissive; higher N requires broader consensus.',
	},
	{
		title: 'Trust depth (GnuPG default 5)',
		body: 'A cap on how far trust may chain through introducers. Depth 1 means only keys you personally signed are valid; depth 2 also covers keys signed by your introducers, and so on. Beyond `maxDepth`, the chain breaks even if every link is trusted.',
	},
	{
		title: 'Ultimate trust (that\'s you)',
		body: 'Your own key sits at depth 0 as an ultimate anchor. The engine also treats certifications YOU make as fully-trusted introductions, regardless of how you set owner-trust on yourself — because the whole computation is "from your point of view".',
	},
];

export interface LessonCard {
	title: string;
	body: string;
}

// Real-world WoT failure modes. None of these are theoretical; they have
// burned PGP users and keyserver operators repeatedly.
export const FAILURE_LESSONS: LessonCard[] = [
	{
		title: 'Over-trusted introducer = wide blast radius',
		body: 'If you grant full trust to someone who is sloppy about key-signing, every key they sign becomes valid for you — including ones they signed without actually verifying identity. WoT pushes the trust decision to humans, and humans are inconsistent.',
	},
	{
		title: 'No trust path to the person you need',
		body: 'You want to send encrypted mail to a journalist on the other side of the world. Nobody you trust has signed their key. Strict WoT says "unknown key" and refuses. PGP users routinely override this, which weakens the model in practice.',
	},
	{
		title: 'WoT does not scale to strangers',
		body: 'Trust has to bootstrap from someone. For email between people who have met (or attend the same conferences) it works. For arbitrary parties on the internet — say, a website you have never visited — it is unworkable. That is why TLS uses PKI, not WoT.',
	},
	{
		title: 'A click is not identity verification',
		body: 'Signing a key is supposed to mean "I checked their government ID, compared fingerprints in person, and confirmed they control the private half." In practice many signatures attest to far less. The model assumes diligent humans; the keyservers cannot enforce that assumption.',
	},
];

export interface RealWorldNote {
	title: string;
	body: string;
}

// Where the model is actually deployed, and where it has cracked.
export const REAL_WORLD: RealWorldNote[] = [
	{
		title: 'GnuPG / OpenPGP',
		body: 'GnuPG (GPG) is the reference implementation of OpenPGP (RFC 4880 / RFC 9580). Its trust database stores exactly the things modelled here: a keyring of public keys with certifications between them, plus your private owner-trust assignments. `gpg --check-trustdb` runs the validity computation; `gpg --edit-key … trust` is where you set full / marginal / none.',
	},
	{
		title: 'Key-signing parties',
		body: 'The traditional bootstrap mechanism: people gather, exchange fingerprints printed on paper, check government ID, and afterwards sign each other\'s keys at home. The output is a flurry of new certifications that thicken the WoT graph. Still practiced at conferences such as FOSDEM and DebConf.',
	},
	{
		title: 'The SKS keyserver problem',
		body: 'The SKS keyserver network was append-only and accepted any signature from anyone. Attackers exploited this in 2019 to flood high-profile keys (Robert J. Hansen, Daniel Kahn Gillmor) with hundreds of thousands of bogus certifications, making the keys unusable in GnuPG. SKS was effectively retired; keys.openpgp.org now requires email-confirmed uploads and strips third-party signatures by default.',
	},
	{
		title: 'Why TLS chose hierarchical PKI instead',
		body: 'The web needs strangers to talk to strangers, billions of times per day, without any prior social link. WoT cannot bootstrap that. Hierarchical PKI delegates the verification work to a small set of CAs, which is its own failure mode — but it is the failure mode the web accepted. WoT remains the standard for email and code-signing where the participants do know each other.',
	},
	{
		title: 'Where WoT-style trust persists',
		body: 'Linux distribution signing keys (Debian, Arch, Fedora) are validated through PGP and a developer WoT. Reproducible-build attestations and some software-supply-chain projects (sigstore, in-toto) use related ideas. The mechanism is not dead — it just lost the web.',
	},
];
