# DIDs, Key Management and Recovery

A decentralised identifier (DID) is a URI such as `did:example:123` that resolves to a **DID document** listing public keys and service endpoints. The W3C published DID Core 1.0 as a Recommendation in 2022. A DID lets an issuer, holder or verifier publish keys without a certificate authority. That shifts the hard problems to key management: generation, rotation, recovery and revocation, with nobody to call when things go wrong.

## DID methods differ in where trust sits

The DID Core spec defines the data model; each **DID method** defines how to create, resolve, update and deactivate DIDs. Security depends almost entirely on the method.

| Method style | Example | Where truth lives | Main risks |
|---|---|---|---|
| Key-derived | `did:key` | The identifier *is* the public key | No rotation possible; key loss or compromise means a new identity |
| Web-hosted | `did:web` | A JSON file on an HTTPS domain | DNS/TLS/hosting compromise rewrites keys; domain expiry; no history |
| Ledger-anchored | `did:ethr`, other chain methods | Smart contract or ledger state | Contract bugs; controller key compromise; resolver trusting a single RPC |
| Peer | `did:peer` | Exchanged between parties | Not publicly verifiable; fine for pairwise links |

For issuers, `did:web` is common because it is easy: the issuer's domain becomes its root of trust, which is a regression to Web PKI with fewer checks (no Certificate Transparency for DID documents). For holders, pairwise or key-derived DIDs avoid creating one global correlation handle. A single public DID used everywhere links all activity together.

## Lessons from the DKMS report

The *DKMS Requirements Report* (Drummond Reed et al., DHS Science & Technology Directorate, 2017), with contributors from Evernym, Digital Bazaar, BYU and others, analysed decentralised key management against NIST SP 800-130 (the framework for cryptographic key management systems). Points that still apply:

- **Decentralisation is hardest at recovery.** The report notes the need to stay decentralised "is most acute when it comes to key recovery". Recovery that falls back to a central service rebuilds the central point of failure the system was designed to avoid.
- **Account recovery by security questions fails.** The report repeats that security-question recovery "has been shown repeatedly" to be weak.
- **Social recovery and guardianship** were listed as requirements, together with delegation for people who cannot manage keys themselves.
- **Usability was unstudied.** The report says there had been "no prior usability studies of key recovery and key portability". Usability failures become security failures when users copy seed phrases into cloud notes.

## Key events and their failure modes

| Event | Correct handling | Failure mode |
|---|---|---|
| Rotation | Update DID document; old key marked revoked from a time | Verifiers cache old documents; old signatures accepted after compromise |
| Compromise | Rotate, then revoke credentials signed after the compromise time | No way to say *when* the key was compromised; all past credentials suspect |
| Loss | Recover via guardians, backup or controller key | Identity permanently lost (`did:key`); or recovery path is weaker than the key |
| Deactivation | Mark DID deactivated | Resolvers ignore the flag; credentials keep verifying |

**Timestamps matter.** To revoke "everything signed after the compromise", verifiers need trustworthy signing times. If credentials carry only issuer-asserted dates, an attacker with the key can backdate. Anchoring issuance events (for example, in a status list or on a ledger) gives a time reference.

## Resolver security

A verifier never sees a DID directly; it asks a resolver. Questions to ask:

- Does the resolver use a single RPC endpoint or HTTP fetch that an attacker could spoof? Use several sources or a light client for ledger methods.
- Does it cache, and for how long? Long caches delay revocation.
- Does it check method-specific integrity (for example, that a `did:web` document is served over valid TLS, with the expected path)?
- What does it do on failure: fail open (accept) or fail closed (reject)?

## Wallet keys and holder DIDs

Holder keys sit in wallets: mobile apps, browser extensions, hardware or passkeys. Hardware-backed, non-exportable keys give strong holder binding (Chapter 5) but make backup harder. Many wallets export keys for backup, which weakens non-transferability: a holder can hand a credential and its key to someone else. Decide which property matters more for each use case. For wallet authentication patterns see **passkeys-webauthn-web3**, and for smart-account recovery see **account-abstraction-security**.

## Worked example

*Execution status: Not executed in this book's CI; verify locally. Uses a local web server and synthetic keys only.*

Simulate a `did:web` takeover and a cached-resolver delay:

1. Generate two Ed25519 key pairs with `openssl genpkey -algorithm ed25519`.
2. Write a DID document `did.json` for `did:web:localhost%3A8443` containing key 1, and serve it over HTTPS on localhost with a self-signed certificate trusted by your test machine.
3. Sign a small JSON credential with key 1 and write a verifier script (Python `cryptography` or Node `jose`) that resolves the DID, fetches the key and checks the signature.
4. Replace `did.json` with one containing key 2 (simulating a hosting compromise). Sign a forged credential with key 2 and confirm the verifier accepts it. Note that nothing records the change.
5. Add a cache with a one-hour TTL to the verifier and repeat the rotation the other way (legitimate rotation away from a compromised key). Measure how long the verifier keeps accepting the compromised key.
6. Write down which controls would have detected step 4: document hash pinning, transparency logs, ledger anchoring or monitoring.

## Common pitfalls

- Using one public DID for a holder everywhere, creating a global correlation handle.
- Issuers relying on `did:web` without monitoring the hosted document.
- Recovery flows weaker than the keys they recover.
- No trustworthy timestamps, so compromise windows cannot be bounded.
- Resolvers that fail open or cache for days.

## Exercises

1. Complete the `did:web` exercise and add a monitor that alerts when the document hash changes.
2. Compare three DID methods for an issuer use case and recommend one, with reasons.
3. Design a guardian-based recovery flow for a holder wallet and list its attack paths (guardian collusion, phishing guardians, lost guardians).

## Further reading

- D. Reed et al., *DKMS Requirements Report*, DHS S&T SBIR deliverable (2017).
- W3C DID Core 1.0: <https://www.w3.org/TR/did-core/>
- W3C DID Specification Registries (methods): <https://www.w3.org/TR/did-spec-registries/>
- NIST SP 800-130, *A Framework for Designing Cryptographic Key Management Systems*: <https://csrc.nist.gov/pubs/sp/800/130/final>
- See **name-service-attacks** for domain and naming risks.
