# Reviewing Identity Systems: Correlation Attacks and a Checklist

This chapter has two parts. First, it collects the correlation attacks that break privacy claims in otherwise sound systems. Second, it gives a review checklist covering the whole book. Test only systems you are authorised to assess, use synthetic identities and test credentials, never real people's documents, and report issues through the project's disclosure channel.

## Correlation attacks

Cryptography decides what a single presentation reveals. Correlation decides what many presentations reveal together. Giovanni Livraga's *Protecting Privacy in Data Release* (Springer, 2015) gives the classic warning from data publishing: removing explicit identifiers "does not provide any guarantee of anonymity", because quasi-identifiers can be linked with public data. It cites a study of 2000 US Census data in which 63% of the population could be uniquely identified by gender, ZIP code and full date of birth. Disclosed credential attributes are quasi-identifiers in exactly this sense.

| Correlation handle | Where it appears | Attack | Mitigation |
|---|---|---|---|
| Stable signature or digests | SD-JWT presentations | Colluding verifiers match identical values | Batch issuance, one-time use; BBS proofs |
| Holder DID or key | Key binding, DID auth | Same public key at every verifier | Pairwise DIDs; per-verifier keys; ZK binding |
| Status-list index | Revocation | Index identifies the credential | Large lists; holder-side ZK non-revocation |
| Nullifier with reused scope | Semaphore-style proofs | Same nullifier across apps sharing a scope | Scope per app and action; avoid global scopes |
| Nullifier from public data | Document-number hashes | Anyone recomputes and links | Derive from holder secret |
| Disclosed attribute combination | Age bracket + region + issuer | Quasi-identifier linking (Livraga) | Predicates instead of values; coarse values |
| Small anonymity set | Small groups or rare issuers | "One of five members" is not anonymous | Minimum group size before proofs are accepted |
| Timing | Proof shortly after group join or credential issuance | Join-then-prove timing links identity to commitment | Delay; batch joins; encourage later use |
| Gas payer and funding | On-chain proofs sent from the user's main wallet | Chain analysis links proof to wallet | Relayers; fresh accounts funded privately |
| Device and network metadata | Wallet fingerprint, IP, user agent | Verifier logs link sessions | Minimise logs; network privacy tools |

Two patterns cause most real failures. **On-chain proofs from identified wallets**: a perfect Semaphore proof submitted from the user's well-known address is not anonymous. **Join-then-prove**: if a group adds one member at 10:00 and a proof arrives at 10:01, the anonymity set is one. Chain-analysis techniques from **onchain-malware-analysis** and **airdrop-sybil-detection** work equally well against identity users.

## Review checklist

### A. Claims and properties

- [ ] The project states which ENISA properties (unforgeability, unlinkability, non-transferability, revocability, escrow) it claims, and against whom.
- [ ] Marketing claims ("anonymous", "private") match the technical properties.
- [ ] Minimum anonymity-set sizes are defined and enforced.

### B. Identifiers and keys

- [ ] DID methods for issuers and holders are justified; holders do not reuse one public DID everywhere.
- [ ] Issuer key rotation, compromise handling and trustworthy issuance times exist.
- [ ] Resolvers fail closed, use more than one source for ledger methods and cache for bounded times.
- [ ] Recovery is not weaker than the key it recovers.

### C. Selective disclosure

- [ ] SD-JWT salts are 128-bit random, per claim; decoys used where claim counts are sensitive.
- [ ] KB-JWT requires and checks verifier-chosen `nonce` and `aud`.
- [ ] Batch issuance and one-time use exist where unlinkability is claimed; time claims are rounded or randomised.
- [ ] BBS deployments list remaining correlation handles (binding, revocation, metadata).

### D. ZK proofs and nullifiers

- [ ] Nullifiers derive from a holder secret, per scope; scopes are specific to app and action.
- [ ] Used-nullifier state persists across upgrades and redeployments.
- [ ] Proofs bind message, recipient, chain ID and contract.
- [ ] Root-history windows match revocation needs.
- [ ] Circuits are audited for missing constraints, signature checks and Fiat–Shamir issues (see **zk-circuit-security**).
- [ ] For document proofs: country-root list is curated and updated; multiple documents per person and renewal are addressed.

### E. Issuers, revocation and binding

- [ ] Trust registry changes are governed, time-locked and monitored.
- [ ] Signed attestations include domain, function, recipient (`msg.sender`), nonce and expiry.
- [ ] Revocation mechanism and its privacy leak are documented; caches and fail modes are tested.
- [ ] Holder binding strength matches the use case; key export is considered.

### F. Correlation and metadata

- [ ] Every value a verifier receives is listed and classified as fresh or stable.
- [ ] On-chain proofs can be submitted through relayers or fresh accounts.
- [ ] Logs at verifiers and issuers are minimised and retention is defined.

## Using AI tools

LLMs can help build the "every value a verifier sees" inventory from specs and code, or suggest correlation paths. Treat each suggestion as a hypothesis: confirm it with a test (two presentations that a script links) before putting it in a report.

## Worked example

*Execution status: Not executed in this book's CI; verify locally with test credentials only.*

Run a correlation test on a credential flow you are authorised to test:

1. Issue yourself two test credentials (or one, if batch issuance is not supported) from the system's test issuer.
2. Present to two test verifiers you control, logging every byte each verifier receives.
3. Write a script that searches the two logs for identical substrings longer than 16 bytes (signatures, digests, keys, indices). Each match is a correlation handle.
4. Repeat with batch issuance or BBS (if available) and compare the number of matches.
5. If proofs go on chain, submit one from a fresh account and one from a funded test wallet, then check with a block explorer how easily each links to its funding source.
6. Record findings against section F of the checklist.

## Common pitfalls

- Reviewing the cryptography and skipping metadata, timing and gas payers.
- Accepting "unlinkable" claims without a two-verifier test.
- Ignoring small anonymity sets in new or niche groups.
- Treating disclosed attributes as harmless because each one alone is not identifying.
- Testing with real documents or real people's data.

## Exercises

1. Run the two-verifier correlation test on two different credential formats and compare results.
2. Simulate join-then-prove timing on a local Semaphore deployment: with 100 members joining over a week, how much does a proof one minute after a join shrink the anonymity set?
3. Write the privacy section of an audit report for a hypothetical ZK passport airdrop using the checklist.

## Further reading

- G. Livraga, *Protecting Privacy in Data Release* (Springer, 2015), Chapter 2 on quasi-identifiers and k-anonymity.
- G. Danezis et al., *Privacy and Data Protection by Design* (ENISA, 2014).
- RFC 9901, Section 10 (privacy considerations): <https://www.rfc-editor.org/rfc/rfc9901>
- See **privacy-protocol-security**, **zk-circuit-security** and **airdrop-sybil-detection**.
