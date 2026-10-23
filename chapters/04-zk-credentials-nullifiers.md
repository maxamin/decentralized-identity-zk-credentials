# ZK Credentials, Nullifiers and Group Membership

Zero-knowledge (ZK) credentials go further than selective disclosure. The holder proves a *statement* about hidden data ("I am a member of this group", "my passport was signed by a recognised state and I am over 18") and reveals only the result. On chains, these proofs gate airdrops, votes and access. Most designs pair the proof with a **nullifier**, a value that stops the same person proving twice in the same context. Nullifiers are where privacy and Sybil resistance meet, and where many bugs live.

## Semaphore-style group membership

Semaphore, maintained by the Privacy & Scaling Explorations team, is the reference design for anonymous group membership. Its V4 glossary defines:

- **Identity:** "an EdDSA public/private key pair and a commitment".
- **Identity commitment:** the public value stored in groups.
- **Group:** "a Merkle tree in which each leaf is an identity commitment for a user" (Semaphore uses the LeanIMT incremental Merkle tree).
- **Scope:** "a value used like a topic on which users can generate a valid proof only once".
- **Nullifier:** "the hash of the scope and private key of the user's Semaphore identity".
- **Message:** the value the user broadcasts with the proof, such as a vote.

A proof shows: "I know a private key whose commitment is a leaf under Merkle root R; here is the nullifier for scope S; and I bind this message M." The verifier checks the proof against a known root, rejects nullifiers already used for scope S, and records the new one.

```mermaid
flowchart LR
  SK[Private key] --> CM[Commitment = H(pk)]
  CM --> MT[Group Merkle tree root R]
  SK --> NF["Nullifier = H(scope, sk)"]
  SC[Scope S] --> NF
  MT --> P[ZK proof]
  NF --> P
  MSG[Message M] --> P
  P --> V{Verifier: root known? nullifier unused for S? proof valid?}
```

## Nullifier properties and failures

| Property | Requirement | Failure example |
|---|---|---|
| Uniqueness per scope | Same person, same scope → same nullifier | Nullifier derived from something the user can vary (a fresh random value, a second key), allowing double use |
| Unlinkability across scopes | Different scopes → unrelated nullifiers | Using a global constant scope, so all actions link to one pseudonym |
| Binding to the right secret | Nullifier depends on a secret only the holder knows | Derived from public data (document number hash), so anyone can compute it and link or front-run |
| State persistence | "Used" set survives upgrades and redeployments | New contract starts with an empty set |
| Message binding | Proof binds message, recipient and chain | Front-running: someone copies the proof and changes the recipient |

The state-persistence row has a real audit example. Secure3's Holonym-P1 audit (September 2023) reviewed `SybilGovID.sol`, part of a privacy-preserving identity protocol that uses zkSNARKs over government ID checks for Sybil resistance. The critical finding HYM-1 was titled "One Person can verify one more time at each new contract redeployment". A marker of used identities was not checked against the legacy contract, so each redeployment reset it. The team responded that the production function was not affected, renamed the vulnerable one to avoid future misuse, and noted that future upgrades would likely change the nullifier scheme.

A second pattern comes from forked privacy pools. Halborn's Sacred Finance audit (2022) describes a Tornado Cash fork whose reward circuit computed a reward nullifier as the Poseidon hash of the note's nullifier *hash* rather than the nullifier itself. Changes like this must be re-analysed: does the new derivation keep uniqueness and unlinkability?

## Document-based ZK proofs (ZK passports)

Electronic passports and some national ID cards carry an NFC chip with the holder's data and the issuing state's signature. ZK passport projects read the chip with a phone and prove statements about the signed data without revealing it. As of October 2026, projects in this space include ZKPassport, Self, Rarimo, Anon Aadhaar (for India's Aadhaar) and Privado ID. Check each project's current docs; this field moves fast.

Safe Research's review "ZKPassport: where are we now?" (September 2025) lists the trade-offs that a reviewer should test:

- **Replay.** "Proofs must not be reusable; each request needs a fresh nonce or challenge and single-use semantics".
- **Issuer trust.** The design depends on government PKI, so compromised issuing-authority keys are a risk.
- **Correlation.** Exposing or storing raw or hashed MRZ fields "invites correlation and dictionary attacks"; predicate-only proofs are recommended.
- **Multiple documents.** "The system cannot prevent a single person with multiple passports from onboarding multiple times."
- **Possession is not liveness.** A thief with a valid document could generate proofs.
- **Renewal.** A new passport changes identifiers; without a linking flow, users can be locked out.
- **Device limits.** Full on-device proving is still limited on some phones, and "light" modes move signature checks to a trusted verifier.

## Circuit-level bugs

ZK credentials inherit every circuit bug class from **zk-circuit-security**. Secure3's UniPass email-circuits audit (June 2023), for a system that proves control of an email address via DKIM-signed mail, lists findings including "Missing check email DKIM-Signature in circuit", "ZK prove can be replay" and an issue similar to the Frozen Heart attack on Plonk (a weak Fiat–Shamir transformation). Each maps onto identity risk: an unchecked signature lets anyone forge identity; a replayable proof lets anyone reuse someone else's.

## Worked example

*Execution status: Not executed in this book's CI; verify locally on a local Hardhat or Anvil chain.*

1. Install the Semaphore CLI and create a project from its Hardhat template (see the Semaphore docs for the current command).
2. Create a group, add three identities and generate a proof for scope `airdrop-2026` and message = recipient address.
3. Verify the proof on chain and record the nullifier. Submit the same proof again and confirm it is rejected.
4. Generate a proof from the same identity for scope `vote-42` and confirm the nullifier differs.
5. Deploy a *second* copy of your verifier contract and submit the first proof there. It succeeds: this is the Holonym-style redeployment issue. Fix it by keeping the used-nullifier set in a separate storage contract shared by all versions, or by checking legacy contracts.
6. Try to submit the first proof with a different message (recipient). Confirm the message binding rejects it.

## Common pitfalls

- Nullifiers derived from public data (document numbers, email hashes), making them linkable and predictable.
- One global scope for all actions, turning the nullifier into a permanent pseudonym.
- Used-nullifier state lost on redeployment or upgrade.
- Proofs not bound to recipient, chain ID and contract, enabling front-running.
- Ignoring that one person may hold several valid documents.

## Exercises

1. Complete the Semaphore exercise and write a test for each nullifier property in the table.
2. For one ZK passport project, find out how its nullifier is derived and whether it can link a user across two applications.
3. Write a threat model for an airdrop gated by passport proofs, including people with dual nationality, stolen documents and renewal.

## Further reading

- Semaphore documentation and glossary: <https://docs.semaphore.pse.dev/glossary>
- Safe Research, "ZKPassport: where are we now?" (2025): <https://safefoundation.org/blog/safe-research-zk-passport-where-are-we-now>
- Secure3, Holonym-P1 audit report (2023); Secure3, UniPass email circuits audit report (2023).
- Halborn, Sacred Finance smart contract and Circom circuit audit (2022).
- See **zk-circuit-security** and **airdrop-sybil-detection**.
