# Selective Disclosure: SD-JWT and BBS

Selective disclosure lets a holder show some attributes of a credential and hide others: nationality without name, or "over 18" without birth date. Two approaches dominate: **salted-hash** schemes such as SD-JWT, and **signature-based** schemes such as BBS, which produce zero-knowledge proofs of a signature. They differ sharply on linkability, which is where most privacy claims break.

## How SD-JWT works

SD-JWT was published by the IETF as RFC 9901, "Selective Disclosure for JSON Web Tokens", in November 2025. The mechanism is simple:

1. For each disclosable claim, the issuer makes a **disclosure**: the JSON array `[salt, claim_name, claim_value]`, base64url-encoded.
2. The issuer hashes each disclosure (SHA-256 by default) and puts the digests in an `_sd` array in the signed JWT, instead of the claims themselves.
3. The holder receives the signed JWT plus all disclosures.
4. To present, the holder sends the JWT plus only the chosen disclosures. The verifier hashes each disclosure and checks that the digest is in `_sd`.
5. Optionally, a **Key Binding JWT** (KB-JWT) signed by the holder's key proves possession. RFC 9901 requires it to carry `iat`, `aud` (the intended verifier), a `nonce` for freshness, and `sd_hash` over the issuer-signed JWT and the selected disclosures.

The RFC recommends at least 128 bits of randomness in each salt and a new salt per claim. It also defines **decoy digests**, digests with no matching claim, "to make it more difficult for an adversarial Verifier to see the original number of claims".

## Where SD-JWT leaks

| Leak | Why | Mitigation |
|---|---|---|
| Verifier–verifier linking | The issuer signature, `_sd` digests and holder key are identical in every presentation of the same credential | Batch issuance: many credentials, each with new salts and new key-binding keys, each used once |
| Issuer–verifier linking | The issuer knows the signature and digests it issued; a colluding verifier can show them | None within SD-JWT; RFC 9901 says this "cannot be achieved in salted hash-based selective disclosure approaches" |
| Claim-count leak | Number of digests reveals how many claims exist | Decoy digests |
| Low-entropy claims | Without a good salt, a digest of `birthdate` can be brute-forced | 128-bit random salts, per claim |
| Timestamps | `iat`/`exp` values are unique-ish fingerprints | RFC 9901 says time claims in a batch must be randomised within a window or rounded |
| Replay | A captured presentation is re-sent | KB-JWT with verifier-chosen nonce and `aud` |

RFC 9901's privacy section adds a caveat that applies to every scheme: unlinkability holds only when the disclosed claims do not themselves identify the user. Disclosing a full name makes every other protection moot.

## How BBS differs

BBS signatures (an IRTF CFRG Internet-Draft; check the datatracker for the current revision) let the issuer sign a list of messages (attributes) with one signature. The holder can derive a **proof** that discloses some messages and proves knowledge of a valid signature over all of them. Each proof is randomised, so two proofs from the same credential do not share a signature value. This gives verifier–verifier and issuer–verifier unlinkability *for the proof itself*.

ENISA's *Privacy and Data Protection by Design* (Danezis et al., 2014) describes the same two strategies in general terms: either use each credential only once, or use schemes where presentations are zero-knowledge proofs. It cites Idemix and U-Prove as earlier implementations of anonymous credentials. SD-JWT with batch issuance is the first strategy; BBS is the second.

BBS does not remove all correlation handles. Disclosed attribute values, holder-binding values (unless proven in zero knowledge), revocation indices and presentation metadata (time, IP address, wallet fingerprint) can still link proofs. A companion draft on per-verifier linkability exists for cases where a verifier *should* recognise returning users (a pseudonym per verifier).

## Choosing between them

| Question | SD-JWT | BBS |
|---|---|---|
| Ecosystem and library maturity | Broad JOSE tooling; RFC published | Fewer libraries; pairing-friendly curves; draft status |
| Unlinkability without batches | No | Yes, for the proof |
| Predicates ("over 18" from birth date) | No; disclose the claim or issue a separate `age_over_18` claim | Not in the base draft; needs extra ZK range proofs |
| Hardware key support for holder binding | Good (ES256 in secure elements) | Harder; holder binding often done in software |
| Verifier complexity | Low | Higher |

Many deployments choose SD-JWT for maturity, then rely on batch issuance and issuer-provided boolean claims (`age_over_18`) for privacy. Reviewers should check that the batch really exists and that wallets actually rotate credentials.

## Worked example

*Execution status: run locally with Python 3.13 (standard library only); output observed. No signatures are computed, so this shows digest logic only.*

Save as `sd_digest.py`:

```python
import hashlib, base64, json, secrets
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def disclosure(name, value, salt=None):
    salt = salt if salt is not None else b64u(secrets.token_bytes(16))
    d = b64u(json.dumps([salt, name, value]).encode())
    return d, b64u(hashlib.sha256(d.encode()).digest())
claims = {"given_name": "Ada", "birthdate": "1990-01-01", "nationality": "NL"}
disc = {k: disclosure(k, v) for k, v in claims.items()}
sd = sorted(h for _, h in disc.values())
d, _ = disc["nationality"]
print("nationality disclosure verifies:", b64u(hashlib.sha256(d.encode()).digest()) in sd)
# A digest made with an empty salt can be brute-forced
target = disclosure("birthdate", "1990-01-01", salt="")[1]
found = next(f"{y}-{m:02d}-{dd:02d}" for y in range(1900, 2025) for m in range(1, 13)
             for dd in range(1, 32) if disclosure("birthdate", f"{y}-{m:02d}-{dd:02d}", salt="")[1] == target)
print("unsalted birthdate recovered:", found)
```

Run `python3 -I sd_digest.py`. Observed output: `nationality disclosure verifies: True`, then `unsalted birthdate recovered: 1990-01-01` after trying about 33 000 candidate dates; the whole script took about 1.7 seconds on our test machine. With a 128-bit salt the same search is infeasible. Note that the `_sd` list is identical every time this credential is presented, which is the verifier–verifier correlation handle described above.

## Common pitfalls

- Claiming unlinkability for SD-JWT without batch issuance and one-time use.
- Short, reused or predictable salts.
- Missing or unchecked KB-JWT `nonce` and `aud`, allowing replay to another verifier.
- Disclosing identifying claims and then describing the presentation as anonymous.
- Assuming BBS proofs hide everything while revocation indices or metadata still link them.

## Exercises

1. Extend the script to issue a batch of five credentials with fresh salts, and show that their `_sd` arrays share no digest.
2. Using an SD-JWT library of your choice, produce a presentation with a KB-JWT and write a verifier test that rejects a wrong `aud` and a reused `nonce`.
3. List every value in a BBS proof presentation in a real wallet and mark which ones could still correlate two presentations.

## Further reading

- D. Fett, K. Yasuda and B. Campbell, RFC 9901, "Selective Disclosure for JSON Web Tokens" (2025): <https://www.rfc-editor.org/rfc/rfc9901>
- IRTF CFRG, "The BBS Signature Scheme" (Internet-Draft): <https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/>
- G. Danezis et al., *Privacy and Data Protection by Design* (ENISA, 2014), Section 4.2.
- See **crypto-implementation-testing** for testing signature libraries.
