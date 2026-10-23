# Issuer Trust, Revocation and Holder Binding

A credential is a claim by an issuer. Its value depends on three things outside the cryptography: whether the issuer's key is safe and trusted, whether revoked credentials stop working, and whether the person presenting is the person it was issued to. This chapter covers each, with audit findings from real identity contracts.

## Issuer trust

Verifiers need a list of issuers they accept and the keys those issuers use. This **trust registry** is often the weakest part of a system:

| Question | Why it matters |
|---|---|
| Who decides which issuers are trusted? | Governance capture lets attackers add a fake issuer |
| How are issuer keys published and rotated? | `did:web` hosting compromise (Chapter 2) swaps keys silently |
| What happens on issuer key compromise? | Every credential signed with that key is suspect unless issuance times are anchored |
| Does the issuer actually check facts? | A KYC issuer with weak document checks mints real credentials for fake people |
| Is issuance rate monitored? | A compromised signer can mint thousands of credentials quickly |

For ZK passports, the issuers are states. Their document-signing certificates chain to Country Signing CAs, whose certificates are shared through ICAO's Public Key Directory and national publications. Safe Research's 2025 review flags compromised issuing-authority keys as a risk and recommends planning degradation paths. A verifier that accepts any document signer that "looks valid", without a curated list of country roots, is open to forged roots.

## Signed-attestation contracts

Many on-chain identity systems are simpler than full credentials: an off-chain service checks KYC and signs a message; the user submits it to mint a token. Trail of Bits' review of Goldfinch's CommunityRewards and UniqueIdentity contracts (November 2021) is a clear example. UniqueIdentity was an ERC-1155 token minted after KYC, using a signature from an off-chain component. Three findings concerned the signature scheme:

- **"Lack of a time limit on the use of signatures."** A user could keep a signature and mint later. The report explains that "by delaying the minting operation, a malicious user could prevent the revocation of his or her identity NFT".
- **"Lack of contract address in signed data enables signature reuse"** across instances of the same contract.
- **"Lack of function selector in signed data enables signature reuse"** across functions (mint versus burn).

The report also recommended using `msg.sender` instead of a `to` parameter in `mint`, which binds the token to the account that submits the signature. These are standard EIP-712 lessons: sign over domain (chain ID, contract), function, recipient, nonce and expiry. See **account-abstraction-security** for signature replay in smart accounts.

## Revocation versus unlinkability

ENISA's *Privacy and Data Protection by Design* (2014) notes that revocation "badly interacts with the unlinkability requirement" and that revoked credentials are "linkable by definition". Every revocation mechanism leaks something:

| Mechanism | How it works | Privacy leak | Security risk |
|---|---|---|---|
| Short-lived credentials | Expire in hours or days; re-issue | Issuer sees each refresh | Issuer must be online; users locked out on outage |
| Status list (bitstring) | Credential carries an index into a published bitmap | Index is a correlation handle; issuer sees fetches if not cached | Stale caches accept revoked credentials |
| Online status check | Verifier asks issuer | Issuer learns where and when the credential is used | Fail-open on timeout |
| Accumulator / Merkle non-membership proof | Holder proves in ZK that the credential is not revoked | Minimal | Complex; holders need fresh witnesses |
| Group root removal (Semaphore-style) | Remove commitment from tree; new root | Root history may reveal timing | Verifiers accepting old roots keep revoked members |

The last row matters for ZK groups. If a verifier accepts any recent root, a removed member can keep proving against an old root until it expires from the window. Check the root-history window against your revocation needs.

## Holder binding

Holder binding answers: is the presenter the legitimate holder? Options, from weakest to strongest:

1. **None (bearer credential).** Whoever has the file can present it. Fine for coupons, not for identity.
2. **Software key.** The credential binds to a key in the wallet. Users can export and share the key.
3. **Hardware key.** Non-exportable key in a secure element or passkey. Sharing requires handing over the device.
4. **Biometric or liveness binding.** Presentation also checks the person (face match against document photo). Raises its own privacy issues.

On chain, holder binding usually means "bound to an address". Soulbound (non-transferable) tokens stop on-chain transfers, but nothing stops a user from selling the private key of the address. Safe Research's ZK passport review makes the same point about documents: possession is not liveness.

## Correlation through issuance and binding

Issuer trust and binding create correlation handles of their own: a hardware key's public key, a status-list index, an issuer that issues to few people (small anonymity set), or a credential issued at a unique time. Chapter 6 lists these together.

## Worked example

*Execution status: Not executed in this book's CI; verify locally with Foundry on a local Anvil chain.*

Reproduce the Goldfinch-style signature issues on a toy contract:

1. Write `ToyIdentity.sol` with `mint(address to, uint256 id, bytes sig)` that checks a signer signature over `keccak256(abi.encodePacked(to, id, nonces[to], block.chainid))`, mirroring the pattern quoted in the report.
2. In a Foundry test, sign a mint authorisation with a test signer key (`vm.sign`). Deploy two instances of `ToyIdentity` and show the same signature mints in both (missing contract address).
3. Add a `burn(address, uint256, bytes)` that verifies the same hash, and show a mint signature also authorises a burn (missing function selector).
4. Wait (with `vm.warp`) 365 days and show the signature still works (no expiry). Model "revocation" as the off-chain service refusing new signatures, and show that the old one bypasses it.
5. Fix with EIP-712 typed data including contract address, function name, recipient = `msg.sender`, nonce and deadline. Re-run all tests and confirm they fail as expected.

## Common pitfalls

- Signed attestations without expiry, domain or function binding.
- Trust registries editable by a single key or a weak governance process.
- Verifiers accepting stale status lists or old group roots.
- Calling soulbound tokens "identity" when the private key can be sold.
- Online status checks that leak usage to the issuer and fail open.

## Exercises

1. Complete the Foundry exercise and write the fixed contract.
2. For one ZK passport verifier, find out which country roots it accepts and how that list is updated.
3. Choose a revocation mechanism for a proof-of-personhood airdrop and justify it against the table above.

## Further reading

- Trail of Bits, Goldfinch CommunityRewards and UniqueIdentity security assessment (2021).
- G. Danezis et al., *Privacy and Data Protection by Design* (ENISA, 2014), Section 4.2.2 on revocation.
- W3C Bitstring Status List: <https://www.w3.org/TR/vc-bitstring-status-list/>
- ICAO Public Key Directory: <https://www.icao.int/icao-pkd>
- EIP-712 typed structured data signing: <https://eips.ethereum.org/EIPS/eip-712>
