---
aliases:
- Wallet-based verifier discovery
- Encrypted render assignments
---

# XRPL verifier discovery and encrypted assignments

## Enrollment and public assignment

A deployment can enroll members of the public, industry organizations, camera manufacturers or a mix. The enrollment policy sets eligibility and independence requirements. The job pins the eligible roster before the public draw selects its committees.

1. **Enroll the roster.** Operators opt in through an app and publish signed availability for an epoch. Verify control of the operator's enabled XRPL signing key against validated ledger state and bind the account, operator ID, BLS key and X25519 key to a domain-separated enrollment challenge. Check possession of both application keys, using the registered [BLS proof-of-possession suite](Shared%20signing%20of%20a%20DNG%20render.md) for the receipt key. Pin the eligible operators, key bindings, availability and stake in the historical epoch. The enrollment policy must establish operator independence beyond wallet control. [XRPL signing keys](https://xrpl.org/docs/concepts/accounts/cryptographic-keys)
2. **Lock one job and candidate before the draw.** Hash the canonical encoding of the registered sensor key ID and the unique frame ID signed with the RAW capture. The registry verifies capture authorization for the owner and candidate job before accepting a reservation. The first authorized commitment for a capture and render profile pins $J$, $a$, $C_J$ and the future beacon round. Enforce this across registry epochs in the smart contract's namespace. Reuse the reservation only if the job and both commitments match. Each worker checks the capture identifier against the authenticated evidence for the frame.
3. **Draw the committees.** Use the beacon rule pinned by $J$ and a fresh, publicly verifiable random value revealed after the commitment is finalized. The policy specifies the beacon's unpredictability and bias assumptions, roster order, deterministic sampling without replacement within each group, committee sizes and per-operator disclosure caps. Derive groups in layout order. For each group, seed the draw with the beacon round and value, job digest, both commitments and group ID. Use enough redundant assignments for the chosen quorum. If the draw cannot meet the policy or a committee falls short, leave the job uncertified. Retransmit to the same assigned set before expiry. The committed capture and profile keep the same draw.
4. **Enforce equivocation penalties.** Hold each eligible operator's stake through the evidence window. Two valid signatures under the same enrolled key on conflicting root or candidate digests for the same job constitute evidence of equivocation. Resolve eligibility and the signing key against the pinned epoch. Stake makes equivocation punishable. Operator independence and the per-group fault bound remain enrollment and sampling assumptions.

## Encrypted delivery

1. **Protect both directions.** The wallet key authorizes the association between the operator's account and their separate X25519 key. The owner encrypts the off-chain assignment to that registered encryption key and authenticates it with the owner's enrolled application key. Use authenticated HPKE with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305. Bind domain, job, direction, sender and recipient identities and key IDs, assignment ID and expiry as associated data. Use fresh encapsulations and reject unexpected, expired or replayed assignments. [HPKE modes and suites](https://www.rfc-editor.org/rfc/rfc9180.html)
2. **Send assigned pieces.** Include the job reference, signed root evidence, assigned RAW footprints with salts and indexed paths, and candidate root $Q$ with the paths and $\rho_i$ for the same interval indices. The worker verifies the finalized assignment, signed inputs and candidate paths, then returns a separate receipt for each verified group over the reverse channel. Track each operator's cumulative disclosure of RAW samples per capture, including overlaps and repeated delivery. Workers can retain their cleartext, and colluding workers can pool their pieces.
