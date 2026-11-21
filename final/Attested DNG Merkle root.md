---
aliases:
- SEP-signed DNG Merkle root
- TEE-signed capture root
---

# Attested DNG Merkle root

> Let
> - a sensor sign a unique frame ID together with the canonical RAW frame and its sensor metadata on the protected capture path described in [Apple secure digital negative](https://security.apple.com/blog/apple-reference-image/#technical-details).
> - a trusted execution environment (TEE) have an attested root-signing key confined to approved code. Apple's Secure Enclave Processor (SEP) would need to expose this capability. The capture policy pins the sensor and attestation trust roots, accepted code and security versions, sensor-to-device binding, and freshness and revocation rules.
> - $J$ be the [render job](Exact%20reference%20JPEG%20commitment.md) with digest $j$. Its fields fix the network and contract, owner, capture identifier, profile, geometry, layout, assignment policy, opening commitment, registry epoch and expiry.
>
> Then the ==attested DNG Merkle root== is produced and checked as follows.
>
> 1. **Authenticate the input.** The measured code verifies the sensor signature, enrollment and required device pairing. It hashes the canonical encoding of the registered sensor key ID and signed frame ID to derive the stable capture identifier and checks it against $J$. It verifies the camera/SEP binding for off-sensor rendering metadata when the profile uses it. It enforces the approved time and rollback policy and rejects unauthenticated capture inputs, unsupported DNG layouts and unauthenticated render settings.
> 2. **Extract footprints and build their tree (crux).** Within the same measured boundary, use the registered output geometry to identify the RAW samples and metadata needed for each planned restart interval. Extract the canonical input records directly from the verified capture and build the ordered [DNG piece tree](Authenticated%20DNG%20tiles.md). The records and shared metadata are sufficient for workers to render their intervals. DNG container serialization can run in the owner's app.
> 3. **Sign a root statement.** Check that the geometry and derived interval count agree with $J$. Sign the canonical statement $A$ binding $j$, the RAW root, interval count and shared rendering metadata. The private evidence package $B$ contains $A$, its signature and the key/attestation evidence. The approved format must bind the expected measurement and state to this signing key and a fresh job challenge recognized by the registry. The owner can assemble inclusion paths from the exported tree and retain the attestation evidence.
> 4. **Verify.** Recompute $j$ and match it and the derived count against $A$. Verify the attestation signature and chain to the pinned trust root. Match the root-signing key, approved code measurement and security state, fresh job challenge, device enrollment and revocation policy. Use that key to verify the signature on $A$ and match the statement digest $a$ to the ledger. Workers bind the digest $a$ of the checked statement into their [BLS receipts](Shared%20signing%20of%20a%20DNG%20render.md). An authorized auditor can also check $B$ against $a$.
>
> > [!dim]- #### Why the trust assumption is sufficient
> > - **(1–3)** A usable root signature must come from the approved runtime under the attestation and signature assumptions. Its signing interface accepts only a root it derived after authenticating the input, so the signed root covers those capture-derived pieces.
> > - **(4)** An indexed Merkle path then authenticates the disclosed piece at that position, assuming collision resistance. If a valid key can sign caller-supplied roots, an owner can submit a root over an edited frame and produce valid paths for every piece.
>
> > [!warning]
> > - **Apple integration gap.** Apple documents a sensor signature and SEP metadata binding, with verification and development in Private Cloud Compute. The proposed in-device root derivation and attestation need a new Apple capability or a TEE with usable camera evidence and an independently verifiable attestation policy. A Secure Enclave-backed app key signing an app-computed hash supplies key protection alone. [Apple Reference Image](https://security.apple.com/blog/apple-reference-image/#technical-details) · [IETF remote attestation architecture](https://www.rfc-editor.org/rfc/rfc9334.html)
> > - **Runtime responsibility.** The TEE authenticates and partitions the render inputs, then signs their root. All pixel development, JPEG encoding and candidate commitment computation run outside the TEE. Independent operators check the render against the attested records. Renderer updates can be registered without changing the TEE code when the footprint and metadata requirements remain compatible.
> > - **Claim scope.** Compromised capture hardware or trusted code can attest to bad input or output. This proves a digital derivation under the capture policy. A timestamp claim requires the corresponding authenticated time evidence.
> > - **Capture certification.** A dishonest issuer can certify a key outside the protected capture path, and honest render workers can still accept its evidence. A multi-vendor registry with independent governance would distribute approval and revocation of capture trust roots. Resisting a dishonest issuer for a particular device requires independent evidence for that device or its capture path.
