---
aliases:
- Reference JPEG verification contract
---

# On-chain verification of a reference JPEG

## Register and verify

1. **Reserve the capture and commit the job.** Authenticate capture authorization and the owner, and check the target chain and contract, render profile, geometry, interval count, policy, historical epoch and expiry. Record $J$, $j$, $a$, $C_J$ and the future beacon round under the capture identifier and render profile. Only the first authorized commitment reserves that pair. Follow the [public assignment policy](XRPL%20verifier%20discovery%20and%20encrypted%20assignments.md) to derive the committees from the pinned beacon and registry.
2. **Register the complete certificate.** For $K=(j,a,C_J,D,(B_g)_g,\Sigma)$, match the finalized job and deadline. Check the length of $D$ and recompute $C_J$ from the ordered digests and canonical header. Derive every committee and decode its bitmap in committee roster order. Require a quorum in every group and run [BLS AggregateVerify](Shared%20signing%20of%20a%20DNG%20render.md) on exactly the selected enrolled keys paired with their reconstructed group messages. Record the verified certificate and its digest using the job's versioned certificate encoding. Repeated identical registration is idempotent. Maintain the finalized certificate and historical verification inputs in the ledger record.
3. **Verify delivered bytes.** Resolve the verified record and recompute the [JPEG commitment](Exact%20reference%20JPEG%20commitment.md) with the master opening and strict parser. The reader performs the check locally for private delivery. A contract can perform the same check for bounded public files. The signed statement digest $a$ identifies the TEE evidence for independent appraisal by an authorized reader.

> [!note]
> - **Ledger target.** Prototype direct verification on XRPL EVM with its documented EIP-2537 BLS12-381 precompiles. The contract still checks the pinned BLS encoding and enrollment, the ordered interval digests and each committee’s signer bitmap and quorum. Benchmark calldata and gas for the supported profiles and cap the registry limits accordingly. [XRPL EVM precompiles](https://docs.xrplevm.org/pages/developers/resources/precompiles) · [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537)
> - **Long-term evidence.** Preserve the pinned job, beacon and registry history needed to audit the certificate. BLS12-381 provides classical security.
