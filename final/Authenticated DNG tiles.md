---
aliases:
- Tile manifest for a DNG
- Authenticated RAW pieces
---

# Authenticated DNG tiles

> Let
> - the [trusted runtime](Attested%20DNG%20Merkle%20root.md) have access to the canonical DNG inputs from the checked camera-signed RAW and authenticated metadata.
> - $W,H$ be the positive oriented JPEG dimensions under the approved profile. Use 4:4:4 sampling with one 8 × 8 minimum coded unit (MCU) per restart interval. Index the $n=\lceil W/8\rceil\lceil H/8\rceil$ MCUs in row-major order.
> - $j$ be the digest of the [canonical render job](Exact%20reference%20JPEG%20commitment.md). Use that profile's canonical encoding and byte hash.
>
> Then an ==authenticated DNG tile== is the DNG render-input record for one indexed JPEG restart interval, with its opening and Merkle path.
>
> 1. **Derive the DNG footprint.** For interval $i$, map the clipped output MCU back through orientation and crop. Include all source samples and per-piece parameters used by development, including any demosaicing halo, at absolute coordinates. Encode the resulting record $U_i$ with plane, sample format, bounds or coordinate list, and the values in canonical order. Distinct pieces may share RAW samples. The profile fixes CFA phase where applicable, arithmetic, white balance, color/tone transforms and edge handling. Accept only the specified DNG plane and input dependencies. Shared parameters are fixed by the profile or bound by the signed root statement. [Adobe DNG specification](https://helpx.adobe.com/camera-raw/desktop/dng-and-file-formats/digital-negative.html)
> 2. **Hash in interval order.** Draw an independent secret 32-byte salt $s_i$ for each record. The $i$-th leaf is $H_b(0\mathrm{x}00\parallel \operatorname{enc}(\text{IXH26/raw-piece/v2},j,i,s_i,U_i))$, where $H_b$ is the protocol byte hash. Use internal nodes $H_b(0\mathrm{x}01\parallel L\parallel R)$ and the largest-power-of-two split of RFC 9162. The TEE signs the root and count as part of $A$. Keep unopened salts private. [Ordered Merkle tree and inclusion proof](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1)
> 3. **Check the disclosed piece.** Authenticate the job, batch and root evidence $B$. Match $i$ to its expected assignment, derive the footprint, and reject missing or extra data. Recompute the leaf from $(j,i,s_i,U_i)$ and use the path and signed count $n$ to check equality with the root in $A$. The owner may batch paths and reuse $B$ for assignments in the same job.
> 4. **Encode the interval at the worker.** Run the pinned development profile on the verified inputs, then the pinned JPEG encoder on the resulting MCU pixels. At the right and bottom edges use exactly the whole-image padding rule. Compare the stuffed entropy bytes with the candidate commitment using the assigned opening and path. [Exact reference JPEG commitment](Exact%20reference%20JPEG%20commitment.md) · [JPEG restart interval assembly](Supporting%20notes.md#jpeg-restart-interval-assembly) · [JPEG T.81](https://www.itu.int/rec/T-REC-T.81)
>
> > [!example]
> > For a 17 × 9 image, a 4:4:4 grid has three columns and two rows. Interval 5 is the bottom-right MCU. Its output footprint is one pixel, plus whatever source neighbors development requires. The encoder pads that one-pixel output to the same boundary as the full-frame encoder.
>
> > [!warning]
> > - **Input disclosure.** The worker learns the samples in every record it decrypts. The owner's app counts the union of exposed coordinates per operator and capture across retries and jobs, including overlaps and border samples. Scattering reduces contiguous coverage and can still reveal recognizable content. The owner controls its own copy of the capture.

## Authenticating pieces of an existing secure DNG

The baseline checks the runtime's attestation and root signature as above. For a capture distributed without that root signature, a proof that verifies the secure DNG and recomputes the same root is a separate evidence mode. [A local proof of DNG development](Supporting%20notes.md#a-local-proof-of-dng-development)
