---
aliases:
- Signed JPEG piece map
- BLS piece proof
---

# BLS-signed JPEG piece coverage

A coverage map is a diagnostic for a job that falls short of certification. Use the [finalized draw](XRPL%20verifier%20discovery%20and%20encrypted%20assignments.md), the job and candidate commitment, and the available validated [group receipts](Shared%20signing%20of%20a%20DNG%20render.md).

1. Match the ordered digest vector to the finalized JPEG commitment. Reconstruct each group message from its indexed digests. Verify retained receipts on that message with the drawn committee’s enrolled keys. A partial aggregate can supply the same evidence when verified on its exact signer–group pairs. Count each operator once within that group.
2. For interval $i$, find its group $g$. Report the selected signers in $A_g$ and their count against $q_g$. Distinguish groups with quorum, groups below quorum and groups with no supplied signatures. Display area coverage, if needed, using the clipped MCU rectangles of groups with quorum.
3. For a private piece check, use the exact entropy bytes, its interval opening $\rho_i$ and indexed path to verify membership in the candidate commitment. Combine that result with the group diagnostics for the same job and candidate. [Exact reference JPEG commitment](Exact%20reference%20JPEG%20commitment.md)

> [!example]
> Committees $\{A,B,D\}$ and $\{C,E,F\}$ each require two signatures. Receipts from $A,B,C$ give the first group quorum and the second group one approval. The job remains uncertified.
