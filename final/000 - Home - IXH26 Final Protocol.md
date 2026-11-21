# IXH26 final protocol

Start with [Certified photo protocol from capture to verification](Certified%20photo%20protocol%20from%20capture%20to%20recovery.md) for the complete path from a sensor-signed frame to the JPEG a reader receives.

| Stage | How the notes connect |
| --- | --- |
| Authenticate the capture | The trusted runtime signs the [DNG Merkle root](Attested%20DNG%20Merkle%20root.md). A worker uses that root to check that its [DNG tile](Authenticated%20DNG%20tiles.md) contains the inputs for the assigned JPEG interval. |
| Commit to the output | The owner renders the whole image and fixes the [exact reference JPEG commitment](Exact%20reference%20JPEG%20commitment.md) before the verifier draw. Workers use interval openings to compare their independently encoded bytes with that same candidate. |
| Assign the work | The [band layout](Scattered%20restart%20interval%20assignments.md) determines which intervals belong to each group. The [operator draw and encrypted delivery](XRPL%20verifier%20discovery%20and%20encrypted%20assignments.md) determine who checks each group and how they receive its inputs. |
| Collect receipts | In [shared signing](Shared%20signing%20of%20a%20DNG%20render.md), each operator signs the groups it verified. If a quorum is missing, [piece coverage](BLS-signed%20JPEG%20piece%20coverage.md) identifies the affected intervals. |
| Verify the delivery | The [on-chain verifier](On-chain%20verification%20of%20a%20reference%20JPEG.md) checks the aggregate signature and every group’s quorum. The reader uses the master opening to check the delivered JPEG against the certified commitment. |

The [protocol write-up](../Shared_signing_for_verifiable_photo_origin.pdf) gives the specification. The [proof-of-concept walkthrough](../Proof_of_concept/README.md#the-seven-steps-in-code) traces the same handoffs in a local run.
