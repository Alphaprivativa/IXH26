# Off-ledger photo certification

Run a simulated sensor, capture runtime, owner, five operators and a local registry on one computer. Each operator signs a separate BLS receipt for every group it verifies. The registry checks one aggregate and exports a signed checkpoint. A reader can audit that checkpoint and verify the delivered JPEG with its secret opening. [Protocol specification, Figure 1 and §4](Shared_signing_for_verifiable_photo_origin.pdf)

## Run the example

From this folder, use Python 3.13 and GNU Make. Setup creates a local virtual environment and installs the pinned dependencies. The default receipt suite is BLS12-381 with proof of possession.

```sh
make setup
make walkthrough RUN=example-photo
make test
```

On Windows, you can also run the full example directly in PowerShell with Python 3.13. Choose a fresh output directory for each capture.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe demo.py certify example-photo
.\.venv\Scripts\python.exe demo.py audit example-photo/certificate.json --trust example-photo/ledger-public.der
.\.venv\Scripts\python.exe demo.py verify example-photo/certificate.json --trust example-photo/ledger-public.der example-photo/private/candidate.jpg example-photo/private/opening.bin --evidence example-photo/private/attestation.json
.\.venv\Scripts\python.exe -m unittest -v test_protocol
```

`walkthrough` runs three commands in order. To inspect each handoff, use a fresh directory with `make certify RUN=another-photo`, then `make audit RUN=another-photo`, then `make verify RUN=another-photo`. The fixture reports 20 JPEG restart intervals, ten groups and a quorum of two of three in each group. The certificate ID changes with fresh keys, salts, openings and the draw.

## The seven steps in code

1. **Capture.** The simulated sensor signs the digest of a 43 × 33 RGGB RAW frame, its geometry, frame identifier and owner. The owner creates a fresh nonce and a 32-byte master opening. The public job digest `j` binds the capture ID, owner's keys, opening commitment, render profile, geometry, epoch, deadline, registry challenge and assignment rules. A different job produces a different receipt message.
2. **Authenticate inputs.** The simulated TEE checks the live job and sensor signature against the RAW bytes. It emits the DNG and extracts the input footprint for each output interval, including adjacent samples needed for interpolation. It salts each indexed footprint independently and builds an ordered Merkle tree. The runtime signs the root statement `a`, which binds the input root to the job. A vendor-signed device credential and a fresh quote bind the runtime key to the enrolled device, code measurement, security state and job challenge.
3. **Commit the candidate.** The owner renders the complete DNG. The canonical parser separates its JPEG header and restart intervals. For each interval the owner derives an opening from the master with HMAC-SHA-256 and commits to its index and exact payload. The ordered output tree and header produce the JPEG commitment `C_J` (the code calls it `candidate`). The owner signs the reservation of `(j, a, C_J)`. The registry fixes these values for this capture and profile before releasing the next beacon round.
4. **Assign work.** The epoch roster fixes five positions. Each operator's software wallet authorizes its BLS signing and X25519 encryption keys. Enrollment checks proof of possession and challenges the operator through its encrypted channel. The registry signs the target round with a local beacon key. Its output and the reservation determine three members per group, subject to the disclosure cap. The owner uses authenticated HPKE to send each operator its assigned RAW samples, salts, paths, interval openings and attestation evidence. The master opening stays with the owner.
5. **Check the render.** Each worker reads the finalized reservation and derives its full assignment. It checks the quote, device enrollment, revocation status and signed input root. For each index, it checks input membership, independently develops the footprint, encodes that JPEG interval and checks the resulting bytes against the output tree using the supplied opening and path. Missing or extra indices fail. The worker returns an encrypted list of group receipts. Each signs `enc("IXH26/jpeg-group-receipt/v1", j, a, C_J, g, count, i₀, d₀, …)` with the group’s indices in increasing order. Each `d` is the 32-byte interval digest the worker reproduced at that index. The output tree hashes `0x02 || d` for each leaf.
6. **Certify.** The owner verifies each receipt and aggregates the selected signatures. The owner submits the ordered digest vector and one bitmap byte per group. Bit zero selects the committee member with the lowest roster index. The registry rebuilds the JPEG commitment, requires two or more approvals in each committee and runs proof-of-possession `AggregateVerify` over the selected key and group-message pairs. It records the certificate. The signed checkpoint includes the exact roster, wallet authorizations, beacon proof, reservation fields, digest vector, group bitmaps and aggregate needed to replay the public checks.
7. **Verify the photo.** `audit` authenticates the checkpoint with a trusted registry key, then checks the enrollment evidence, beacon, assignments, quorums, aggregate and certificate digest. `verify` runs the audit, checks that the master opening matches the job, parses the delivered JPEG and recomputes `C_J`. A changed header, wrong interval order, missing delimiter, trailing data or wrong opening fails. The Make target also supplies the saved capture evidence for attestation appraisal.

**Worked example.** The 39 × 29 crop is rotated to 29 × 39 output pixels. At one 8 × 8 block per restart interval this gives four columns and five rows. Group 0 covers indices 0 and 19. An operator drawn for group 0 signs a message containing indices 0 and 19 with their verified digests. If the operator also serves on group 1, it signs a second message for indices 1 and 10. A reader checks all 20 intervals against the certificate with one master opening.

## What the run writes

| Path under `RUN` | Who uses it |
| --- | --- |
| `certificate.json` | Public signed checkpoint for auditors and readers. |
| `ledger-public.der` | Registry verification key. The example writes it beside the certificate for convenience. An independent reader obtains or pins this key through a trusted channel and can pass `TRUST=path` to Make. |
| `private/candidate.jpg`, `private/opening.bin` | Private delivery to the reader. To verify a separately delivered JPEG, use `make verify RUN=example-photo JPEG=path/to/delivered.jpg`. |
| `private/capture.dng`, `private/attestation.json` | Local capture and attestation evidence. The public audit needs neither file. |

The signed checkpoint and beacon model trust in a single registry. The local beacon key can sign future rounds, so this mode demonstrates verifiability and message ordering while relying on the registry for unpredictability.

## Files and optional commands

| File | Role |
| --- | --- |
| [demo.py](demo.py) | `build()` orchestrates capture through registration. `demo()` writes the bundle. `audit()` and `verify_jpeg()` implement the reader checks. |
| [protocol.py](protocol.py) and [assignments.py](assignments.py) | `Ledger` tracks enrollment, reservation, round and certificate. `CaptureRuntime` authenticates inputs. `Worker.process()` checks the encrypted assignments built by `collect_receipts()`. |
| [render.py](render.py) and [primitives.py](primitives.py) | Reference renderer, strict JPEG grammar, commitments, signatures and authenticated channels. |
| [Makefile](Makefile), [requirements.txt](requirements.txt) and [test_protocol.py](test_protocol.py) | Commands, Python dependencies and tests for valid runs and rejected changes. |
| [archive.py](archive.py) | Optional recovery of encrypted JPEG bytes and the master opening. |

`make archive-walkthrough RUN=archive-example` adds an encrypted recovery bundle and reader key, exercises threshold recovery and compares the recovered JPEG byte for byte. For a quick run using individual Ed25519 receipts, add `SUITE=ed25519-demo` to every command for that directory. Use the default `bls-pop` to reproduce the PDF's aggregate.
