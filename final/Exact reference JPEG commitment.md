---
aliases:
- Ordered JPEG restart interval commitment
- Exact-file verification
---

# Exact reference JPEG commitment

> Let
> - $J$ be the canonical render job, with a fresh 32-byte job ID $x$. It fixes the protocol and BLS suite versions, chain and contract, owner, capture identifier and policy, registry epoch, JPEG profile, layout, assignment and randomness policy, width and height, interval count, expiry, and opening mode.
> - $\rho$ be a fresh uniform secret 32-byte master opening in private mode or 32 zero bytes in public mode. Include $u=H_b(\operatorname{enc}(\text{IXH26/opening/v3},x,\rho))$ in $J$ and define $j=H_b(\operatorname{enc}(\text{IXH26/job/v3},J))$.
> - $A$ be the [root statement](Attested%20DNG%20Merkle%20root.md) binding $j$ to the authenticated RAW pieces. Its digest is $a=H_b(\operatorname{enc}(\text{IXH26/root-statement/v2},A))$.
> - $C$ be the canonical JPEG header through SOS, derived from the registered profile and authenticated geometry. Let $n\ge1$ be the interval count and $e_0,\ldots,e_{n-1}$ the stuffed entropy segments of the baseline 4:4:4 single-scan image.
>
> Then the owner renders the candidate and computes the ==exact reference JPEG commitment== outside the TEE, after the TEE has signed the DNG input root.
>
> 1. **Encode and derive openings.** Use $H_b=\operatorname{SHA256}$. Encode tuples in schema order with unsigned fixed-width big-endian integers and 32-bit big-endian lengths and counts for variable byte strings and arrays. Use the shown ASCII domain tags. Derive
> $$\rho_i=\operatorname{HMAC}_{\rm SHA256}\bigl(\rho,\operatorname{enc}(\text{IXH26/interval-opening/v3},j,i)\bigr).$$
> 2. **Commit in interval order.** Compute
> $$d_i=H_b(\operatorname{enc}(\text{IXH26/jpeg-interval/v3},j,a,i,\rho_i,e_i)).$$
> Build $Q$ over the ordered digests with the RAW tree's split rule, using $H_b(0\mathrm{x}02\parallel d_i)$ at leaves and $H_b(0\mathrm{x}03\parallel L\parallel R)$ at internal nodes. Set
> $$C_J=H_b(\operatorname{enc}(\text{IXH26/exact-jpeg/v3},j,a,C,n,Q)).$$
> Commit $C_J$ before the [operator draw](XRPL%20verifier%20discovery%20and%20encrypted%20assignments.md) and authenticate it with the [BLS certificate](Shared%20signing%20of%20a%20DNG%20render.md).
> 3. **Open assigned intervals privately.** Give each worker only the openings $\rho_i$ and indexed paths for its assigned intervals, with $Q$. Workers check the paths from their recomputed digests to $Q$ and match the derived $C_J$ to the job record. The authorized reader checks derivation from $\rho$ across the whole file.
> 4. **Check candidate bytes.** Check $\rho$ against $u$ and the opening mode. Match the candidate header byte for byte to $C$. Parse exactly $n$ nonempty segments and preserve $FF00$ byte stuffing. Require cyclic restart markers after the first $n-1$ segments, beginning with $FFD0$, followed immediately after the final segment by $FFD9$ and end of file. Reject extra marker fill and trailing bytes. Derive all $\rho_i$, recompute the indexed digests and compare the resulting $C_J$ with the finalized certificate. [JPEG T.81](https://www.itu.int/rec/T-REC-T.81)
>
> > [!dim]- #### Why this binds the exact file
> > The opening commitment fixes $\rho$ up to hash collisions. The candidate commitment fixes the header and ordered digests for that job and root. The parser fixes interval boundaries and delimiters, so changing the file while preserving the verified commitment requires a hash collision.
>
> > [!note]
> > - **Privacy.** Authorized readers receive the master opening. The operator learns only its assigned openings and paths. The public certificate carries the candidate commitment, ordered interval digests and per-group signer bitmaps.
> > - **Single interval.** For $n=1$, the JPEG has a header, one entropy segment and EOI. For $n>1$, the marker after segment $i<n-1$ is $FFD(i\bmod 8)$ in hexadecimal notation.
