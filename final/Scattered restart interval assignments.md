---
aliases:
- Scattered MCU assignment
- Band layout
---

# Scattered restart interval assignments

> Let
> - $N\ge1$ be the number of items in row-major order and $1\le b\le N$ the maximum number assigned to one group.
> - $N=mb+r$ with $0\le r<b$. Number bands, offsets and groups from zero.
>
> Then the ==band layout== partitions the items as follows.
>
> 1. Split the $N$ items into $b$ consecutive bands, the first $r$ of length $m+1$ and the rest of length $m$.
> 2. In band $j$ of length $L_j$, assign its item at offset $u$ to group $(u+j)\bmod L_j$. Read each group in band order.
> 3. Groups $0,\ldots,m-1$ have size $b$. If $r>0$, group $m$ has size $r$. Every item is assigned exactly once.
>
> > [!dim]- #### Proof
> > - $(3)$ Addition by $j$ permutes the offsets modulo $L_j$, so each band contributes exactly one item to each group below $L_j$.
>
> > [!note]
> > - **Restart JPEG.** Apply this layout to row-major MCU indices. The [public draw](XRPL%20verifier%20discovery%20and%20encrypted%20assignments.md) assigns a committee to each group. Each [group receipt](Shared%20signing%20of%20a%20DNG%20render.md) covers the indexed digests of exactly one group. An operator serving on two committees signs separately for each verified group. Use original row-major indices to assemble or verify the JPEG. [Authenticated DNG tiles](Authenticated%20DNG%20tiles.md)
> > - **RGB prototype.** The same formula on individual pixel indices gives the layout used in [Scattered RGB recomposition](Supporting%20notes.md#scattered-rgb-recomposition).
