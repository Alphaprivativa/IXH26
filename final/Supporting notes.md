# Supporting notes

## JPEG restart interval assembly

With one 8 × 8 MCU per restart interval, the worker can encode its assigned MCU independently. The restart boundary resets DC prediction, and the pinned profile fixes the tables, byte stuffing and edge padding. To reassemble the JPEG, write the canonical header, emit the entropy segments in row-major order with the prescribed restart markers between them, then append the end-of-image marker. The reader checks the resulting bytes against the [exact reference JPEG commitment](Exact%20reference%20JPEG%20commitment.md).

## Scattered RGB recomposition

The earlier RGB prototype applied the [band layout](Scattered%20restart%20interval%20assignments.md) to individual pixels. Each tile supplied an ordered list of RGB triplets. The assembler wrote each triplet back to its original raster position, checked that every position was filled exactly once, then encoded the complete raster. The final protocol applies the layout to independently encoded JPEG restart intervals.

## A local proof of DNG development

A photographer holding the capture could prove in zero knowledge that the sensor signature and metadata authenticate the same frame under the verifier’s registry, and that the pinned renderer produces the committed JPEG from that frame. For a proof used to authenticate [DNG tiles](Authenticated%20DNG%20tiles.md), the proof must also bind the ordered footprint root to the verified capture. This is a proposed alternative evidence mode. The final protocol uses an [attested root statement](Attested%20DNG%20Merkle%20root.md).
