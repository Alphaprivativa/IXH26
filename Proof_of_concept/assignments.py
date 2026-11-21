"""Private delivery and verification of receipts for the assigned groups."""

from primitives import pack, require, seal, unpack, unseal
from protocol import assigned, channel_context, draw, groups, receipt_message


def collect_receipts(job, ledger, workers, owner_channel, samples, salts, raw_tree, evidence, jpeg_tree, openings,
                     digests):
    a, candidate, target, beacon = ledger.finalized(job)
    committees = draw(job, a, candidate, target, beacon, ledger.roster)
    layout = groups(job.geometry.count)
    receipts = [{} for _ in committees]
    for index, worker in enumerate(workers):
        indices = assigned(job, committees, index)
        if not indices:
            continue
        pieces = [dict(i=i, samples=samples[i], salt=salts[i], raw_path=raw_tree.path(i),
                       opening=openings[i], jpeg_path=jpeg_tree.path(i)) for i in indices]
        packet = dict(evidence=evidence, Q=jpeg_tree.root, pieces=pieces)
        ctx = channel_context(job, a, candidate, index, worker.channel, b"assignment")
        envelope = seal(owner_channel, worker.channel, ctx, pack(packet))
        reply = worker.process(job, ledger, index, envelope)
        ctx = channel_context(job, a, candidate, index, worker.channel, b"receipt")
        returned = unpack(unseal(worker.channel, owner_channel, ctx, reply))
        expected = [g for g, committee in enumerate(committees) if index in committee]
        require([g for g, _ in returned] == expected, "incorrect group receipts")
        for group, signature in returned:
            msg = receipt_message(job, a, candidate, group, layout[group], digests)
            ledger.suite.check(worker.pk, msg, signature)
            receipts[group][index] = signature
    return committees, receipts


def aggregate_receipts(suite, committees, receipts):
    bitmaps = bytearray()
    signatures = []
    for committee, approvals in zip(committees, receipts, strict=True):
        require(approvals.keys() <= set(committee), "unassigned signer")
        bits = 0
        for seat, index in enumerate(sorted(committee)):
            if index in approvals:
                bits |= 1 << seat
                signatures.append(approvals[index])
        bitmaps.append(bits)
    return bytes(bitmaps), suite.aggregate(signatures)
