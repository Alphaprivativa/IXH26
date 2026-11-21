import copy
import importlib.util
import itertools
import unittest
from dataclasses import replace
from io import BytesIO
from unittest.mock import patch

from Crypto.PublicKey import ECC
from PIL import Image
from PIL.TiffImagePlugin import ImageFileDirectory_v2

from archive import share_check
from assignments import aggregate_receipts
from demo import audit, build, recover_verified, verify_jpeg
from primitives import Receipts, Tree, check_path, digest, pack, public, seal, sha, sign, unpack, unseal
from protocol import (CaptureRuntime, Ledger, Worker, appraise, beacon_value, camera_capture, capture_id,
                      channel_context, check_certificate, check_wallet_bindings, commitment, commit_file, draw, groups,
                      jpeg_tree_from_digests, receipt_message, statement)
from render import (Geometry, dng_header, fixture, footprint, header, intervals, render_dng,
                    render_interval)


def changed(data):
    return bytes([data[0] ^ 1]) + data[1:]


class RenderTests(unittest.TestCase):
    def test_whole_frame_matches_disclosures_in_all_orientations(self):
        for orientation in range(1, 9):
            with self.subTest(orientation=orientation):
                g = Geometry(21, 19, 2, 1, 17, 15, orientation)
                p = fixture(g)
                dng = dng_header(g) + p
                stream = BytesIO(dng)
                tags = ImageFileDirectory_v2(stream.read(8))
                tags.load(stream)
                self.assertEqual(tags[50706], bytes([1, 4, 0, 0]))
                self.assertEqual(tags[274], orientation)
                stream.seek(tags[273][0])
                self.assertEqual(stream.read(tags[279][0]), p)
                jpeg = render_dng(dng, g)
                with Image.open(BytesIO(jpeg)) as image:
                    image.load()
                    self.assertEqual(g.size, image.size)
                parts = [render_interval(footprint(p, g, i), g, i) for i in range(g.count)]
                self.assertEqual(parts, intervals(jpeg, g.size))

    def test_strict_entropy_parser(self):
        g = Geometry(17, 9, 0, 0, 17, 9, 1)
        data = render_dng(dng_header(g) + fixture(g), g)
        first = data.index(b"\xff\xd0", len(header(g.size)))
        for bad in (data+b"!", data[:-1], changed(data), data[:first]+data[first+2:],
                    data[:first]+b"\xff"+data[first:], data[:first]+b"\xff\xd2"+data[first+2:]):
            with self.assertRaises(ValueError):
                intervals(bad, g.size)
        size = (1, 1)
        self.assertEqual(intervals(header(size)+b"\x01\xff\x00\xff\xd9", size), [b"\x01\xff\x00"])

    def test_tree_shape_and_index(self):
        for n in (1, 2, 3, 5, 8, 17):
            leaves = [sha(bytes([i])) for i in range(n)]
            tree = Tree.build(leaves, b"\x01")
            for i, leaf in enumerate(leaves):
                check_path(leaf, i, n, tree.path(i), b"\x01", tree.root)
                with self.assertRaises(ValueError):
                    check_path(changed(leaf), i, n, tree.path(i), b"\x01", tree.root)
                if n > 1:
                    with self.assertRaises(ValueError):
                        check_path(leaf, (i+1) % n, n, tree.path(i), b"\x01", tree.root)


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signed, cls.anchor, _, cls.jpeg, cls.master, cls.evidence, cls.bundle, cls.reader = build("ed25519-demo")
        cls.job, cls.checkpoint = audit(unpack(pack(cls.signed)), cls.anchor, "ed25519-demo")

    def test_public_audit_and_private_delivery(self):
        appraise(self.job, self.checkpoint["a"], self.evidence, self.checkpoint["policy"])
        verify_jpeg(self.job, self.checkpoint, self.jpeg, self.master)
        for bad in (changed(self.jpeg), self.jpeg[:-1], self.jpeg+b"x"):
            with self.assertRaises(ValueError):
                verify_jpeg(self.job, self.checkpoint, bad, self.master)
        parts = intervals(self.jpeg, self.job.geometry.size)
        parts[0], parts[1] = parts[1], parts[0]
        swapped = header(self.job.geometry.size) + b"".join(
            part + bytes([255, 0xd9 if i == len(parts)-1 else 0xd0+i%8]) for i, part in enumerate(parts))
        with self.assertRaisesRegex(ValueError, "certified JPEG"):
            verify_jpeg(self.job, self.checkpoint, swapped, self.master)
        with self.assertRaisesRegex(ValueError, "opening"):
            verify_jpeg(self.job, self.checkpoint, self.jpeg, changed(self.master))
        with self.assertRaisesRegex(ValueError, "suite"):
            audit(self.signed, self.anchor, "bls-pop")
        with self.assertRaises(ValueError):
            audit(self.signed, public(ECC.generate(curve="Ed25519")), "ed25519-demo")

    def test_capture_authorization_and_reservation(self):
        owner, sensor, vendor = [ECC.generate(curve="Ed25519") for _ in range(3)]
        runtime = CaptureRuntime(vendor, sensor)
        ledger = Ledger(runtime.policy, self.checkpoint["roster"], Receipts("ed25519-demo"))
        g = self.job.geometry
        plane = fixture(g)
        capture = camera_capture(sensor, public(owner), g, plane)
        job = replace(self.job, owner=public(owner), capture_id=capture_id(public(sensor), capture[0]),
                      challenge=ledger.challenge(self.job.nonce))
        for modified in (replace(job, capture_id=bytes(32)), replace(job, epoch=2),
                         replace(job, geometry=replace(g, orientation=4)), replace(job, challenge=b"")):
            with self.assertRaises(ValueError):
                runtime.extract(modified, capture, plane, ledger)
        with self.assertRaises(ValueError):
            runtime.extract(job, capture, changed(plane), ledger)
        with self.assertRaises(ValueError):
            runtime.extract(job, camera_capture(owner, job.owner, g, plane), plane, ledger)
        dng, _, _, tree, ev = runtime.extract(job, capture, plane, ledger)
        a = statement(job, tree.root)
        with self.assertRaises(ValueError):
            appraise(job, a, {**ev, "quote": changed(ev["quote"])}, ledger.policy)
        candidate = commit_file(job, a, render_dng(dng, g), self.master)[0]
        def reserve(c):
            return ledger.reserve(job, a, c, capture, sign(owner, digest("reserve/v1", job.j, a, c)))
        self.assertEqual(reserve(candidate), reserve(candidate))
        with self.assertRaises(ValueError):
            ledger.finalized(job)
        ledger.advance()
        original = ledger.finalized(job)
        ledger.advance()
        self.assertEqual(original, ledger.finalized(job))
        with self.assertRaises(ValueError):
            reserve(changed(candidate))
        ledger.height = job.expires + 1
        with self.assertRaisesRegex(ValueError, "expired"):
            ledger.finalized(job)

    def test_epoch_credentials_and_beacon_round(self):
        c = self.checkpoint
        roster, bindings = c["roster"], list(c["wallet_bindings"])
        wallet, proof = bindings[0]
        for invalid in (bindings[:-1], [bindings[1], *bindings[1:]], [(wallet, changed(proof)), *bindings[1:]],
                        [bindings[1], bindings[0], *bindings[2:]]):
            with self.assertRaises(ValueError):
                check_wallet_bindings(roster, invalid)
        self.assertEqual(beacon_value(c["beacon_key"], c["round"], c["beacon_proof"]), c["beacon"])
        with self.assertRaises(ValueError):
            beacon_value(c["beacon_key"], c["round"] + 1, c["beacon_proof"])
        ev = self.evidence
        for policy in ({"devices": []}, {"revoked": [ev["attester"]]}, {"revoked": [ev["key"]]},
                       {"minimum_state": 2}, {"measurement": changed(ev["measurement"])}, {"epoch": 2}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                appraise(self.job, c["a"], ev, {**c["policy"], **policy})
        with self.assertRaises(ValueError):
            appraise(self.job, c["a"], {**ev, "certificate": changed(ev["certificate"])}, c["policy"])

    def test_worker_rejects_wrong_input_and_incomplete_assignment(self):
        original = Worker.process
        exercised = []

        def intercept(worker, job, ledger, index, envelope):
            a, candidate, _, _ = ledger.finalized(job)
            ctx = channel_context(job, a, candidate, index, worker.channel, b"assignment")
            packet = unpack(unseal(job.channel, worker._channel, ctx, envelope))
            mutations = []
            for field in ("opening", "samples", "salt"):
                bad = copy.deepcopy(packet)
                bad["pieces"][0][field] = changed(bad["pieces"][0][field])
                mutations.append(bad)
            mutations.append({**packet, "pieces": packet["pieces"][:-1]})
            # Capture the enrolled owner's channel when it sends the original packet.
            for bad in mutations:
                with self.assertRaises(ValueError):
                    original(worker, job, ledger, index, seal(owner_channel[0], worker.channel, ctx, pack(bad)))
            with self.assertRaises(ValueError):
                original(worker, job, ledger, index, [envelope[0], changed(envelope[1])])
            reply = original(worker, job, ledger, index, envelope)
            with self.assertRaisesRegex(ValueError, "replay"):
                original(worker, job, ledger, index, envelope)
            exercised.append(index)
            return reply

        owner_channel = []
        def capture_channel(sender, *args):
            owner_channel[:] = [sender]
            return seal(sender, *args)

        with patch("assignments.seal", capture_channel), patch.object(Worker, "process", intercept):
            build("ed25519-demo")
        self.assertEqual(len(exercised), 5)

    def test_quorum_bitmap_and_aggregate(self):
        c = self.checkpoint
        suite = Receipts(self.job.suite)
        committees = draw(self.job, c["a"], c["candidate"], c["round"], c["beacon"], c["roster"])
        self.assertEqual(sorted(i for g in groups(self.job.geometry.count) for i in g),
                         list(range(self.job.geometry.count)))
        def check(bitmaps, signature, digests=c["digests"]):
            check_certificate(self.job, c["a"], c["candidate"], c["round"], c["beacon"], c["roster"],
                              digests, bitmaps, signature, suite)
        layout = groups(self.job.geometry.count)
        receipts = [c["signature"][i:i+64] for i in range(0, len(c["signature"]), 64)]
        keys, messages = [], []
        for g, indices in enumerate(layout):
            msg = receipt_message(self.job, c["a"], c["candidate"], g, indices, c["digests"])
            for index in sorted(committees[g]):
                keys.append(c["roster"][index][0])
                messages.append(msg)
        self.assertEqual(len(set(messages)), len(layout))
        # The same operator signs distinct messages across overlapping committees.
        other = next(i for i in range(3, len(keys)) if keys[i] == keys[0])
        swapped = receipts.copy()
        swapped[0], swapped[other] = swapped[other], swapped[0]
        with self.assertRaises(ValueError):
            check(c["bitmaps"], b"".join(swapped))
        # Choose seats 1 and 2 in group 0. Both receipts must be present.
        check(bytes([6]) + c["bitmaps"][1:], b"".join(receipts[1:]))
        partial = b"".join(receipts[2:])
        suite.check_aggregate(keys[2:], messages[2:], partial)
        with self.assertRaisesRegex(ValueError, "quorum"):
            check(bytes([4]) + c["bitmaps"][1:], partial)
        for bitmap in (b"", c["bitmaps"][:-1], b"\x0f" + c["bitmaps"][1:]):
            with self.assertRaisesRegex(ValueError, "bitmap"):
                check(bitmap, c["signature"])
        with self.assertRaises(ValueError):
            check(c["bitmaps"], changed(c["signature"]))
        for vector in (c["digests"][:-1], [b"short", *c["digests"][1:]], list(reversed(c["digests"]))):
            with self.assertRaises(ValueError):
                check(c["bitmaps"], c["signature"], vector)

    def test_archive_thresholds_and_authorization(self):
        for fragments, releases in itertools.product(itertools.combinations(range(3), 2), repeat=2):
            bundle = {**self.bundle, "fragments": [self.bundle["fragments"][i] for i in fragments],
                      "releases": [self.bundle["releases"][i] for i in releases]}
            self.assertEqual(self.jpeg, recover_verified(self.job, self.checkpoint, bundle, self.reader))
        for field, reason in (("fragments", "fragments"), ("releases", "shares")):
            bad = {**self.bundle, field: [self.bundle[field][0]] * 3}
            with self.assertRaisesRegex(ValueError, reason):
                recover_verified(self.job, self.checkpoint, bad, self.reader)
        with self.assertRaisesRegex(ValueError, "recipient"):
            recover_verified(self.job, self.checkpoint, self.bundle, ECC.generate(curve="Curve25519"))
        with self.assertRaisesRegex(ValueError, "invalid custody share"):
            share_check(self.bundle["manifest"][0]["commitments"], 1, [0, 0])

    def test_assignment_and_conflict_evidence(self):
        suite = Receipts("ed25519-demo")
        workers = [Worker(suite) for _ in range(5)]
        ledger = Ledger.enroll(self.checkpoint["policy"], workers, suite)
        job = replace(self.job, geometry=Geometry(3, 3, 0, 0, 3, 3, 1))
        # Install a single finalized test fixture to exercise one group with two unassigned operators.
        from protocol import PROFILE
        a, leaf, beacon = [sha(label) for label in (b"statement", b"leaf", b"round 2")]
        candidate = commitment(job, a, jpeg_tree_from_digests([leaf]).root)
        ledger.reservations[job.capture_id, PROFILE] = (job.j, a, candidate, 2)
        ledger.beacons[2] = beacon
        committee = draw(job, a, candidate, 2, beacon, ledger.roster)[0]
        outsider = next(i for i in range(5) if i not in committee)
        index = committee[0]
        def receipt(c):
            msg = receipt_message(job, a, c, 0, [0], [leaf])
            return a, c, [leaf], suite.sign(workers[index]._key, msg)
        first, second = receipt(candidate), receipt(changed(candidate))
        with self.assertRaises(ValueError):
            ledger.report_conflict(job, index, 0, first, first)
        with self.assertRaises(ValueError):
            ledger.report_conflict(job, outsider, 0, first, second)
        ledger.report_conflict(job, index, 0, first, second)
        self.assertIn((job.epoch, index), ledger.slashed)

    @unittest.skipUnless(importlib.util.find_spec("py_ecc"), "install requirements.txt for BLS12-381")
    def test_bls_overlapping_committees(self):
        suite = Receipts("bls-pop")
        job = replace(self.job, suite=suite.name, geometry=Geometry(16, 16, 0, 0, 16, 16, 1))
        keys = [11, 22, 33]
        roster = [(suite.bls.SkToPk(k), bytes([k]), b"") for k in keys]
        a, beacon = sha(b"statement"), sha(b"beacon")
        digests = [sha(bytes([i])) for i in range(4)]
        candidate = commitment(job, a, jpeg_tree_from_digests(digests).root)
        committees = draw(job, a, candidate, 2, beacon, roster)
        receipts = []
        for group, indices in enumerate(groups(4)):
            msg = receipt_message(job, a, candidate, group, indices, digests)
            receipts.append({i: suite.sign(keys[i], msg) for i in (group, group+1)})
        def check():
            bitmaps, signature = aggregate_receipts(suite, committees, receipts)
            self.assertEqual(bitmaps, bytes([3, 6]))
            check_certificate(job, a, candidate, 2, beacon, roster, digests, bitmaps, signature, suite)
        check()
        receipts[1][1] = receipts[0][1]
        with self.assertRaisesRegex(ValueError, "invalid BLS aggregate"):
            check()

    @unittest.skipUnless(importlib.util.find_spec("py_ecc"), "install requirements.txt for BLS12-381")
    def test_bls_end_to_end(self):
        signed, anchor, _, jpeg, master, _, bundle, reader = build("bls-pop")
        job, checkpoint = audit(signed, anchor, "bls-pop")
        self.assertEqual(len(checkpoint["signature"]), 96)
        verify_jpeg(job, checkpoint, jpeg, master)
        self.assertEqual(jpeg, recover_verified(job, checkpoint, bundle, reader))


if __name__ == "__main__":
    unittest.main()
