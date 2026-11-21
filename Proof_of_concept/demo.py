"""Run, audit and recover an IXH26 exact-render certificate locally."""

import argparse
import secrets
import sys
from dataclasses import asdict
from pathlib import Path

from Crypto.PublicKey import ECC

from archive import archive, manifest_id, recover
from assignments import aggregate_receipts, collect_receipts
from primitives import Receipts, digest, pack, public, require, sign, unpack, verify
from protocol import (CaptureRuntime, EPOCH, Job, Ledger, LEGACY_POLICY, NETWORK, POLICY, Worker, appraise,
                      camera_capture, capture_id, certificate_id, check_certificate, draw,
                      check_profile, check_roster, commit_file, groups, prepare_file, statement,
                      check_wallet_bindings, beacon_value)
from render import Geometry, fixture, render_dng


def build(suite_name, with_archive=True):
    check_profile()
    suite = Receipts(suite_name)
    sensor, vendor, owner, ledger_key = [ECC.generate(curve="Ed25519") for _ in range(4)]
    owner_channel, reader = [ECC.generate(curve="Curve25519") for _ in range(2)]
    workers = [Worker(suite) for _ in range(5)]
    runtime = CaptureRuntime(vendor, sensor)
    ledger = Ledger.enroll(runtime.policy, workers, suite)

    # A crop, orientation change, strong CFA boundaries and partial edge MCUs.
    g = Geometry(43, 33, 1, 2, 39, 29, 6)
    plane = fixture(g)
    capture = camera_capture(sensor, public(owner), g, plane)
    nonce, master = secrets.token_bytes(32), secrets.token_bytes(32)
    job = Job(nonce, public(owner), public(owner_channel), capture_id(public(sensor), capture[0]),
              g, digest("opening/v3", nonce, master), suite_name, 12, ledger.challenge(nonce))
    dng, samples, salts, raw_tree, evidence = runtime.extract(job, capture, plane, ledger)
    a = statement(job, raw_tree.root)
    jpeg = render_dng(dng, g)
    candidate, jpeg_tree, openings, digests = prepare_file(job, a, jpeg, master)
    authorization = sign(owner, digest("reserve/v1", job.j, a, candidate))
    target = ledger.reserve(job, a, candidate, capture, authorization)
    ledger.advance()
    _, _, _, beacon = ledger.finalized(job)
    committees, receipts = collect_receipts(job, ledger, workers, owner_channel, samples, salts,
                                            raw_tree, evidence, jpeg_tree, openings, digests)
    bitmaps, signature = aggregate_receipts(suite, committees, receipts)
    cert_id = ledger.register(job, digests, bitmaps, signature)

    checkpoint = dict(version=3, job=asdict(job), a=a, candidate=candidate, round=target,
                      height=ledger.height, beacon=beacon, roster=ledger.roster, policy=ledger.policy,
                      wallet_bindings=ledger.wallet_bindings, beacon_key=ledger.beacon_key,
                      beacon_proof=ledger.beacon_proofs[target], **ledger.certificates[job.j])
    bundle = None
    if with_archive:
        bundle = archive(owner, public(reader), cert_id, jpeg, master, ledger.height)
        checkpoint["manifest"] = manifest_id(bundle["manifest"][0])
        verify(job.owner, checkpoint["manifest"], bundle["manifest"][1])
        require(bundle["manifest"][0]["certificate"] == cert_id, "archive certificate mismatch")
    signed = [checkpoint, sign(ledger_key, digest("local-checkpoint/v1", pack(checkpoint)))]
    return signed, public(ledger_key), dng, jpeg, master, evidence, bundle, reader


def audit(signed, trusted_key, expected_suite):
    checkpoint, signature = signed
    verify(trusted_key, digest("local-checkpoint/v1", pack(checkpoint)), signature)
    version = checkpoint["version"]
    require(version in (1, 2, 3), "unsupported checkpoint")
    check_profile()
    policy = POLICY if version == 3 else LEGACY_POLICY
    job = Job.restore(checkpoint["job"] if version == 3 else {"assignment_policy": policy, **checkpoint["job"]})
    require(job.network == NETWORK and job.assignment_policy == policy, "wrong checkpoint domain")
    require(job.suite == expected_suite, "unexpected receipt suite")
    require(job.epoch == EPOCH and 1 < checkpoint["round"] <= checkpoint["height"] <= job.expires,
            "invalid finalization height")
    suite = Receipts(expected_suite)
    roster = checkpoint["roster"]
    check_roster(roster, suite)
    if version >= 2:
        require(checkpoint["policy"].get("version") == 2, "unexpected capture policy")
        check_wallet_bindings(roster, checkpoint["wallet_bindings"])
        require(beacon_value(checkpoint["beacon_key"], checkpoint["round"], checkpoint["beacon_proof"])
                == checkpoint["beacon"], "invalid checkpoint beacon")
    a, candidate = checkpoint["a"], checkpoint["candidate"]
    aggregate = checkpoint["signature"]
    if version == 3:
        digests, bitmaps = checkpoint["digests"], checkpoint["bitmaps"]
        check_certificate(job, a, candidate, checkpoint["round"], checkpoint["beacon"], roster,
                          digests, bitmaps, aggregate, suite)
        cert_id = certificate_id(job, a, candidate, digests, bitmaps, aggregate)
    else:  # Read-only support for authenticated common-message checkpoints.
        bitmap = checkpoint["bitmap"]
        bits = int.from_bytes(bitmap, "little")
        require(len(bitmap) == (len(roster)+7)//8 and bits >> len(roster) == 0, "invalid bitmap")
        selected = {i for i in range(len(roster)) if bits & (1 << i)}
        committees = draw(job, a, candidate, checkpoint["round"], checkpoint["beacon"], roster)
        require(selected <= set().union(*committees), "unassigned signer")
        require(all(len(selected.intersection(c)) >= 2 for c in committees), "missing quorum")
        msg = digest("exact-receipt/v3", job.j, a, candidate)
        keys = [roster[i][0] for i in sorted(selected)]
        if suite.bls:
            require(suite.bls.FastAggregateVerify(keys, msg, aggregate), "invalid historical BLS aggregate")
        else:
            suite.check_aggregate(keys, [msg] * len(selected), aggregate)
        cert_id = digest("certificate/v3", job.j, a, candidate, bitmap, aggregate)
    require(cert_id == checkpoint["certificate"], "incorrect certificate digest")
    return job, checkpoint


def verify_jpeg(job, checkpoint, jpeg, master):
    actual, _, _ = commit_file(job, checkpoint["a"], jpeg, master)
    require(actual == checkpoint["candidate"], "file does not match the certified JPEG")


def recover_verified(job, checkpoint, bundle, reader):
    require("manifest" in checkpoint, "certificate has no recovery archive")
    jpeg, master = recover(bundle, reader, job.owner, checkpoint["certificate"], checkpoint["manifest"])
    verify_jpeg(job, checkpoint, jpeg, master)
    return jpeg


def demo(out, suite, with_archive=True):
    require(not out.exists(), "choose a new output directory")
    signed, anchor, dng, jpeg, master, evidence, bundle, reader = build(suite, with_archive)
    job, checkpoint = audit(signed, anchor, suite)
    appraise(job, checkpoint["a"], evidence, checkpoint["policy"])
    verify_jpeg(job, checkpoint, jpeg, master)
    # Exercise authorized recovery while one storage node and a different custodian are offline.
    if with_archive:
        reduced = {**bundle, "fragments": bundle["fragments"][1:], "releases": bundle["releases"][:2]}
        require(recover_verified(job, checkpoint, reduced, reader) == jpeg, "recovery mismatch")
    out.mkdir(parents=True)
    private = out / "private"
    private.mkdir()
    (out / "ledger-public.der").write_bytes(anchor)
    (out / "certificate.json").write_bytes(pack(signed))
    (private / "capture.dng").write_bytes(dng)
    (private / "candidate.jpg").write_bytes(jpeg)
    (private / "opening.bin").write_bytes(master)
    (private / "attestation.json").write_bytes(pack(evidence))
    if with_archive:
        (private / "archive.json").write_bytes(pack(bundle))
        (private / "reader-key.der").write_bytes(reader.export_key(format="DER", use_pkcs8=True))
    print(f"Certified and verified {len(jpeg)} JPEG bytes ({suite}).")
    print(f"{job.geometry.count} intervals, {len(groups(job.geometry.count))} groups, quorum 2 of 3 in every group.")
    print(f"Certificate {checkpoint['certificate'].hex()}\nFiles in {out}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (("certify", "run the seven steps through private JPEG verification"),
                               ("demo", "include the optional recovery archive")):
        run = commands.add_parser(command, help=help_text)
        run.add_argument("out", type=Path)
        run.add_argument("--suite", choices=["bls-pop", "ed25519-demo"], default="bls-pop")
    for cmd in ("audit", "verify", "recover"):
        sub = commands.add_parser(cmd)
        sub.add_argument("certificate", type=Path)
        sub.add_argument("--trust", type=Path, required=True, help="trusted local ledger public key (DER)")
        if cmd == "verify":
            sub.add_argument("jpeg", type=Path)
            sub.add_argument("opening", type=Path)
            sub.add_argument("--evidence", type=Path)
        if cmd == "recover":
            sub.add_argument("archive", type=Path)
            sub.add_argument("reader_key", type=Path)
            sub.add_argument("output", type=Path)
        sub.add_argument("--suite", choices=["bls-pop", "ed25519-demo"], default="bls-pop")
    args = parser.parse_args()
    if args.command in ("certify", "demo"):
        demo(args.out, args.suite, with_archive=args.command == "demo")
        return
    job, checkpoint = audit(unpack(args.certificate.read_bytes()), args.trust.read_bytes(), args.suite)
    if args.command == "verify":
        verify_jpeg(job, checkpoint, args.jpeg.read_bytes(), args.opening.read_bytes())
        if args.evidence:
            appraise(job, checkpoint["a"], unpack(args.evidence.read_bytes()), checkpoint["policy"])
    if args.command == "recover":
        jpeg = recover_verified(job, checkpoint, unpack(args.archive.read_bytes()),
                                ECC.import_key(args.reader_key.read_bytes()))
        with args.output.open("xb") as file:
            file.write(jpeg)
    print(f"{args.command} succeeded for {checkpoint['certificate'].hex()} ({job.suite})")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, IndexError, OverflowError) as exc:
        sys.exit(f"Rejected: {exc}")
