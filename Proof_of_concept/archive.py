"""Local 2-of-3 storage and custody example for a certified JPEG and opening."""

import secrets

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Util.strxor import strxor

from primitives import (Tree, check_path, digest, enc, pack, public, require, seal,
                        sha, sign, unpack, unseal, verify)


# P-256 field and scalar order as specified by SEC 2.
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = ECC.construct(curve="P-256", d=1).pointQ


def blinding_generator():
    # Deterministic public hash-and-lift, with no chosen discrete log relative to G.
    for counter in range(256):
        x = int.from_bytes(digest("archive/pedersen-H/v1", counter), "big")
        if x >= P:
            continue
        rhs = (x**3 - 3*x + B) % P
        y = pow(rhs, (P+1)//4, P)
        if y*y % P == rhs:
            return ECC.EccPoint(x, y, curve="P-256")
    raise ValueError("failed to derive public generator")


H = blinding_generator()


def point_bytes(point):
    return ECC.construct(curve="P-256", point_x=point.x, point_y=point.y).export_key(
        format="SEC1", compress=True)


def share_check(commitments, index, pair):
    require(1 <= index <= 3 and len(pair) == 2, "invalid share index or shape")
    a, b = pair
    require(0 <= a < ORDER and 0 <= b < ORDER, "noncanonical scalar")
    v0, v1 = [ECC.import_key(p, curve_name="P-256").pointQ for p in commitments]
    require(G*a + H*b == v0 + v1*index, "invalid custody share")


def key(seed, cert_id, nonce):
    return HKDF(seed.to_bytes(32, "big"), 32, cert_id + nonce, SHA256, context=b"IXH26/archive-key/v1")


def archive_header(cert_id, nonce):
    return enc("IXH26/archive/v1", cert_id, nonce, b"JPEG+opening/AES256GCM/XOR2of3/P256-VSS2of3")


def shard_leaf(cert_id, nonce, index, shard):
    return digest("archive/shard/v1", cert_id, nonce, index, shard)


def manifest_id(manifest):
    return digest("archive/manifest/v1", pack(manifest))


def grant_message(mid, reader, request, expiry):
    return digest("archive/recover-grant/v1", mid, reader, request, expiry)


def release(owner_pk, signed_manifest, grant, index, custodian, pair, height):
    manifest, signature = signed_manifest
    mid = manifest_id(manifest)
    verify(owner_pk, mid, signature)
    require(public(custodian) == manifest["custodians"][index-1], "wrong custodian")
    share_check(manifest["commitments"], index, pair)
    reader, request, expiry, authorization = grant
    message = grant_message(mid, reader, request, expiry)
    verify(owner_pk, message, authorization)
    require(height <= expiry, "expired recovery grant")
    return [index, seal(custodian, reader, enc("IXH26/release/v1", message, index), pack(pair))]


def archive(owner, reader_pk, cert_id, jpeg, opening, height):
    coefficients = [1 + secrets.randbelow(ORDER-1) for _ in range(4)]
    a0, a1, b0, b1 = coefficients
    commitments = [point_bytes(G*a0 + H*b0), point_bytes(G*a1 + H*b1)]
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key(a0, cert_id, nonce), AES.MODE_GCM, nonce=nonce)
    cipher.update(archive_header(cert_id, nonce))
    ciphertext, tag = cipher.encrypt_and_digest(opening + jpeg)
    data = ciphertext + tag
    half = (len(data)+1)//2
    first, second = data[:half], data[half:].ljust(half, b"\0")
    shards = [first, second, strxor(first, second)]
    tree = Tree.build([shard_leaf(cert_id, nonce, i, shard) for i, shard in enumerate(shards)], b"\x05")
    custodians = [ECC.generate(curve="Curve25519") for _ in shards]
    manifest = dict(certificate=cert_id, nonce=nonce, length=len(data), ciphertext=sha(data),
                    root=tree.root, commitments=commitments, custodians=list(map(public, custodians)))
    mid = manifest_id(manifest)
    signed = [manifest, sign(owner, mid)]
    request, expiry = secrets.token_bytes(32), height + 10
    grant = [reader_pk, request, expiry, sign(owner, grant_message(mid, reader_pk, request, expiry))]
    releases = []
    for i, custodian in enumerate(custodians, 1):
        pair = [(a0+i*a1) % ORDER, (b0+i*b1) % ORDER]
        releases.append(release(public(owner), signed, grant, i, custodian, pair, height))
    fragments = [[i, shard, tree.path(i)] for i, shard in enumerate(shards)]
    return dict(manifest=signed, grant=grant, fragments=fragments, releases=releases)


def recover(bundle, reader, owner_pk, cert_id, pinned_manifest):
    manifest, signature = bundle["manifest"]
    mid = manifest_id(manifest)
    require(mid == pinned_manifest and manifest["certificate"] == cert_id, "unregistered archive")
    verify(owner_pk, mid, signature)
    recipient, request, expiry, authorization = bundle["grant"]
    require(public(reader) == recipient, "wrong archive recipient")
    message = grant_message(mid, recipient, request, expiry)
    verify(owner_pk, message, authorization)
    nonce, length = manifest["nonce"], manifest["length"]
    shards = {}
    for i, shard, proof in bundle["fragments"]:
        try:
            require(len(shard) == (length+1)//2, "wrong shard length")
            check_path(shard_leaf(cert_id, nonce, i, shard), i, 3, proof, b"\x05", manifest["root"])
        except ValueError:
            continue
        shards[i] = shard
    require(len(shards) >= 2, "fewer than two valid ciphertext fragments")
    if 0 not in shards:
        shards[0] = strxor(shards[1], shards[2])
    if 1 not in shards:
        shards[1] = strxor(shards[0], shards[2])
    data = (shards[0] + shards[1])[:length]
    require(sha(data) == manifest["ciphertext"], "ciphertext digest mismatch")
    shares = {}
    for i, envelope in bundle["releases"]:
        try:
            require(1 <= i <= 3, "unknown custodian")
            pair = unpack(unseal(manifest["custodians"][i-1], reader,
                                 enc("IXH26/release/v1", message, i), envelope))
            share_check(manifest["commitments"], i, pair)
        except ValueError:
            continue
        shares[i] = pair[0]
    require(len(shares) >= 2, "fewer than two valid custody shares")
    x, y = sorted(shares)[:2]
    seed = (y*shares[x] - x*shares[y]) * pow(y-x, -1, ORDER) % ORDER
    cipher = AES.new(key(seed, cert_id, nonce), AES.MODE_GCM, nonce=nonce)
    cipher.update(archive_header(cert_id, nonce))
    package = cipher.decrypt_and_verify(data[:-16], data[-16:])
    return package[32:], package[:32]
