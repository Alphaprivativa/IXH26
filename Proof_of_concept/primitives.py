"""Protocol encodings, RFC 9162 tree shape, signatures and authenticated delivery."""

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

from Crypto.Protocol import HPKE
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def u32(value):
    return value.to_bytes(4, "big")


def enc(domain, *fields):
    """u32 integers; length-prefixed byte strings, including the ASCII domain."""
    result = bytearray()
    for field in (domain.encode("ascii"), *fields):
        if isinstance(field, int):
            result.extend(u32(field))
        else:
            result.extend(u32(len(field)))
            result.extend(field)
    return bytes(result)


def sha(data):
    return hashlib.sha256(data).digest()


def digest(domain, *fields):
    return sha(enc("IXH26/" + domain, *fields))


def opening_at(master, job, index):
    return hmac.digest(master, enc("IXH26/interval-opening/v3", job, index), "sha256")


def pack(value):
    """JSON transport only. Signed protocol tuples use enc()."""
    def encode_bytes(item):
        if isinstance(item, bytes):
            return {"$bytes": item.hex()}
        raise TypeError(type(item).__name__)

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=encode_bytes).encode()


def unpack(data):
    def decode_bytes(obj):
        return bytes.fromhex(obj["$bytes"]) if obj.keys() == {"$bytes"} else obj

    return json.loads(data, object_hook=decode_bytes)


@dataclass(frozen=True)
class Tree:
    root: bytes
    left: "Tree | None" = None
    right: "Tree | None" = None
    count: int = 1

    @classmethod
    def build(cls, leaves, prefix):
        require(len(leaves) > 0, "empty tree")
        if len(leaves) == 1:
            return cls(leaves[0])
        split = 1 << ((len(leaves) - 1).bit_length() - 1)
        left = cls.build(leaves[:split], prefix)
        right = cls.build(leaves[split:], prefix)
        return cls(sha(prefix + left.root + right.root), left, right, len(leaves))

    def path(self, index):
        require(0 <= index < self.count, "invalid leaf index")
        if self.count == 1:
            return []
        if index < self.left.count:
            return [self.right.root, *self.left.path(index)]
        return [self.left.root, *self.right.path(index - self.left.count)]


def check_path(leaf, index, count, path, prefix, root):
    require(0 <= index < count, "invalid proof index")
    steps = []
    while count > 1:
        split = 1 << ((count - 1).bit_length() - 1)
        right = index >= split
        steps.append(right)
        if right:
            index -= split
            count -= split
        else:
            count = split
    require(len(path) == len(steps), "wrong Merkle path length")
    for right, sibling in reversed(list(zip(steps, path))):
        require(len(sibling) == 32, "invalid sibling")
        leaf = sha(prefix + (sibling + leaf if right else leaf + sibling))
    require(hmac.compare_digest(leaf, root), "Merkle inclusion failed")


def public(key):
    return key.public_key().export_key(format="DER")


def sign(key, message):
    return eddsa.new(key, "rfc8032").sign(message)


def verify(pub, message, signature):
    eddsa.new(ECC.import_key(pub), "rfc8032").verify(message, signature)


def seal(sender, receiver, context, plaintext):
    channel = HPKE.new(receiver_key=ECC.import_key(receiver), sender_key=sender,
                       aead_id=HPKE.AEAD.CHACHA20_POLY1305, info=context)
    return [channel.enc, channel.seal(plaintext, context)]


def unseal(sender, receiver, context, envelope):
    ephemeral, ciphertext = envelope
    channel = HPKE.new(receiver_key=receiver, sender_key=ECC.import_key(sender),
                       aead_id=HPKE.AEAD.CHACHA20_POLY1305, info=context, enc=ephemeral)
    return channel.unseal(ciphertext, context)


class Receipts:
    """Distinct, pinned suites. An offline certificate cannot verify as BLS."""

    def __init__(self, name):
        self.name = name
        self.bls = None
        if name == "bls-pop":
            try:
                from py_ecc.bls import G2ProofOfPossession
            except ImportError as exc:
                raise ValueError("BLS requires py-ecc. Install requirements.txt or select --suite ed25519-demo.") from exc
            self.bls = G2ProofOfPossession
        else:
            require(name == "ed25519-demo", "unknown receipt suite")

    def enroll_key(self):
        if self.bls:
            sk = self.bls.KeyGen(secrets.token_bytes(32))
            return sk, self.bls.SkToPk(sk), self.bls.PopProve(sk)
        sk = ECC.generate(curve="Ed25519")
        pk = public(sk)
        return sk, pk, sign(sk, digest("demo-pop/v1", pk))

    def check_pop(self, pk, proof):
        if self.bls:
            require(self.bls.PopVerify(pk, proof), "invalid BLS proof of possession")
        else:
            verify(pk, digest("demo-pop/v1", pk), proof)

    def sign(self, key, msg):
        return self.bls.Sign(key, msg) if self.bls else sign(key, msg)

    def check(self, pk, msg, signature):
        if self.bls:
            require(self.bls.Verify(pk, msg, signature), "invalid worker receipt")
        else:
            verify(pk, msg, signature)

    def aggregate(self, signatures):
        return self.bls.Aggregate(signatures) if self.bls else b"".join(signatures)

    def check_aggregate(self, keys, messages, signature):
        require(len(keys) == len(messages) and len(keys) > 0, "missing key/message pairs")
        if self.bls:
            require(self.bls.AggregateVerify(keys, messages, signature), "invalid BLS aggregate")
        else:
            require(len(signature) == 64 * len(keys), "invalid multisignature length")
            for i, (key, message) in enumerate(zip(keys, messages)):
                self.check(key, message, signature[64*i:64*(i+1)])
