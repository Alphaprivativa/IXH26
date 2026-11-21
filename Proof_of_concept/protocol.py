"""Authenticated capture, dual commitments, public draw and certificate rules."""

import secrets
from dataclasses import asdict, dataclass
from functools import lru_cache

from Crypto.PublicKey import ECC

from primitives import (Tree, check_path, digest, enc, opening_at, pack,
                        public, require, seal, sha, sign, unpack, unseal, verify)
from render import (Geometry, dng_header, fixture, footprint, header, intervals, record,
                    render_dng, render_interval)


VECTOR = bytes.fromhex("275376243e8350882e008233f1e5bbd81c55abbb7dd2bfcae4e368f56d6d389a")
PROFILE = digest("profile/v1", b"RGGB16le-integer-v1/JPEG95-444-RST1", VECTOR)
MAX_DISCLOSED_SAMPLES = 1280
LEGACY_POLICY = enc("IXH26/band-max2/balanced-3/quorum2/next-local-round/v1", MAX_DISCLOSED_SAMPLES)
POLICY = enc("IXH26/band-max2/balanced-3/quorum2/next-local-round/v2", MAX_DISCLOSED_SAMPLES)
EPOCH = 1
MEASUREMENT = digest("measurement/v1", b"simulated-capture-runtime/1")
NETWORK = b"ixh26-local/certificate-contract-1"


@lru_cache(maxsize=1)
def check_profile():
    g = Geometry(23, 19, 1, 2, 19, 15, 6)
    plane = fixture(g)
    data = render_dng(dng_header(g) + plane, g)
    require(sha(data) == VECTOR, "JPEG encoder failed the registered conformance vector")
    for i, segment in enumerate(intervals(data, g.size)):
        require(render_interval(footprint(plane, g, i), g, i) == segment, "RAW renderer mismatch")


@dataclass(frozen=True)
class Job:
    nonce: bytes
    owner: bytes
    channel: bytes
    capture_id: bytes
    geometry: Geometry
    opening: bytes
    suite: str
    expires: int
    challenge: bytes
    epoch: int = EPOCH
    network: bytes = NETWORK
    assignment_policy: bytes = POLICY

    @property
    def j(self):
        return digest("job/v3", self.network, self.nonce, self.owner, self.channel, self.capture_id,
                      PROFILE, self.geometry.wire(), self.geometry.count, self.opening,
                      self.suite.encode(), b"exact/private", self.assignment_policy, self.epoch, self.expires,
                      self.challenge)

    @classmethod
    def restore(cls, obj):
        return cls(**{**obj, "geometry": Geometry(**obj["geometry"])})


def camera_capture(sensor, owner, g, plane):
    frame = secrets.token_bytes(32)
    claim = dict(frame=frame, owner=owner, geometry=asdict(g), raw_digest=sha(plane))
    return claim, sign(sensor, capture_message(claim))


def capture_message(claim):
    return digest("sensor-frame/v1", claim["frame"], claim["owner"],
                  Geometry(**claim["geometry"]).wire(), claim["raw_digest"])


def capture_id(sensor, claim):
    return digest("capture-id/v1", sensor, claim["frame"])


def check_capture(job, policy, signed_capture):
    claim, signature = signed_capture
    require(policy["sensor"] not in policy.get("revoked", ()), "revoked sensor")
    verify(policy["sensor"], capture_message(claim), signature)
    require(job.capture_id == capture_id(policy["sensor"], claim), "wrong capture identifier")
    require(job.geometry == Geometry(**claim["geometry"]) and job.owner == claim["owner"],
            "capture metadata does not authorize this job")


def raw_leaf(job, i, salt, samples):
    require(len(salt) == 32, "invalid RAW salt")
    return sha(b"\x00" + enc("IXH26/raw-piece/v2", job.j, i, salt, record(job.geometry, i, samples)))


def statement(job, root):
    return digest("root-statement/v2", job.j, root, job.geometry.count, job.geometry.wire(), PROFILE)


def quote(job, key, policy):
    return digest("demo-attestation/v1", job.j, job.challenge, key, policy["sensor"],
                  MEASUREMENT, job.epoch, job.expires)


def device_certificate(device, sensor, attester, epoch):
    return digest("demo-device/v2", device, sensor, attester, epoch)


def runtime_quote(job, key, device, measurement, state):
    return digest("demo-attestation/v2", job.j, job.challenge, key, device, measurement, state,
                  job.epoch, job.expires)


class CaptureRuntime:
    """Simulated measured code and vendor attestation service in the same process."""

    def __init__(self, vendor, sensor):
        self._key = ECC.generate(curve="Ed25519")
        self._attester = ECC.generate(curve="Ed25519")
        self.device = secrets.token_bytes(32)
        self.policy = dict(version=2, vendor=public(vendor), sensor=public(sensor), devices=[self.device],
                           epoch=EPOCH, measurement=MEASUREMENT, minimum_state=1, revoked=[])
        cert = device_certificate(self.device, public(sensor), public(self._attester), EPOCH)
        self._certificate = sign(vendor, cert)

    def extract(self, job, signed_capture, plane, ledger):
        ledger.check_live(job)
        check_capture(job, self.policy, signed_capture)
        g = job.geometry
        require(len(plane) == 2*g.width*g.height and sha(plane) == signed_capture[0]["raw_digest"],
                "RAW data differs from sensor capture")
        salts = [secrets.token_bytes(32) for _ in range(g.count)]
        samples = [footprint(plane, g, i) for i in range(g.count)]
        tree = Tree.build([raw_leaf(job, i, salts[i], s) for i, s in enumerate(samples)], b"\x01")
        key = public(self._key)
        evidence = dict(root=tree.root, key=key, signature=sign(self._key, statement(job, tree.root)),
                        device=self.device, attester=public(self._attester), certificate=self._certificate,
                        measurement=MEASUREMENT, state=1,
                        quote=sign(self._attester, runtime_quote(job, key, self.device, MEASUREMENT, 1)))
        return dng_header(g) + plane, samples, salts, tree, evidence


def appraise(job, a, evidence, policy):
    root = evidence["root"]
    require(len(root) == 32 and statement(job, root) == a, "wrong root statement")
    if policy.get("version", 1) == 1:  # Historical local checkpoints
        verify(policy["vendor"], quote(job, evidence["key"], policy), evidence["quote"])
    else:
        require(policy["version"] == 2 and job.epoch == policy["epoch"], "wrong capture policy epoch")
        require(evidence["device"] in policy["devices"], "unenrolled device")
        require(all(k not in policy["revoked"] for k in (policy["sensor"], evidence["attester"], evidence["key"])),
                "revoked capture credential")
        cert = device_certificate(evidence["device"], policy["sensor"], evidence["attester"], job.epoch)
        verify(policy["vendor"], cert, evidence["certificate"])
        require(evidence["measurement"] == policy["measurement"] and evidence["state"] >= policy["minimum_state"],
                "unapproved runtime measurement or security state")
        msg = runtime_quote(job, evidence["key"], evidence["device"], evidence["measurement"], evidence["state"])
        verify(evidence["attester"], msg, evidence["quote"])
    verify(evidence["key"], a, evidence["signature"])


def interval_digest(job, a, i, opening, payload):
    require(len(opening) == 32, "invalid interval opening")
    return digest("jpeg-interval/v3", job.j, a, i, opening, payload)


def jpeg_tree_from_digests(digests):
    return Tree.build([sha(b"\x02" + d) for d in digests], b"\x03")


def commitment(job, a, root):
    return digest("exact-jpeg/v3", job.j, a, header(job.geometry.size), job.geometry.count, root)


def prepare_file(job, a, jpeg, master):
    require(len(master) == 32 and digest("opening/v3", job.nonce, master) == job.opening,
            "incorrect master opening")
    payloads = intervals(jpeg, job.geometry.size)
    openings = [opening_at(master, job.j, i) for i in range(len(payloads))]
    digests = [interval_digest(job, a, i, openings[i], p) for i, p in enumerate(payloads)]
    tree = jpeg_tree_from_digests(digests)
    return commitment(job, a, tree.root), tree, openings, digests


def commit_file(job, a, jpeg, master):
    return prepare_file(job, a, jpeg, master)[:3]


def groups(n):
    bands = min(2, n)
    width, remainder = divmod(n, bands)
    result = [[] for _ in range(width + bool(remainder))]
    start = 0
    for band in range(bands):
        length = width + (band < remainder)
        for offset in range(length):
            result[(offset + band) % length].append(start + offset)
        start += length
    return result


def roster_digest(roster):
    return digest("roster/v1", len(roster), *(enc("operator", *row) for row in roster))


def wallet_message(index, pk, channel):
    return digest("operator-wallet/v1", NETWORK, EPOCH, index, pk, channel)


def check_wallet_bindings(roster, bindings):
    require(len(roster) == len(bindings), "missing wallet authorization")
    require(len({wallet for wallet, _ in bindings}) == len(roster), "duplicate operator wallet")
    for i, ((pk, channel, _), (wallet, signature)) in enumerate(zip(roster, bindings)):
        verify(wallet, wallet_message(i, pk, channel), signature)


def beacon_value(key, target, proof):
    verify(key, digest("local-beacon-round/v1", NETWORK, EPOCH, target), proof)
    return sha(proof)


def draw(job, a, candidate, round_id, beacon, roster):
    seed = digest("draw/v1", job.j, a, candidate, round_id, beacon, roster_digest(roster))
    load = [0] * len(roster)
    disclosed = [set() for _ in roster]
    committees = []
    for group, indices in enumerate(groups(job.geometry.count)):
        coordinates = set()
        for i in indices:
            x0, y0, x1, y1 = job.geometry.bounds(i)
            coordinates.update(y*job.geometry.width+x for y in range(y0, y1) for x in range(x0, x1))

        def score(index):
            return load[index], digest("rank/v1", seed, group, index)

        eligible = [i for i, seen in enumerate(disclosed)
                    if len(seen) + len(coordinates - seen) <= MAX_DISCLOSED_SAMPLES]
        require(len(eligible) >= 3, "draw exceeds the RAW disclosure cap")
        selected = sorted(eligible, key=score)[:3]
        for index in selected:
            load[index] += 1
            disclosed[index].update(coordinates)
        committees.append(selected)
    return committees


def assigned(job, committees, worker):
    return sorted(i for group, members in zip(groups(job.geometry.count), committees, strict=True)
                  if worker in members for i in group)


def receipt_message(job, a, candidate, group, indices, digests):
    fields = [field for i in indices for field in (i, digests[i])]
    return enc("IXH26/jpeg-group-receipt/v1", job.j, a, candidate, group, len(indices), *fields)


def certificate_id(job, a, candidate, digests, bitmaps, signature):
    return digest("certificate/v4", job.j, a, candidate, len(digests), *digests, bitmaps, signature)


def check_roster(roster, suite):
    require(3 <= len(roster) <= 64, "invalid roster size")
    for column in (0, 1):
        require(len({row[column] for row in roster}) == len(roster), "duplicate operator key")
    for pk, channel, pop in roster:
        require(ECC.import_key(channel).curve == "Curve25519", "invalid channel key")
        suite.check_pop(pk, pop)


def check_certificate(job, a, candidate, round_id, beacon, roster, digests, bitmaps, signature, suite):
    require(job.epoch == EPOCH and suite.name == job.suite, "wrong certificate policy")
    require(len(digests) == job.geometry.count and all(isinstance(d, bytes) and len(d) == 32 for d in digests),
            "invalid interval digest vector")
    require(commitment(job, a, jpeg_tree_from_digests(digests).root) == candidate, "wrong candidate commitment")
    committees = draw(job, a, candidate, round_id, beacon, roster)
    require(isinstance(bitmaps, bytes) and len(bitmaps) == len(committees), "invalid group bitmap length")
    keys, messages = [], []
    for group, (indices, members) in enumerate(zip(groups(job.geometry.count), committees, strict=True)):
        bits = bitmaps[group]
        require(bits >> len(members) == 0, "invalid group bitmap padding")
        require(bits.bit_count() >= 2, f"missing quorum in group {group}")
        message = receipt_message(job, a, candidate, group, indices, digests)
        for seat, index in enumerate(sorted(members)):
            if bits & (1 << seat):
                keys.append(roster[index][0])
                messages.append(message)
    suite.check_aggregate(keys, messages, signature)


class Ledger:
    """In-memory, single-threaded finality and enrollment model."""

    def __init__(self, policy, roster, suite):
        check_roster(roster, suite)
        self.policy = dict(policy)
        self.roster = tuple(tuple(row) for row in roster)
        self.suite = suite
        self.height = 1
        self._beacon_key = ECC.generate(curve="Ed25519")
        self.beacon_key = public(self._beacon_key)
        self.beacon_proofs = {}
        self.beacons = {}
        self.reservations = {}
        self.challenges = {}
        self.certificates = {}
        self.slashed = set()

    @classmethod
    def enroll(cls, policy, workers, suite):
        # The local operator list stands in for wallet eligibility at this epoch.
        # A signed challenge decrypted from HPKE binds both application keys.
        registrar = ECC.generate(curve="Curve25519")
        roster = []
        for index, worker in enumerate(workers):
            challenge = secrets.token_bytes(32)
            pk, channel, pop = worker.enrollment
            ctx = enc("IXH26/enrollment/v1", NETWORK, EPOCH, index, pk, channel)
            box = seal(registrar, channel, ctx, challenge)
            response = worker.enroll(suite, public(registrar), ctx, box)
            suite.check(pk, digest("enrollment-response/v1", ctx, challenge), response)
            roster.append((pk, channel, pop))
        ledger = cls(policy, roster, suite)
        ledger.wallet_bindings = [worker.authorize_keys(i) for i, worker in enumerate(workers)]
        check_wallet_bindings(ledger.roster, ledger.wallet_bindings)
        return ledger

    def challenge(self, nonce):
        return self.challenges.setdefault(nonce, secrets.token_bytes(32))

    def check_live(self, job):
        require(job.network == NETWORK and job.assignment_policy == POLICY, "wrong local contract or policy")
        require(job.epoch == EPOCH and self.height <= job.expires, "expired or wrong registry epoch")
        require(self.challenges.get(job.nonce) == job.challenge and len(job.challenge) == 32,
                "unrecognized job challenge")
        require(job.suite == self.suite.name, "wrong enrolled suite")

    def reserve(self, job, a, candidate, signed_capture, authorization):
        self.check_live(job)
        check_capture(job, self.policy, signed_capture)
        verify(job.owner, digest("reserve/v1", job.j, a, candidate), authorization)
        key = job.capture_id, PROFILE
        existing = self.reservations.get(key)
        if existing:
            require(existing[:3] == (job.j, a, candidate), "capture/profile already reserved")
            return existing[3]
        target = self.height + 1
        self.reservations[key] = (job.j, a, candidate, target)
        return target

    def advance(self):
        self.height += 1
        proof = sign(self._beacon_key, digest("local-beacon-round/v1", NETWORK, EPOCH, self.height))
        self.beacon_proofs[self.height] = proof
        self.beacons[self.height] = sha(proof)

    def finalized(self, job):
        self.check_live(job)
        j, a, candidate, target = self.reservations[job.capture_id, PROFILE]
        require(j == job.j and target in self.beacons, "draw is not finalized for this job")
        require(beacon_value(self.beacon_key, target, self.beacon_proofs[target]) == self.beacons[target],
                "invalid local beacon value")
        return a, candidate, target, self.beacons[target]

    def register(self, job, digests, bitmaps, signature):
        a, candidate, target, beacon = self.finalized(job)
        check_certificate(job, a, candidate, target, beacon, self.roster, digests, bitmaps, signature, self.suite)
        cert_id = certificate_id(job, a, candidate, digests, bitmaps, signature)
        record = dict(certificate=cert_id, digests=tuple(digests), bitmaps=bitmaps, signature=signature)
        require(self.certificates.setdefault(job.j, record) == record, "certificate already finalized")
        return cert_id

    def report_conflict(self, job, index, group, first, second):
        """Record a simulated stake penalty against the historical operator ID."""
        j, a, candidate, target = self.reservations[job.capture_id, PROFILE]
        require(j == job.j and target in self.beacons, "unknown finalized assignment")
        committees = draw(job, a, candidate, target, self.beacons[target], self.roster)
        require(0 <= group < len(committees) and index in committees[group], "operator was not assigned")
        indices = groups(job.geometry.count)[group]
        messages = []
        for root, commitment_digest, group_digests, signature in (first, second):
            require(len(root) == len(commitment_digest) == 32, "invalid receipt digest")
            require(len(group_digests) == len(indices) and all(len(d) == 32 for d in group_digests),
                    "invalid group digest vector")
            msg = receipt_message(job, root, commitment_digest, group, indices, dict(zip(indices, group_digests)))
            self.suite.check(self.roster[index][0], msg, signature)
            messages.append(msg)
        require(messages[0] != messages[1], "identical receipt statements")
        self.slashed.add((job.epoch, index))


def channel_context(job, a, candidate, worker, channel, direction):
    return enc("IXH26/channel/v1", job.j, a, candidate, worker, job.owner, job.channel,
               channel, job.expires, direction)


class Worker:
    def __init__(self, suite):
        self._wallet = ECC.generate(curve="Ed25519")
        self._key, self.pk, self.pop = suite.enroll_key()
        self._channel = ECC.generate(curve="Curve25519")
        self.channel = public(self._channel)
        self.completed = set()

    @property
    def enrollment(self):
        return self.pk, self.channel, self.pop

    def authorize_keys(self, index):
        return public(self._wallet), sign(self._wallet, wallet_message(index, self.pk, self.channel))

    def enroll(self, suite, registrar, ctx, box):
        challenge = unseal(registrar, self._channel, ctx, box)
        return suite.sign(self._key, digest("enrollment-response/v1", ctx, challenge))

    def process(self, job, ledger, index, envelope):
        check_profile()
        a, candidate, target, beacon = ledger.finalized(job)
        require(ledger.roster[index] == self.enrollment and job.j not in self.completed,
                "wrong worker or replayed assignment")
        committees = draw(job, a, candidate, target, beacon, ledger.roster)
        expected = assigned(job, committees, index)
        require(expected, "operator has no assignment")
        ctx = channel_context(job, a, candidate, index, self.channel, b"assignment")
        packet = unpack(unseal(job.channel, self._channel, ctx, envelope))
        appraise(job, a, packet["evidence"], ledger.policy)
        require(commitment(job, a, packet["Q"]) == candidate, "wrong candidate root")
        require([item["i"] for item in packet["pieces"]] == expected, "incomplete or extra assignment")
        verified = {}
        for piece in packet["pieces"]:
            i, samples = piece["i"], piece["samples"]
            leaf = raw_leaf(job, i, piece["salt"], samples)
            check_path(leaf, i, job.geometry.count, piece["raw_path"], b"\x01", packet["evidence"]["root"])
            payload = render_interval(samples, job.geometry, i)
            d = interval_digest(job, a, i, piece["opening"], payload)
            check_path(sha(b"\x02" + d), i, job.geometry.count, piece["jpeg_path"], b"\x03", packet["Q"])
            verified[i] = d
        receipts = []
        for group, indices in enumerate(groups(job.geometry.count)):
            if index in committees[group]:
                msg = receipt_message(job, a, candidate, group, indices, verified)
                receipts.append((group, ledger.suite.sign(self._key, msg)))
        ctx = channel_context(job, a, candidate, index, self.channel, b"receipt")
        reply = seal(self._channel, job.channel, ctx, pack(receipts))
        self.completed.add(job.j)
        return reply
