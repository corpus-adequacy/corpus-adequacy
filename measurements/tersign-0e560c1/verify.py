#!/usr/bin/env python3
"""evidence-record-conformance verifier — stdlib-only, no dependencies, no network.

Usage:  python3 verify.py            # runs every vector in MANIFEST.json
Exit 0 only if: every vector produces its expected verdict AND the run observed both
verdicts (valid + reject) AND every reject reason code in the manifest was exercised.
A green run therefore demonstrates the verifier *discriminates*, not merely accepts.

Layer under test: the EVIDENCE RECORD — the layer whose properties must survive the
record being held by an interested party. Checks implemented, each with at least one
adversarial vector for its known failure class:

  digest_recompute      canonical form -> keccak256 content address
  canonical_bytes       claimed canonical bytes actually canonical (RFC 8785 key order,
                        incl. the integer-key ordering class that breaks naive impls,
                        and the supplementary-plane class where UTF-16 code-unit order
                        diverges from code-point order)
  chain_link            link digest binds artifact + prev + sequence number
  chain_set             per-seller continuity AND completeness (no silent omission),
                        incl. per-record link recomputation where links are presented
  anchor_relation       anchoredDigest = SHA-256(subjectDigest bytes) — the existence bound
  phase_claim           a record of one economic phase must not verify as a later phase
  independence_claim    a record attested only by parties to the transaction MUST NOT
                        count as an independent/neutral finding
  offer_binding         a receipt that does not commit to the accepted offer's canonical
                        digest MUST NOT be evaluated as proof that a specific offer's
                        terms were paid (the offer-substitution class)
  decision_evidence_binding
                        a protected record presented as evidence of an authority decision
                        must commit to the exact canonical decision-evidence object; an
                        unbound or substituted requested-to-effective reduction rejects
  boundary_binding      a boundary event that changes a stream's verification parameters
                        must bind the prefix it extends AND its own position in that
                        prefix's continuation — naming the prefix alone is satisfiable by
                        two conflicting continuations at once; and coverage claimed over
                        an empty attested prefix is a downgrade, not a pass

SCOPE BOUNDARY (stated, not implied): this stdlib core decides the STRUCTURAL predicate —
digests, canonical bytes, sequence closure, link arithmetic, declared-claim evaluation.
It does not recover counter-signatures. A structurally complete set whose head and links
were all recomputed by a single forging party passes the structural predicate; what
prevents that in production is that every link is counter-signed at transaction time by
a party outside the transaction and the head is anchored. Signature recovery over the
links (secp256k1 personal_sign; signer published at https://tersign.ai/v1/ledger) is the
crypto profile, deliberately outside this stdlib core — the digests, chain, completeness,
existence and criteria checks above require no cryptography beyond hashing.
"""

import hashlib
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from keccak import keccak256  # vendored; self-checked at import against measured KATs

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- canonical form (JCS)
def canonical(value):
    """RFC 8785 (JCS) serialization for the vector domain (I-JSON, integer numerics).

    Keys sort by UTF-16 code units (encode to UTF-16BE and compare bytes — identical
    ordering, done explicitly rather than trusting the host language's default sort).
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError("outside the I-JSON interoperable range (|n| > 2^53-1)")
        return str(value)
    if isinstance(value, float):
        raise ValueError("non-integer JSON number in the digest domain")
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonical(v) for k, v in items
        ) + "}"
    raise TypeError(f"non-JSON value in vector: {type(value)}")


def digest_of(value):
    return "0x" + keccak256(canonical(value).encode("utf-8")).hex()


GENESIS_PREV = "0x" + "00" * 32


def chain_link_digest(artifact_digest, prev_digest, seq):
    a = bytes.fromhex(artifact_digest[2:])
    p = bytes.fromhex((prev_digest or GENESIS_PREV)[2:])
    return "0x" + keccak256(a + p + seq.to_bytes(8, "big")).hex()


# -------------------------------------------------------- identifier normalization
# Identity comparison must not depend on incidental byte forms: EIP-55 mixed case is
# the same address, and " 0xabc… " with trailing whitespace is the same address — but a
# string this verifier cannot parse AS an address is not an address it can evaluate.
# Normalize (strip + lowercase), then validate; unparseable fails closed. Without this,
# a party could relabel itself as "outside the parties" by appending a space or an
# invisible format character to its own address — an alias bypass of the independence
# criterion, the exact fail-open class this suite exists to reject.
ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^0x[0-9a-f]{64}$")
# A second identity syntax, added 2026-08-19 — the independence criterion compares attestor
# identity, and a criterion bound to ONE identity syntax cannot decide records from schemes
# that name parties differently. Found against a foreign corpus (AXES Golden Trace v2 custody
# twins, axes#6): under `org:…` / `agent:…` identities the criterion rejected the accepting
# twin on the identifier alone. The grammar is deliberately strict so the aliasing defence
# (n13 whitespace, n14 unparseable, the zero-width-space vector) still holds: a lowercase
# alnum scheme, one colon, then printable non-space ASCII — no whitespace, no format chars,
# no format chars. Case and trailing punctuation are then FOLDED AWAY (see _norm_addr) so a
# party cannot alias itself outside the transaction with a case variant or a trailing slash.
URN_RE = re.compile(r"^[a-z][a-z0-9+.-]*:[\x21-\x7e]+$")


def _norm_addr(a):
    """A canonical party identifier, or None if not parseable as one.

    Two syntaxes: a 0x-address (lowercased — EIP-55 mixed case is the same address) or a
    scheme-qualified identifier. The URN branch normalises AGGRESSIVELY toward "same party":
    case-folded, and trailing `/` `.` `#` stripped. The verifier does not own any scheme's
    equivalence rules, so where two identifiers MIGHT denote one party it must treat them as
    one — a deployer writing `org:caldera-robotics/` is otherwise "outside the transaction"
    for free, which is n13's alias bypass one syntax over (found in the self-review that
    shipped p21/n30). The cost is that a genuinely distinct party whose identifier differs
    only by case or trailing punctuation is read as the same party and the claim rejects;
    for a disqualification that is the correct direction to be wrong in."""
    if not isinstance(a, str):
        return None
    a = a.strip()
    low = a.lower()
    if ADDR_RE.fullmatch(low):
        return low
    if URN_RE.fullmatch(a):
        return low.rstrip("/.#")
    return None


def _norm_digest(x):
    """Lowercased 0x-32-byte digest, or None if not parseable as one."""
    if not isinstance(x, str):
        return None
    x = x.strip().lower()
    return x if DIGEST_RE.fullmatch(x) else None


def _is_seq(x):
    """A sequence number is an int and not a bool (bool is an int subclass in Python)."""
    return isinstance(x, int) and not isinstance(x, bool)


# ------------------------------------------------------------------------ vector kinds
def check_digest_recompute(inp):
    try:
        got = digest_of(inp["payload"])
    except ValueError as exc:
        # The digest domain is I-JSON with integer numerics. A non-integer number, or an
        # integer beyond 2^53-1, produces digests other implementations cannot reproduce
        # (RFC 8785 §3.2.2.3 routes numbers through ECMAScript Number::toString over IEEE
        # 754 doubles) — refused rather than silently serialized.
        return "reject", "number_domain_reject", str(exc)
    expected = _norm_digest(inp.get("expected_digest"))
    if expected is None:
        return "reject", "recompute_mismatch", "expected digest is not a parseable 32-byte hex digest"
    if got != expected:
        return "reject", "recompute_mismatch", f"recomputed {got}"
    return "valid", None, got


def check_canonical_bytes(inp):
    # `payload_text` carries the payload as raw JSON text where the distinction under
    # test cannot survive a JSON load in every language (a JS JSON.parse collapses the
    # token 2.0 to the value 2, so a value-carrying vector cannot express an
    # integer-valued float). Key presence, not sentinel, per the cross-language guard
    # convention. Python's json preserves float-ness, so the existing domain guard in
    # canonical() is the enforcement; the TS engine enforces the same boundary at the
    # token level. Boundary: a number TOKEN with a fraction or exponent part is outside
    # the digest domain even when integer-valued.
    try:
        payload = json.loads(inp["payload_text"]) if "payload_text" in inp else inp["payload"]
        got = canonical(payload)
    except ValueError as exc:
        return "reject", "number_domain_reject", str(exc)
    if got != inp["claimed_canonical"]:
        return "reject", "canonicalization_reject", f"canonical form is {got!r}"
    return "valid", None, "canonical bytes confirmed"


def check_chain_link(inp):
    artifact = _norm_digest(inp.get("artifact_digest"))
    if artifact is None:
        return "reject", "continuity_reject", "unparseable artifact digest"
    prev_raw = inp.get("prev_digest")
    if prev_raw is None:
        prev = None
    else:
        prev = _norm_digest(prev_raw)
        if prev is None:
            return "reject", "continuity_reject", "unparseable prev digest"
    if not _is_seq(inp.get("seq")) or inp["seq"] < 1:
        return "reject", "continuity_reject", "sequence number is not a positive integer"
    expected = _norm_digest(inp.get("expected_link"))
    if expected is None:
        return "reject", "continuity_reject", "unparseable expected link digest"
    got = chain_link_digest(artifact, prev, inp["seq"])
    if got != expected:
        return "reject", "continuity_reject", f"recomputed link {got}"
    return "valid", None, got


GENESIS_PREV_FORMS = {None, GENESIS_PREV}

# Claim strings that assert nothing about independence. A record is free to stay
# silent; what it may not do is assert something this verifier cannot evaluate and
# have that pass (see check_independence_claim).
NO_CLAIM = frozenset({"", "none", "issuer_attested"})

# Economic phases this verifier understands. A phase token outside this vocabulary is
# not interpretable — and an uninterpretable phase must not verify as ANY phase, for
# the same reason an uninterpretable independence claim must not pass: the check would
# switch off exactly where the record asserts something new.
PHASES = ("funding", "delivery", "settlement", "refund", "reversal")

# Suite-profile bound on head.seq: completeness is checked by materializing the
# committed range, so an absurd head is refused rather than allowed to exhaust memory.
MAX_HEAD_SEQ = 100_000


def _norm_prev(p):
    """Wire form of a genesis predecessor is null; the 32-zero-byte digest is the
    hashing-time substitution (see chain_link_digest) and normalizes to the same thing.
    Returns None (genesis), a normalized digest, or the sentinel "invalid"."""
    if p is None:
        return None
    d = _norm_digest(p)
    if d is None:
        return "invalid"
    return None if d == GENESIS_PREV else d


def check_chain_set(inp):
    head = inp.get("head")
    if not isinstance(head, dict):
        return "reject", "completeness_reject", "head is not an object"
    if not _is_seq(head.get("seq")) or head["seq"] < 1:
        return "reject", "completeness_reject", "head commits no records (seq < 1 or not an integer)"
    if head["seq"] > MAX_HEAD_SEQ:
        return "reject", "completeness_reject", f"head.seq exceeds the suite profile bound ({MAX_HEAD_SEQ})"
    head_digest = _norm_digest(head.get("digest"))
    if head_digest is None:
        return "reject", "completeness_reject", "head digest is not a parseable 32-byte hex digest"

    raw_records = inp.get("records")
    if not isinstance(raw_records, list):
        return "reject", "completeness_reject", "records is not an array"
    records = []
    for r in raw_records:
        if not isinstance(r, dict) or not _is_seq(r.get("seq")):
            return "reject", "completeness_reject", "record entry is not an object with an integer seq"
        records.append(r)
    records.sort(key=lambda r: r["seq"])

    seqs = [r["seq"] for r in records]
    counts = Counter(seqs)
    expected = list(range(1, head["seq"] + 1))
    if seqs != expected:
        missing = sorted(set(expected) - set(seqs))
        dupes = sorted(s for s, c in counts.items() if c > 1)
        extra = sorted(set(seqs) - set(expected))
        parts = [f"missing seq {missing}"] if missing else []
        parts += [f"duplicate seq {dupes}"] if dupes else []
        parts += [f"out-of-range seq {extra}"] if extra else []
        return "reject", "completeness_reject", " + ".join(parts) + " under committed head"

    prev = None
    for r in records:
        artifact = _norm_digest(r.get("artifact_digest"))
        if artifact is None:
            return "reject", "continuity_reject", f"unparseable artifact digest at seq {r['seq']}"
        r_prev = _norm_prev(r.get("prev_digest"))
        if r_prev == "invalid":
            return "reject", "continuity_reject", f"unparseable prev digest at seq {r['seq']}"
        if r_prev != prev:
            return "reject", "continuity_reject", f"prev mismatch at seq {r['seq']}"
        if "link" in r:
            # Per-record links, where presented, must be the chain-link arithmetic over
            # this record's own artifact, predecessor, and sequence number. This is what
            # catches renumbering: a record relabeled to hide an omission carries a link
            # computed for its ORIGINAL position, and the recomputation diverges. (In
            # production each link is counter-signed at transaction time, so a forger
            # cannot simply recompute them — see the scope boundary in the module doc.)
            claimed_link = _norm_digest(r["link"])
            if claimed_link is None:
                return "reject", "continuity_reject", f"unparseable link digest at seq {r['seq']}"
            if chain_link_digest(artifact, prev, r["seq"]) != claimed_link:
                return "reject", "continuity_reject", f"link mismatch at seq {r['seq']}"
        prev = artifact
    if prev != head_digest:
        return "reject", "continuity_reject", "head digest does not match final record"
    return "valid", None, f"complete 1..{head['seq']} under head (structural predicate; counter-signature profile out of stdlib scope)"


def check_anchor_relation(inp):
    subject = _norm_digest(inp.get("subject_digest"))
    if subject is None:
        return "reject", "existence_reject", "unparseable subject digest"
    anchored = _norm_digest(inp.get("anchored_digest"))
    if anchored is None:
        return "reject", "existence_reject", "unparseable anchored digest"
    got = "0x" + hashlib.sha256(bytes.fromhex(subject[2:])).hexdigest()
    if got != anchored:
        return "reject", "existence_reject", f"sha256(subject) = {got}"
    return "valid", None, "anchored digest binds subject"


def check_phase_claim(inp):
    record = inp.get("record")
    if not isinstance(record, dict) or "economic_phase" not in record:
        return "reject", "phase_reject", "record carries no economic_phase"
    phase = record["economic_phase"]
    presented = inp.get("presented_as")
    if phase not in PHASES:
        return "reject", "phase_reject", f"unrecognized economic phase {phase!r}: not interpretable by this verifier"
    if presented not in PHASES:
        return "reject", "phase_reject", f"unrecognized presented phase {presented!r}: not interpretable by this verifier"
    if phase != presented:
        return "reject", "phase_reject", f"{phase} record presented as {presented} evidence"
    return "valid", None, f"phase {phase} consistent"


_MISSING = object()


def _check_object_binding(
    carrier,
    digest_field,
    presented,
    label,
    *,
    carrier_label="carrier",
    object_required=False,
    missing_detail=None,
    missing_presented_detail=None,
    valid_detail=None,
):
    """Shared binding arithmetic without conflating the bound objects' semantics."""
    if not isinstance(carrier, dict):
        return "reject", "binding_reject", f"{carrier_label} is not an object"
    if object_required and not isinstance(presented, dict):
        return "reject", "binding_reject", f"presented {label} is not an object"
    committed = _norm_digest(carrier.get(digest_field))
    if committed is None:
        detail = missing_detail or f"{carrier_label} commits to no parseable {label} digest"
        return "reject", "binding_reject", detail
    if presented is _MISSING:
        return "reject", "binding_reject", missing_presented_detail or f"{label} is missing"
    try:
        got = digest_of(presented)
    except (ValueError, TypeError, KeyError) as exc:
        return "reject", "binding_reject", f"{label} not canonicalizable: {exc}"
    if got != committed:
        return "reject", "binding_reject", f"presented {label} digests to {got}, {carrier_label} commits to {committed}"
    return "valid", None, valid_detail or f"{carrier_label} binds the presented {label}"


def check_offer_binding(inp):
    """A receipt proves the terms it COMMITS to. A receipt that carries no digest of the
    accepted offer cannot bind amount/asset/payTo/scheme, so two offers sharing
    resourceUrl/network/payer become interchangeable behind a valid signature — the
    substitution class reported upstream (x402-foundation/x402#3006). The check is the
    binding arithmetic: the presented offer's canonical digest must equal the digest the
    receipt commits to; changing ANY term changes the canonical bytes, hence the digest."""
    return _check_object_binding(
        inp.get("receipt"),
        "offerDigest",
        inp["offer"] if "offer" in inp else _MISSING,
        "offer",
        carrier_label="receipt",
        missing_detail="receipt commits to no parseable offer digest — terms are unbound",
        missing_presented_detail="offer not canonicalizable: 'offer'",
        valid_detail="receipt binds the presented offer's exact terms",
    )


def check_decision_evidence_binding(inp):
    """Bind the exact authority-decision evidence object to the protected record.

    This criterion deliberately decides only structural distinguishability. It does not
    validate the authority intersection, authenticate the producer, establish historical
    position, or prescribe where a future protocol stores the commitment.
    """
    return _check_object_binding(
        inp.get("record"),
        "decisionEvidenceDigest",
        inp.get("decision_evidence"),
        "decision-evidence object",
        carrier_label="record",
        object_required=True,
    )


def check_boundary_binding(inp):
    """A record stream may change its own verification parameters — which witness, which
    signature suite, which canonical form — and it does so with a BOUNDARY EVENT inside the
    stream rather than by rewriting the records that predate the change. The question this
    criterion settles is what such an event must bind for a verifier holding only the stream
    to be able to check it.

    Naming the prefix it extends is NOT sufficient. Two conflicting continuations of the same
    prefix can both name that prefix truthfully, so a verifier accepts either and cannot tell
    which the deployment committed to — demonstrated against a live implementation and
    reproduced four independent ways in modelcontextprotocol/modelcontextprotocol#3004
    (2026-08-08/09). A boundary event must therefore bind BOTH the digest of the prefix it
    extends AND its own position in that prefix's continuation.

    The second failure this pins is the downgrade: a verifier that cannot find the attestation
    falls back to a weaker path — digest and link arithmetic alone — and reports success while
    its own report says the attested prefix was empty. An offline snapshot is then
    indistinguishable from a verified stream. Coverage that is claimed must be coverage that
    was checked, so a claim of coverage over an empty attested prefix rejects.

    Stated at the record layer, deliberately: the shape is a stream of records, a boundary
    event, and a claimed covered prefix. Nothing here depends on a particular file format,
    witness kind, or signature suite."""
    event = inp.get("boundary_event")
    if not isinstance(event, dict):
        return "reject", "boundary_reject", "boundary event is not an object"

    prefix = inp.get("prefix")
    if not isinstance(prefix, list) or not prefix:
        return "reject", "boundary_reject", "the prefix a boundary event extends is not an evaluable sequence"

    # (a) Does it bind the prefix it extends, and truthfully?
    claimed_prefix = _norm_digest(event.get("prefixDigest"))
    if claimed_prefix is None:
        return "reject", "boundary_reject", "boundary event binds no parseable digest of the prefix it extends"
    try:
        actual_prefix = digest_of(prefix)
    except (ValueError, TypeError) as exc:
        return "reject", "boundary_reject", f"prefix not canonicalizable: {exc}"
    if claimed_prefix != actual_prefix:
        return "reject", "boundary_reject", f"boundary event names prefix {claimed_prefix}, presented prefix digests to {actual_prefix}"

    # (b) Does it bind its OWN position in that prefix's continuation? A truthful (a) with no
    # (b) is the fabricated-boundary case: an event appended later, claiming an earlier
    # effective point, is indistinguishable from one that was always there.
    position = event.get("position")
    if not isinstance(position, int) or isinstance(position, bool):
        return "reject", "boundary_reject", "boundary event binds the prefix it extends but not its own position in the continuation — a later append claiming an earlier point is indistinguishable from an original"
    if position != len(prefix):
        return "reject", "boundary_reject", f"boundary event claims position {position}, the presented prefix ends at {len(prefix)}"

    # The downgrade: coverage claimed over an empty attested prefix. A verifier that reports
    # success here has checked nothing and said so in the same breath.
    covered = inp.get("covered_through")
    if covered is not None:
        if not isinstance(covered, int) or isinstance(covered, bool) or covered < 0:
            return "reject", "boundary_reject", "claimed coverage is not an evaluable position"
        attested = event.get("attestedPrefixLength")
        if not isinstance(attested, int) or isinstance(attested, bool):
            return "reject", "boundary_reject", "coverage is claimed but the attested prefix length is not stated — unattested is not a pass"
        if attested <= 0 < covered:
            return "reject", "boundary_reject", f"coverage claimed through {covered} while the attested prefix is empty — an offline snapshot is indistinguishable from a verified stream"
        if covered > attested:
            return "reject", "boundary_reject", f"coverage claimed through {covered}, attestation reaches only {attested}"

    return "valid", None, f"boundary event binds prefix {actual_prefix[:12]}… at position {position}"


def derive_settlement_commits(result):
    """What a settlement result actually commits to, read off the result rather than declared.

    Returns the fact classes an evaluator may let an independence claim reach. `settlement` is
    committed only when the result both claims success AND carries a transaction reference that
    resolves to something: an empty `transaction` is the spec's own encoding of a failed
    settlement, so a record carrying it commits to no settlement at all.
    """
    commits = []
    if not isinstance(result, dict):
        return commits
    tx = result.get("transaction")
    if result.get("success") is True and isinstance(tx, str) and tx.strip() != "":
        commits.append("settlement")
    if isinstance(result.get("network"), str) and result["network"].strip() != "":
        commits.append("network")
    return commits


def derive_delivery_commits(inp):
    """What a record's delivery fields commit to, read off the record rather than declared.

    None when the record presents no delivery commitment to evaluate — neither key present,
    tested by key PRESENCE so both engines read an explicit null the same way (the
    `record_commits` lesson, n23). Otherwise a list: `["delivery"]` when the deliverable
    digest the record carries recomputes from the deliverable bytes it presents,
    keccak256(utf8(bytes)) == digest, and `[]` when it does not. A digest carried beside
    bytes that do not hash to it is the delivery-side twin of `transaction: ""`: a
    well-formed field committing to nothing a reader can check — evaluated, and empty.

    WHO delivered is deliberately not read here. `deliverable_signer` names a position, and
    position is the INDEPENDENCE axis, decided upstream by the parties/attestations count
    (the position/faculty distinction, p17/n21). Folding the signer in would let one axis do
    the other's work and the reject would name the wrong defect. Enumerated by @0rkz against
    issue #3; p22/n32 anticipated this derivation and must not move under it; p23/n33 drive it.
    """
    if "deliverable_bytes" not in inp and "deliverable_digest" not in inp:
        return None
    presented = inp.get("deliverable_bytes")
    declared = _norm_digest(inp.get("deliverable_digest"))
    if not isinstance(presented, str) or declared is None:
        return []
    try:
        # A lone surrogate is valid JSON text with no UTF-8 form: Python raises here, a JS
        # TextEncoder substitutes U+FFFD and hashes on — two engines, two verdicts. Both
        # now read it as bytes that cannot be the digested bytes: presented, and empty.
        encoded = presented.encode("utf-8")
    except UnicodeEncodeError:
        return []
    if "0x" + keccak256(encoded).hex() == declared:
        return ["delivery"]
    return []


def derive_record_commits(inp):
    """Every fact class the record commits to, composed from the per-fact derivations.

    Settlement and network come off the settlement result; delivery comes off the presented
    bytes. None when the record presents nothing derivable at all — distinct from an empty
    list, which is a record that presented commitments and was found to commit to nothing.
    """
    parts = []
    if isinstance(inp.get("settlement_result"), dict):
        parts.append(derive_settlement_commits(inp["settlement_result"]))
    delivery = derive_delivery_commits(inp)
    if delivery is not None:
        parts.append(delivery)
    if not parts:
        return None
    return [c for part in parts for c in part]


def check_independence_claim(inp):
    claimed = inp.get("claimed")
    if claimed is None:
        return "valid", None, "no independence claimed"
    # Membership must not depend on the value being hashable: a list or dict claim
    # raised TypeError here, which produces no verdict at all — the criterion did not
    # fail closed, it threw. An array is also the shape a CLAIM SET lands on, i.e. the
    # one shape we said this field should move toward. Reported by @Rul1an (issue #1).
    if isinstance(claimed, str):
        if claimed in NO_CLAIM:
            return "valid", None, "no independence claimed"
        if claimed == "independent":
            claimed_set = {claimed}
        else:
            claimed_set = None
    elif isinstance(claimed, list) and all(isinstance(c, str) for c in claimed):
        claimed_set = {c for c in claimed if c not in NO_CLAIM}
        if not claimed_set:
            return "valid", None, "no independence claimed"
        if claimed_set - {"independent"}:
            claimed_set = None
    else:
        claimed_set = None
    if claimed_set is None:
        # Fail closed on a claim this verifier cannot interpret — including a STRONGER
        # one. An exact-equality trigger silently returned "valid" for any other value,
        # turning the check off precisely where more was asserted. Silence is a valid
        # state; an unintelligible assertion is not.
        return "reject", "independence_reject", f"unrecognized claim {claimed!r}: not interpretable by this verifier"

    # From here the record CLAIMS independence, so the claim must be evaluable: the
    # parties and attestations must exist, have evaluable shapes, and carry parseable
    # identities. Failing closed also means returning a verdict for every shape — a
    # missing key or a non-object attestation is a reject, not an exception.
    raw_parties = inp.get("parties")
    if not isinstance(raw_parties, list) or not raw_parties:
        return "reject", "independence_reject", "independence claimed but parties are not evaluable"
    parties = set()
    for p in raw_parties:
        norm = _norm_addr(p)
        if norm is None:
            return "reject", "independence_reject", f"unparseable party identifier {p!r}"
        parties.add(norm)
    raw_attestations = inp.get("attestations")
    if not isinstance(raw_attestations, list) or not raw_attestations:
        return "reject", "independence_reject", "independence claimed with no evaluable attestations"
    outside = 0
    for a in raw_attestations:
        if not isinstance(a, dict) or "by" not in a:
            return "reject", "independence_reject", "attestation is not an object naming its attestor"
        by = _norm_addr(a["by"])
        if by is None:
            return "reject", "independence_reject", f"unparseable attestor identifier {a['by']!r}"
        if by not in parties:
            outside += 1
    if not outside:
        return "reject", "independence_reject", "attested only by parties to the transaction"

    # DERIVED, never declared — and the declared field's PRESENCE is itself the reject,
    # scope assertion or no. A declared commitment list lets a record assert the very scope
    # the commitment-scope rule exists to bound; leaving the declared path in as a fallback
    # made the derivation decorative (a record carrying both fields was scored on the
    # declaration — the override attack). An explicit null is a declaration too: one that
    # evaluates to nothing, which is the same shape as an unrecognized claim string, and it
    # fails closed for the same reason. The guard is KEY PRESENCE, not a value sentinel —
    # `is None` here and `=== undefined` in the TS cross-check read an explicit JSON null
    # differently, and the two engines forked on exactly that input. `in` has identical
    # semantics in both languages, which makes the fork unrepresentable rather than merely
    # untested. Both reported against this suite by @Rul1an (issue #4, second report).
    if "record_commits" in inp:
        return "reject", "independence_reject", "commitment scope must be derived from the record, not declared alongside it"

    # Commitment scope: an independence claim MUST NOT be read as covering any fact the
    # record does not itself commit to. A record whose committed content is a settlement
    # digest carries, at most, independent evidence OF THAT SETTLEMENT — nothing its
    # attestation did not cover, however independent the attestor. Absent a scope
    # assertion, the claim reads as scoped to the committed facts and nothing more.
    covers = inp.get("covers")
    if covers is not None:
        if isinstance(covers, str):
            covers = [covers]
        if not isinstance(covers, list) or not covers or not all(isinstance(c, str) for c in covers):
            return "reject", "independence_reject", "scope assertion is not evaluable"
        # x402 v2 §5.3.2 defines the empty string as what `transaction` carries when
        # settlement failed, and the type only requires a string — so `success: true`
        # with `transaction: ""` is well formed and commits to no settlement anyone can
        # resolve. Deriving the commitments off the record is what makes the
        # commitment-scope rule bite without resolving anything on-chain, and it is why
        # `delivery` is now a scope a record can actually reach: before this, no record
        # could commit to it, so n20 rejected for a structural reason that happened to be
        # correct for the wrong cause (@0rkz, issue #3).
        committed = derive_record_commits(inp)
        if not isinstance(committed, list) or not all(isinstance(c, str) for c in committed):
            return "reject", "independence_reject", "independence claimed over a scope, but the record's commitments are not evaluable"
        uncovered = sorted(set(covers) - set(committed))
        if uncovered:
            return "reject", "independence_reject", f"claim covers {uncovered} — fact(s) the record does not commit to"
    return "valid", None, f"{outside} non-party attestation(s)"


CHECKS = {
    "digest_recompute": check_digest_recompute,
    "canonical_bytes": check_canonical_bytes,
    "chain_link": check_chain_link,
    "chain_set": check_chain_set,
    "anchor_relation": check_anchor_relation,
    "phase_claim": check_phase_claim,
    "independence_claim": check_independence_claim,
    "offer_binding": check_offer_binding,
    "decision_evidence_binding": check_decision_evidence_binding,
    "boundary_binding": check_boundary_binding,
}


# ------------------------------------------------------------------------------ runner
# The reason-code closure is PINNED IN CODE, not derived from the manifest — a fork that
# quietly drops a reject class from MANIFEST.json must go red, not stay green.
REQUIRED_REASONS = frozenset({
    "recompute_mismatch", "canonicalization_reject", "continuity_reject",
    "completeness_reject", "existence_reject", "phase_reject", "independence_reject",
    "number_domain_reject", "binding_reject", "boundary_reject",
})


def _load_strict(path):
    """json load that REJECTS duplicate object names (RFC 7493 / RFC 8785 precondition)."""
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            dupes = sorted({k for k in keys if keys.count(k) > 1})
            raise ValueError(f"duplicate object name(s) {dupes} — not valid I-JSON")
        return dict(pairs)
    with open(path, encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=hook)


def main():
    manifest = _load_strict(os.path.join(HERE, "MANIFEST.json"))

    failures, verdicts_seen, reasons_seen, kinds_seen = [], set(), set(), set()
    # Per-kind verdict sets. The README's second design rule — every criterion is two-sided,
    # so an unconditional rejector fails as hard as an unconditional accepter — was stated as
    # run-enforced and was not: the gate below checked {valid, reject} over the WHOLE run, so a
    # criterion whose accepting vectors all disappeared stayed green as long as some other
    # criterion contributed a valid somewhere. Reported by @Rul1an (issue #1, 2026-08-12).
    # The case that made it concrete: d50545a (identity aliasing fail-closed) silently moved
    # the independence criterion from deciding to not-deciding under URN identities — every
    # URN input rejected on the identifier, so the criterion could no longer return valid for
    # that syntax — and nothing in the run said so. A per-kind gate catches that at the commit.
    verdicts_by_kind = {}
    expected_reasons = {v["reason"] for v in manifest["vectors"]
                        if v.get("expect") == "reject" and "reason" in v}

    for entry in manifest["vectors"]:
        try:
            vector = _load_strict(os.path.join(HERE, "vectors", entry["file"]))
            if vector["kind"] != entry["kind"]:
                raise ValueError(f"kind mismatch: manifest says {entry['kind']}, vector says {vector['kind']}")
            verdict, reason, detail = CHECKS[vector["kind"]](vector["input"])
        except Exception as exc:  # a malformed vector is a controlled failure, not a crash
            verdict, reason, detail = "malformed", None, f"{type(exc).__name__}: {exc}"
        verdicts_seen.add(verdict)
        kinds_seen.add(entry["kind"])
        verdicts_by_kind.setdefault(entry["kind"], set()).add(verdict)
        if reason:
            reasons_seen.add(reason)
        ok = verdict == entry["expect"] and (verdict == "valid" or reason == entry.get("reason"))
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {entry['file']:44s} -> {verdict}{'/' + reason if reason else ''}  ({detail})")
        if not ok:
            failures.append(entry["file"])

    print()
    if failures:
        print(f"NON-CONFORMANT: {len(failures)} vector(s) produced the wrong verdict: {failures}")
        return 1
    if verdicts_seen != {"valid", "reject"}:
        print(f"NON-CONFORMANT: run must observe BOTH verdicts; saw {sorted(verdicts_seen)}")
        return 1
    if expected_reasons != REQUIRED_REASONS or reasons_seen != REQUIRED_REASONS:
        print(f"NON-CONFORMANT: reject-reason closure is pinned to {sorted(REQUIRED_REASONS)}; "
              f"manifest covers {sorted(expected_reasons)}, run exercised {sorted(reasons_seen)}")
        return 1
    if kinds_seen != set(CHECKS):
        print(f"NON-CONFORMANT: every vector kind must be exercised; missing {sorted(set(CHECKS) - kinds_seen)}")
        return 1
    one_sided = sorted(k for k, vs in verdicts_by_kind.items() if vs != {"valid", "reject"})
    if one_sided:
        detail = ", ".join(f"{k} saw only {sorted(verdicts_by_kind[k])}" for k in one_sided)
        print(f"NON-CONFORMANT: every criterion must be two-sided IN THIS RUN — an unconditional "
              f"rejector fails as hard as an unconditional accepter; {detail}")
        return 1
    print(f"CONFORMANT: {len(manifest['vectors'])} vectors, both verdicts observed per kind, "
          f"all {len(REQUIRED_REASONS)} reject reasons and all {len(CHECKS)} kinds exercised.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
