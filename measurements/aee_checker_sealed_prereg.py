#!/usr/bin/env python3
"""Enumerate explicit-if sites in pinned check_sealed. Stdlib only.

Selects the unique `fn check_sealed(...) -> R<(Vec<&'static str>, String)>`
by source structure and emits every explicit `if` condition inside it.
Does not run the checker, cargo, or any mutant.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

UNPROVED_EXIT_CODES = [75]
ACCEPTED_EXIT_CODES = [0]
OUTCOME_FROM = ["rows"]
DIAGNOSTIC_FROM = ["diagnostics"]
PINNED_BUILD = ["cargo", "build", "--locked", "--release"]
PINNED_IMPLEMENTATION_SOURCES = ["src/check.rs", "aee_checker_sealed.py"]
SELECTED_COUNT = 7
# Live #211: every explicit if. if-let is in the complement, not the denominator.
# check_sealed has no if-let, so selected stays 7. Do not amend the issue.
# syn ExprIf outside=124 plus the format! token-if at check.rs:647 = 125.
IF_LET_IN_COMPLEMENT = True
GROUP = "sealed"
CONTROL_ANCHOR = (
    "fn check_sealed(payload: &Value, ctx: &Ctx) -> R<(Vec<&'static str>, String)> {"
)
CONTROL_REPLACEMENT = (
    CONTROL_ANCHOR + "\n    return Err(Fail(\"CONTROL: immediate refusal\".into()));"
)
RET_RE = re.compile(
    r"->\s*R<\s*\(\s*Vec\s*<\s*&'static\s+str\s*>\s*,\s*String\s*\)\s*>"
)
FN_RE = re.compile(r"fn\s+(check_\w+)")


class PreregError(Exception):
    """The frozen preregistration is incomplete or inconsistent."""


def encode_json(doc) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def code_mask(src: str) -> str:
    """Same length as src. Non-code becomes space; newlines are kept."""
    out = []
    i, n = 0, len(src)
    state = "code"
    raw_hash = 0
    block_depth = 0
    while i < n:
        c, nxt = src[i], src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                block_depth = 1
                out.append("  ")
                i += 2
                continue
            if c in "br" and nxt in "\"'":
                out.append(" ")
                i += 1
                continue
            if c == "r":
                j = i + 1
                hashes = 0
                while j < n and src[j] == "#":
                    hashes += 1
                    j += 1
                if j < n and src[j] == '"':
                    out.append(" " * (j - i + 1))
                    i = j + 1
                    state = "raw"
                    raw_hash = hashes
                    continue
            if c == '"':
                state = "string"
                out.append(" ")
                i += 1
                continue
            if c == "'":
                # `'e'` is a char literal. `'static` / `'a` are lifetimes.
                closed_char = bool(nxt) and i + 2 < n and src[i + 2] == "'" and nxt != "\\"
                if nxt == "\\" or closed_char:
                    state = "char"
                    out.append(" ")
                    i += 1
                    continue
                if nxt == "_" or nxt.isalpha():
                    out.append(c)
                    i += 1
                    continue
                state = "char"
                out.append(" ")
                i += 1
                continue
            out.append(c)
            i += 1
            continue
        if state == "line":
            if c == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if state == "block":
            if c == "/" and nxt == "*":
                out.append("  ")
                i += 2
                block_depth += 1
                continue
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                block_depth -= 1
                if block_depth == 0:
                    state = "code"
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if state in ("string", "char"):
            end = '"' if state == "string" else "'"
            if c == "\\":
                out.append("  " if nxt else " ")
                i += 2 if nxt else 1
                continue
            if c == end:
                out.append(" ")
                i += 1
                state = "code"
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if state == "raw":
            if c == '"' and src[i + 1:i + 1 + raw_hash] == "#" * raw_hash:
                out.append(" " * (1 + raw_hash))
                i += 1 + raw_hash
                state = "code"
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
    return "".join(out)


def _brace_end(masked: str, brace: int) -> int:
    depth = 0
    for j in range(brace, len(masked)):
        if masked[j] == "{":
            depth += 1
        elif masked[j] == "}":
            depth -= 1
            if depth == 0:
                return j + 1
    raise PreregError("unbalanced function body")


def _explicit_ifs(text: str, masked: str, lo: int, hi: int) -> list[dict]:
    sites = []
    i = lo
    while True:
        m = re.search(r"\bif\b", masked[i:hi])
        if not m:
            break
        pos = i + m.start()
        i = pos + 2
        k = pos + 2
        while k < hi and masked[k] in " \t":
            k += 1
        cond_start, depth = k, 0
        cond_end = None
        while k < hi:
            ch = masked[k]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "{" and depth == 0:
                cond_end = k
                break
            k += 1
        if cond_end is None:
            continue
        raw_cond = text[cond_start:cond_end]
        cond = raw_cond.strip()
        if "=>" in cond:
            continue
        lead = len(raw_cond) - len(raw_cond.lstrip())
        trail = len(raw_cond) - len(raw_cond.rstrip())
        start, end = cond_start + lead, cond_end - trail
        sites.append({
            "condition": cond,
            "bytes": text[start:end],
            "span": {
                "start": start,
                "end": end,
                "line": text[:start].count("\n") + 1,
                "column": start - text.rfind("\n", 0, start),
            },
            "sha256": _sha256(text[start:end].encode("utf-8")),
            "replacement": "false",
        })
    return sites


def _unique_window(source: str, cond_start: int, cond_end: int) -> tuple[str, str]:
    if_pos = source.rfind("if", 0, cond_start + 1)
    grow = cond_end
    while grow <= len(source):
        anchor = source[if_pos:grow]
        if source.count(anchor) == 1:
            replacement = source[if_pos:cond_start] + "false" + source[cond_end:grow]
            return anchor, replacement
        grow += 1
    raise PreregError("cannot pin a unique anchor")


def enumerate_source(source: bytes) -> dict:
    text = source.decode("utf-8")
    masked = code_mask(text)
    chosen = []
    for m in FN_RE.finditer(masked):
        brace = masked.find("{", m.start())
        if brace < 0 or not RET_RE.search(text[m.start():brace]):
            continue
        chosen.append((m.group(1), m.start(), brace))
    if len(chosen) != 1 or chosen[0][0] != "check_sealed":
        raise PreregError(
            "source structure must select exactly one check_sealed returning "
            "R<(Vec<&'static str>, String)>, got %r" % [c[0] for c in chosen])
    name, start, brace = chosen[0]
    end = _brace_end(masked, brace)
    func = text[start:end]
    sites = _explicit_ifs(text, masked, start, end)
    if len(sites) != SELECTED_COUNT:
        raise PreregError("expected %d explicit ifs in check_sealed, got %d"
                          % (SELECTED_COUNT, len(sites)))
    outside = _explicit_ifs(text, masked, 0, start) + _explicit_ifs(text, masked, end, len(text))
    for idx, site in enumerate(sites, 1):
        site["id"] = "sealed-%d" % idx
        site["label"] = "remove check_sealed guard: %s" % site["condition"]
        site["anchor"], site["manifest_replacement"] = _unique_window(
            text, site["span"]["start"], site["span"]["end"])
        if text.count(site["anchor"]) != 1:
            raise PreregError("site %s is not uniquely pinable" % site["id"])
    return {
        "function": {
            "name": name,
            "start": start,
            "end": end,
            "sha256": _sha256(func.encode("utf-8")),
        },
        "source_sha256": _sha256(source),
        "sites": sites,
        "complement": [{
            "condition": s["condition"],
            "span": s["span"],
            "line": s["span"]["line"],
        } for s in outside],
    }


def _control() -> dict:
    return {
        "control": True,
        "label": "CONTROL immediate check_sealed refusal",
        "anchor": CONTROL_ANCHOR,
        "replacement": CONTROL_REPLACEMENT,
        "scope": "declared",
    }


def _manifest(found: dict) -> dict:
    mutants = []
    for site in found["sites"]:
        mutants.append({
            "label": site["label"],
            "anchor": site["anchor"],
            "replacement": site["manifest_replacement"],
            "scope": "declared",
        })
    mutants.append(_control())
    return {
        "schema": "corpus-adequacy.manifest.v0",
        "runner": "batch",
        "repo_root": ".",
        "implementation": "src/check.rs",
        "implementation_sources": list(PINNED_IMPLEMENTATION_SOURCES),
        "build": list(PINNED_BUILD),
        "entrypoint_command": [
            "python3", "aee_checker_sealed.py",
            "--checker", "./target/release/aee-checker",
            "corpus/vectors",
        ],
        "outcome_from": list(OUTCOME_FROM),
        "diagnostic_from": list(DIAGNOSTIC_FROM),
        "accepted_exit_codes": list(ACCEPTED_EXIT_CODES),
        "unproved_exit_codes": list(UNPROVED_EXIT_CODES),
        "vectors": "corpus/vectors/MANIFEST.json",
        "id_key": "vector_id",
        "default_group": GROUP,
        "vector_timeout": 600,
        "mutants": {GROUP: mutants},
    }


def _sites_doc(found: dict) -> dict:
    return {
        "selected_count": len(found["sites"]),
        "complement_count": len(found["complement"]),
        "complement_note": (
            "Every explicit if outside check_sealed, including if-let, "
            "is descriptive only and is not in the denominator."
        ),
        "function": found["function"],
        "source_sha256": found["source_sha256"],
        "sites": found["sites"],
        "complement": found["complement"],
    }


def emit_prereg(source: bytes, dest: Path, pins: dict | None = None) -> None:
    found = enumerate_source(source)
    dest.mkdir(parents=True, exist_ok=True)
    if pins is None:
        pins = {"source_sha256": _sha256(source)}
        if len(source) <= 32000:
            pins["source_utf8"] = source.decode("utf-8")
    (dest / "sites.json").write_bytes(encode_json(_sites_doc(found)))
    (dest / "manifest.json").write_bytes(encode_json(_manifest(found)))
    (dest / "control.json").write_bytes(encode_json(_control()))
    (dest / "pins.json").write_bytes(encode_json(pins))


def validate_prereg(dest: Path) -> None:
    sites = json.loads((dest / "sites.json").read_text(encoding="utf-8"))
    manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    control = json.loads((dest / "control.json").read_text(encoding="utf-8"))
    pins = json.loads((dest / "pins.json").read_text(encoding="utf-8"))
    selected = sites.get("sites") or []
    mutants = manifest.get("mutants", {}).get(GROUP, [])
    ordinary = [e for e in mutants if not e.get("control")]
    controls = [e for e in mutants if e.get("control")]
    selected_anchors = {s["anchor"] for s in selected}
    complement_needles = [c["condition"] for c in (sites.get("complement") or [])]
    for mut in ordinary:
        if mut.get("anchor") in selected_anchors:
            continue
        if any(needle and needle in mut.get("anchor", "") for needle in complement_needles):
            raise PreregError("complement site was added to the denominator")
    if len(selected) != SELECTED_COUNT:
        raise PreregError("completeness: selected sites != %d" % SELECTED_COUNT)
    if len(ordinary) != SELECTED_COUNT:
        raise PreregError("completeness: manifest ordinary mutants != %d" % SELECTED_COUNT)
    if {e["anchor"] for e in ordinary} != selected_anchors:
        raise PreregError("completeness: manifest anchors do not match sites")
    if len(controls) != 1 or not control.get("control"):
        raise PreregError("control is absent or not declared")
    if controls[0]["anchor"] != control["anchor"]:
        raise PreregError("control manifest does not match control.json")
    if manifest.get("unproved_exit_codes") != UNPROVED_EXIT_CODES:
        raise PreregError("unproved_exit_codes must be exactly the #45 policy %s"
                          % UNPROVED_EXIT_CODES)
    if manifest.get("accepted_exit_codes") != ACCEPTED_EXIT_CODES:
        raise PreregError("accepted_exit_codes must be %s" % ACCEPTED_EXIT_CODES)
    if manifest.get("build") != PINNED_BUILD:
        raise PreregError("build must be exactly cargo build --locked --release")
    if manifest.get("outcome_from") != OUTCOME_FROM:
        raise PreregError("outcome_from must be the ID-keyed rows map")
    if manifest.get("diagnostic_from") != DIAGNOSTIC_FROM:
        raise PreregError("diagnostic_from must be the ID-keyed diagnostics map")
    if manifest.get("implementation_sources") != PINNED_IMPLEMENTATION_SOURCES:
        raise PreregError("implementation_sources must be check.rs and the adapter")
    if "code" in manifest.get("outcome_from", []) or "code" in (manifest.get("diagnostic_from") or []):
        raise PreregError("code must stay out of outcome_from and diagnostic_from")
    complement = sites.get("complement") or []
    if sites.get("complement_count") != len(complement):
        raise PreregError("completeness: complement_count does not match complement rows")
    pinned_outside = (pins.get("enumeration") or {}).get("complement_count")
    if pinned_outside is not None and sites.get("complement_count") != pinned_outside:
        raise PreregError("completeness: complement_count does not match the pinned inventory")
    selected_spans = [s["span"] for s in selected]
    for item in sites.get("complement") or []:
        if item["span"] in selected_spans:
            raise PreregError("complement span leaked into the denominator")
    source = pins.get("source_utf8")
    if source:
        raw = source.encode("utf-8")
        text = source
        for site in selected:
            sl = site["span"]
            got = text[sl["start"]:sl["end"]]
            if got != site["bytes"]:
                raise PreregError("span does not match recorded bytes for %s" % site.get("id"))
            if _sha256(got.encode("utf-8")) != site["sha256"]:
                raise PreregError("span sha256 mismatch for %s" % site.get("id"))
        found = enumerate_source(raw)
        if [s["span"] for s in found["sites"]] != [s["span"] for s in selected]:
            raise PreregError("span/anchor does not match a fresh enumeration")


def assert_byte_identical_prereg(left: Path, right: Path) -> None:
    for name in ("sites.json", "manifest.json", "control.json"):
        if (left / name).read_bytes() != (right / name).read_bytes():
            raise PreregError("regeneration is not byte-identical: %s" % name)


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] not in ("enumerate", "emit", "validate"):
        sys.stderr.write(
            "usage: aee_checker_sealed_prereg.py enumerate <source.rs>\n"
            "       aee_checker_sealed_prereg.py emit <source.rs> <dest>\n"
            "       aee_checker_sealed_prereg.py validate <dest>\n")
        return 2
    cmd = argv[1]
    if cmd == "validate":
        validate_prereg(Path(argv[2]))
        return 0
    source = Path(argv[2]).read_bytes()
    if cmd == "enumerate":
        sys.stdout.buffer.write(encode_json(enumerate_source(source)))
        return 0
    emit_prereg(source, Path(argv[3]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
