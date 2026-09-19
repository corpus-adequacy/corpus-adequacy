#!/usr/bin/env python3
"""G feasibility probe. NOT EVIDENCE, and no record derives from it.

One question: can a committed boundary-value template already kill every held-out mutant this
candidate can carry? If it can, a model has nothing left to find here, and G is not runnable for
value on this fixture.

The mutants below are throwaway. They were written by Claude, which is ineligible to author a
real held-out set, and they are published here on purpose so that nobody mistakes them for one.
Runs the real Rust candidate on the host with cargo. No Docker, no sealed route, no report.v0.
The recorded output is PROBE-OUTPUT.txt beside this file; README.md there says what it can and
cannot show (#270).

Usage, from anywhere: python3 docs/design/g-feasibility-probe/g_probe.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# The repository root: this file lives at docs/design/g-feasibility-probe/.
ROOT = Path(__file__).resolve().parents[3]
CANDIDATE = ROOT / "fixtures" / "contained-v1-owned" / "candidate"
CORPUS = {"allow": 5, "boundary": 10, "negative": -1, "over-limit": 11}
PUBLISHED_COUNTEREXAMPLE = {"published-12": 12}
I64_MIN, I64_MAX = -(2 ** 63), 2 ** 63 - 1

# The template arm: boundary-value analysis over the declared domain, b-1/b/b+1 at each boundary
# the candidate names, minus anything the frozen corpus or the published counterexample covers.
BOUNDARIES = (0, 10, I64_MIN, I64_MAX)


def template_vectors() -> dict:
    values = set()
    for boundary in BOUNDARIES:
        for value in (boundary - 1, boundary, boundary + 1):
            if I64_MIN <= value <= I64_MAX:
                values.add(value)
    covered = set(CORPUS.values()) | set(PUBLISHED_COUNTEREXAMPLE.values())
    return {"t%d" % index: value
            for index, value in enumerate(sorted(values - covered))}


LOWER = "    if value < 0 {"
UPPER = "    if value > maximum {"
SENTINEL = """    if value == i64::MIN {
        return (false, "minimum-sentinel", "minimum sentinel".to_owned());
    }
"""

MUTANTS = {
    # Guard perturbations that a held-out author might plausibly write.
    "lower-shift-to-one": (LOWER, "    if value < 1 {"),
    "lower-inclusive": (LOWER, "    if value <= 0 {"),
    "sentinel-reachable": (LOWER, "    if value < 0 && value != i64::MIN {"),
    "upper-exclude-max": (UPPER, "    if value > maximum && value < i64::MAX {"),
    "lower-catches-max": (LOWER, "    if value < 0 || value == i64::MAX {"),
    "upper-shift-by-two": (UPPER, "    if value > maximum + 1 {"),
    # Expected to be refused by the authoring rules, included to show the rules bite.
    "upper-interior-hole": (UPPER, "    if value > maximum && value != 37 {"),
    "sentinel-removed": (SENTINEL, ""),
}


def build(source_dir: Path) -> Path:
    out = subprocess.run(["cargo", "build", "--offline", "--quiet"], cwd=source_dir,
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("build failed in %s:\n%s" % (source_dir, out.stderr[-2000:]))
    return source_dir / "target" / "debug" / "corpus-adequacy-owned-fixture"


def run(binary: Path, vectors: dict) -> dict:
    with tempfile.TemporaryDirectory() as raw:
        work = Path(raw)
        vector_dir = work / "vectors"
        vector_dir.mkdir()
        for name, value in vectors.items():
            (vector_dir / ("%s.json" % name)).write_text(
                '{"value":%d}' % value, encoding="utf-8")
        (vector_dir / "MANIFEST.json").write_text(json.dumps(
            {"corpusDigest": "probe", "vectors": [{"file": "%s.json" % name, "id": name,
                                                   "value_class": "probe"}
                                                  for name in sorted(vectors)]}), encoding="utf-8")
        report = work / "report.json"
        out = subprocess.run([str(binary), str(vector_dir), "--json", str(report)],
                             capture_output=True, text=True)
        if out.returncode != 0:
            raise SystemExit("candidate failed: %s" % out.stderr)
        doc = json.loads(report.read_text(encoding="utf-8"))
    # The declared outcome is (accepted, reason); detail is diagnostic only.
    return {row["id"]: (row["accepted"], row["reason"]) for row in doc["vectors"]}


def copy_candidate(name: str) -> Path:
    """A scratch copy, so no build output lands in the repository."""
    work = Path(tempfile.mkdtemp(prefix="g-probe-%s-" % name))
    shutil.copytree(CANDIDATE, work / "candidate", ignore=shutil.ignore_patterns("target"))
    return work / "candidate"


def mutate(name: str, anchor: str, replacement: str) -> Path:
    work = copy_candidate(name).parent
    source = work / "candidate" / "src" / "check.rs"
    text = source.read_text(encoding="utf-8")
    if text.count(anchor) != 1:
        raise SystemExit("anchor not unique for %s" % name)
    source.write_text(text.replace(anchor, replacement), encoding="utf-8")
    return work / "candidate"


def main() -> int:
    template = template_vectors()
    everything = dict(CORPUS, **PUBLISHED_COUNTEREXAMPLE, **template)
    print("template vectors (%d): %s" % (len(template), sorted(template.values())))
    print("frozen corpus: %s   published counterexample: %s\n"
          % (sorted(CORPUS.values()), sorted(PUBLISHED_COUNTEREXAMPLE.values())))

    original = copy_candidate("original")
    original_binary = build(original)
    baseline = run(original_binary, everything)
    frozen_ids = set(CORPUS) | set(PUBLISHED_COUNTEREXAMPLE)

    rows = []
    for name, (anchor, replacement) in MUTANTS.items():
        built = mutate(name, anchor, replacement)
        try:
            observed = run(build(built), everything)
        except SystemExit as exc:
            rows.append((name, "did-not-build", "-", str(exc)[:40]))
            continue
        finally:
            shutil.rmtree(built.parent, ignore_errors=True)
        moved = {row_id for row_id in everything if baseline[row_id] != observed[row_id]}
        survives_frozen = not (moved & frozen_ids)
        killed_by_template = bool(moved & set(template))
        rows.append((name,
                     "survives" if survives_frozen else "killed-by-frozen-corpus",
                     "killed" if killed_by_template else "SURVIVES-TEMPLATE",
                     ",".join(sorted(moved)) or "nothing moved"))

    width = max(len(name) for name, *_ in rows)
    print("%-*s  %-24s  %-18s  %s" % (width, "mutant", "vs frozen corpus + 12",
                                      "vs template", "rows that moved"))
    for name, frozen, template_result, moved in rows:
        print("%-*s  %-24s  %-18s  %s" % (width, name, frozen, template_result, moved))

    eligible = [row for row in rows if row[1] == "survives"]
    survivors = [row for row in eligible if row[2] == "SURVIVES-TEMPLATE"]
    print("\n%d of %d mutants survive the frozen corpus and the published counterexample."
          % (len(eligible), len(rows)))
    print("%d of those survive the boundary template.\n" % len(survivors))

    # Surviving the template is not enough to be a held-out candidate. The authoring rules also
    # refuse a mutant nothing can kill, and one killable only by an arbitrary interior constant.
    # Sweep for killing values and classify, rather than asserting it.
    sweep = {"s%d" % index: value for index, value in enumerate(sorted(
        set(range(-200, 201))
        | {I64_MIN, I64_MIN + 1, I64_MAX - 1, I64_MAX, 2 ** 31, -(2 ** 31), 10 ** 12, -(10 ** 12)}
    ))}
    sweep_baseline = run(original_binary, sweep)
    genuine = []
    for name, _, template_result, _ in survivors:
        anchor, replacement = MUTANTS[name]
        built = mutate(name, anchor, replacement)
        try:
            observed = run(build(built), sweep)
        finally:
            shutil.rmtree(built.parent, ignore_errors=True)
        killers = sorted(sweep[row_id] for row_id in sweep
                         if sweep_baseline[row_id] != observed[row_id])
        on_boundary = [value for value in killers
                       if any(abs(value - boundary) <= 1 for boundary in BOUNDARIES)]
        if not killers:
            verdict = "no killer found in %d values: equivalent, nothing can kill it" % len(sweep)
        elif not on_boundary:
            verdict = ("killable only at interior points %s: refused by the authoring rules as "
                       "not a rule" % killers[:4])
        else:
            verdict = "killable at a boundary the template missed: %s" % on_boundary[:4]
            genuine.append(name)
        print("  %-20s %s" % (name, verdict))

    shutil.rmtree(original.parent, ignore_errors=True)
    print("\nVERDICT:", "template-exhausted" if not genuine
          else "room-for-a-held-out-set: " + ", ".join(genuine))
    return 0


if __name__ == "__main__":
    sys.exit(main())
