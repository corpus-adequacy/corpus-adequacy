# Agent / contributor notes

Open an **issue** before a PR. Do not point an agent at this repository and ask
it to “find bugs”; give it **one concrete target**. Typo sweeps, unused-variable
cleanups and speculative refactors are low-signal here.

This file is **reviewer practice** plus a map of what the tool already does.
It adds **no new tool rule**. Where a checklist row is marked *enforced*, the
named function already refuses the manifest (**exit 2**) or fails the run
(**`failures` / `adequate=false` / exit 1**, often with **no score**). Where it
is marked *judgment*, a human or agent reviewer must check it; the tool cannot.

## Concrete targets (examples)

1. A normative sentence in a corpus’s own text that **no** declared mutant stands for.
2. An `equivalent` entry whose `reason` does not name the `outcome_from` projection
   the equivalence is claimed under.

## Manifest review checklist

Mark each item *enforced* or *judgment*. Prefer citing refusal vs run-failure.

| Kind | Question | What the tool does today |
|------|----------|---------------------------|
| *enforced* (run failure) | Is the **anchor unique** across the **declared** implementation sources? | `_run_mutation_step` (process/batch) and the module substitution path count occurrences in declared sources only; `0` or `>1` appends `failures` (control anomalies also invalidate the score). Not a `ManifestError` / exit 2. |
| *judgment* | Is the anchor on the **rule’s own line**, not a neighbour that shares text? | Uniqueness is counted; **placement** is not. |
| *judgment* | For an ordinal axis, is the mutant a **permutation** (flatten/invert), not a **deletion**? | Module docstring states the method. `load_manifest_bytes` only refuses an **empty** `anchor` or `anchor == replacement` — it does **not** check ordinal semantics. |
| *judgment* | Does the replacement **delete the rule**, not merely a shared line fragment? | Same as above: nonempty / distinct bytes only. |
| *enforced* (run failure / no score) | Does at least one **positive** control **move** (and get killed)? | `structural_failures` requires a control with positive polarity (legacy default via `_control_polarity`). Ordinary evidence is gated until controls succeed; a moved inert control or control-error yields **no adequacy score**. An **inert-only** manifest does **not** satisfy the positive-control requirement. |
| *judgment* | Does each control declare `control_polarity` explicitly? | Legacy controls default to **positive**. If the field is present, `load_manifest_bytes` **refuses** (exit 2) unless `control: true` and the value is `positive` or `inert`. |
| *enforced* (exit 2) | Does every `equivalent` carry a **non-blank reason**? | `load_manifest_bytes` requires `label` + `reason` and refuses a blank reason (`ManifestError` → CLI exit 2). |
| *judgment* | Does that reason name the declared **`outcome_from` projection**? | Equivalence is only meaningful relative to that projection; the tool does not parse the prose. |
| *judgment* | Process and batch runners with a JSON outcome: does **`outcome_from`** cover every channel the corpus pins (for example a reason token, not only the decision)? | Apart from termination kills (timeout, output cap, an exit in neither `accepted_exit_codes` nor `unproved_exit_codes`, a signal), these runners compare only declared members (`child_outcome` reads only the keys each selector names), so a pinned channel left out of `outcome_from` cannot kill a row. `ReasonTokenOnOutcome` shows one substitution as `killed`, `silent` or `survived` depending only on where the reason token is declared. A channel the checker reports but the corpus does not pin belongs in `diagnostic_from`. Which channels the corpus pins is its author's call; the tool cannot check it. Not applicable to the module runner (entrypoint return value) or test-names (failed-test names). |
| *enforced* (exit 2, narrow) | Does every known-hole entry carry **`label`**, **`reason`**, and **`recorded`**, keyed under the digest string read from the named digest file? | `load_manifest_bytes` requires those keys and a non-blank `reason` when `known_holes` is non-empty; `_acknowledged_holes` matches the **file-read** digest string. **Not** enforced: ISO date format of `recorded`, or recomputing the digest from vectors (author-declared file honesty is *judgment*). |
| *enforced* (runner-scoped) | Are `outcome_from` / `diagnostic_from` usable for this runner? | `outcome_from` required for process/batch (unless `outcome_parse: test-names`). `diagnostic_from` is **refused** on `runner: module` and beside `test-names`. Overlap between the two selectors is refused. Missing declared outcome members **fail the run** when those channels are read — not a silent green. |
| *judgment* | Does the PR cite one **real run** (`report.v0` digest + public evidence), as the publish-measurement template already asks? | Not checked by the tool. |

## What a run proves

- A **control that moves** proves the harness can see a change on that path. It
  does **not** prove any other mutant was reachable.
- A **`survived`** (or silent-only) row is a **hole in the contract**, not a defect
  in the implementation — and that reading applies only when the run actually
  produced a score (healthy positive control, not `control-error` / unproved /
  barrier abort).
- On process and batch runners with a JSON outcome, the `survived` and silent-only
  readings also presume that `outcome_from` covers every channel the corpus pins. A
  pinned channel left out of `outcome_from` cannot kill a row, so that row's
  `survived` or `silent` belongs to the manifest, not the corpus. A channel the checker reports but the corpus
  does not pin belongs in `diagnostic_from`, where the row reads `silent` (README,
  "The silent class, and `diagnostic_from`").

## Exit codes (do not conflate)

| Exit | Meaning |
|------|---------|
| **2** | Manifest (or input) **refusal**: `ManifestError` / unreadable input in `main` — no adequacy result. |
| **1** | Measurement **completed** with `adequate=false` (failures, survivors, control problems that null the score, etc.). |
| **0** | `adequate=true`. |

## Disclosure

Agent-assisted manifests and measurements say so in the PR.
