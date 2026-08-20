# corpus-adequacy

Mutation adequacy for a **published conformance corpus**. Standard library only:
no dependency, no install, no network.

The version lives in one place: `VERSION` in `corpus_adequacy.py`. Every report
carries it as `tool_version`, plus `tool_commit` when the checkout can resolve
`HEAD`. Pin CI to the commit SHA; quote the version a human can read. The git
tag is `v` plus that same number.

```
python3 corpus_adequacy.py --version
python3 corpus_adequacy.py <manifest.json>
python3 corpus_adequacy.py <manifest.json> --json
```

## The question it answers

Not *does this corpus reproduce its own verdicts*, but:

> Can an implementer **delete a declared rule**, still reproduce the pinned
> outcomes, and be indistinguishable from a conforming implementation?

Outcome coverage is not rule coverage. A corpus can reach every declared outcome
while some rule never decides anything, because another rule reaches the same
outcome first on every vector it would have caught.

So a surviving mutant is not a gap in confidence. It is a **hole in the
contract**, which is why the bar is 100% of the rules the author declared rather
than the ~80% usual in mutation testing.

## What it cannot do, stated first

It **cannot infer a corpus's rules from source**. That would be a static-analysis
project, and a tool that guessed would report a score it had not earned. A corpus
declares its own mutants in a manifest, which means:

**100% here is 100% of what the AUTHOR DECLARED.** It is never 100% of the rules
the implementation has. A rule nobody declared is invisible to this check, and
the manifest is written by the same hand as the corpus. The report therefore
never prints a bare percentage — it prints the numerator, the denominator, the
exclusions, and what the percentage is a percentage of.

## The rules it enforces on a manifest

- **One mutant per declared rule**, not per line, so a survivor names the rule an
  implementation could omit rather than a line number.
- **Ordinal axes are permuted, not deleted.** Deletion is the wrong operator for
  a ladder: the ordering lives in a table a comparison reads, not in a branch a
  mutant can cut.
- **Equivalence is declared with a reason, never inferred.** Deciding mutant
  equivalence is undecidable, so a tool claiming to detect it would be lying.
- **A crash is a kill**, reported separately.
- **A mutant that never ran is `unproved`, never a kill.** It was never shown to
  the corpus, so the corpus said nothing about that rule. Counting it killed lets
  a typo in the substitution print as a covered rule.
- **Mutant labels are unique across the manifest, including declared
  equivalents.** A known-hole acknowledgement is keyed by that label, so one
  repeated name could otherwise excuse two rules. A label may be acknowledged
  at most once for each corpus digest.
- **At least one control.** All-survivors because a corpus is weak and
  all-survivors because nothing was measured print identically. A control is a
  mutation on the same path that MUST be killed; it is excluded from the score,
  and a control that survives fails the run with every other verdict declared
  meaningless.
- **A group present in the corpus with no declared mutants is a hard failure** —
  the check may not silently cover less than its name claims.

## Runners

| Runner | For |
|---|---|
| `module` | a Python reference implementation with a callable entry point |
| `process` | a compiled implementation behind a command line, one invocation per vector |
| `batch` | a corpus consumed as a unit: one invocation, the summary is the outcome |

`batch` only discriminates if the summary names which cases moved. A checker
reporting a bare boolean makes every mutant kill everything or nothing. That
limitation belongs to the corpus and the tool says so rather than hiding it.

## Exclusion categories, and why each one is narrow

| Category | Means |
|---|---|
| `out_of_scope` | the corpus never claimed this rule. Requires a stated reason |
| known hole | the corpus **does** claim it and does not exercise it. Pinned to a declared corpus digest, requires a reason and a date |
| declared equivalent | no vector can distinguish it, with the reason stated |

A known hole is pinned to a digest **read from a file the manifest names**. It is
not recomputed from the vectors, so the acknowledgement is an author-supplied
claim, honest only if that file is kept honest — and the report says exactly
that rather than claiming more.

## Provenance

Extracted from `Rul1an/assay`, where it was built and reviewed. The move is an
extraction rather than a copy: two implementations of a measurement drift, and
the copy that drifts is the one that stops measuring.

Its own findings on the corpora it was built against, including the unflattering
ones, are published in that repository's `conformance/INDEX.md`.
