# corpus-adequacy

Mutation adequacy for a **published conformance corpus**. Standard library only:
no dependency, no install, no network.

The version lives in one place: `VERSION` in `corpus_adequacy.py`. Every report
carries it as `tool_version`, plus `tool_commit` when the checkout can resolve
`HEAD`. Pin CI to the commit SHA; quote the version a human can read.

The git tag is `v` plus that same number. The cut order is cut → dated heading → VERSION → tag. Quoting a version is not a tag and does not make the tag addressable.

```
python3 corpus_adequacy.py --version
python3 corpus_adequacy.py <manifest.json>
python3 corpus_adequacy.py <manifest.json> --json
```

## Support and release

Maintained on CPython 3.13 on ubuntu-latest, macos-latest, and windows-latest.
The `module` runner is cross-platform. `process` and `batch` refuse where `fcntl` is unavailable.
Release procedure: move Unreleased notes into a dated CHANGELOG heading, set VERSION, merge only after the three-OS CI is green, create and push an annotated vVERSION tag on that merge SHA, require the tag-push CI green, then publish the GitHub Release. Quoting a version alone is not a release.

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
- **Child termination is classified before stdout is parsed.** Default
  `accepted_exit_codes` is `[0]`. A parseable report on an undeclared code, a
  signal, or a missing code is not an outcome. Signals and `None` are never
  accepted. `outcome_parse: test-names` is batch-only and must include `101`.
  JSON `outcome_from` has no protocol ID; extra codes such as `2` are declared
  explicitly, not inferred from a command name. An observed unexpected exit
  or signal on an ordinary mutant may be a kill with that class named as
  `how`. A control abnormality is `control-error` and invalidates the run
  (no score), even if another mutant already moved. Timeout and
  output-ceiling failures stay their own classes. This repository ships no
  corpus manifests and does not migrate downstream adapter manifests.
- **A mutant that never ran is `unproved`, never a kill.** It was never shown to
  the corpus, so the corpus said nothing about that rule. Counting it killed lets
  a typo in the substitution print as a covered rule.
- **Mutant labels are unique across the manifest, including declared
  equivalents.** A known-hole acknowledgement is keyed by that label, so one
  repeated name could otherwise excuse two rules. A label may be acknowledged
  at most once for each corpus digest. Labels are non-empty strings and remain
  exact, case-sensitive identities; the tool does not normalize them.
- **At least one control.** All-survivors because a corpus is weak and
  all-survivors because nothing was measured print identically. A control is a
  mutation on the same path that MUST be killed; it is excluded from the score,
  and a control that survives fails the run with every other verdict declared
  meaningless.
- **A group present in the corpus with no declared mutants is a hard failure** —
  the check may not silently cover less than its name claims.
- **Manifest containers have one declared JSON kind.** `mutants`, `equivalent`,
  and `known_holes` are objects; each group or digest value is an array of
  objects. A wrong kind is a controlled refusal (exit 2), not a traceback.
  `--json` then prints a `corpus-adequacy.error.v0` envelope on stdout.
  A missing manifest file takes the same catch: exit 2, the envelope on stdout,
  and the human `could not measure` line on stderr.

## Runners

| Runner | For |
|---|---|
| `module` | a Python reference implementation with a callable entry point |
| `process` | a compiled implementation behind a command line, one invocation per vector |
| `batch` | a corpus consumed as a unit: one invocation, the summary is the outcome |

`batch` only discriminates if the summary names which cases moved. A checker
reporting a bare boolean makes every mutant kill everything or nothing. That
limitation belongs to the corpus and the tool says so rather than hiding it.

`process` and `batch` currently mutate declared sources in place. The source
guard restores them after normal completion and ordinary Python exceptions; it
cannot restore after `SIGKILL`, power loss, or host termination. Until those
runners use an isolated disposable checkout, run them only in a clean,
disposable checkout. On platforms without `fcntl` advisory locking, `process`
and `batch` refuse before the dirty check, source capture, build, child,
mutation, or score. Resolved source paths outside `repo_root` are refused at
manifest load and checked again before source access. These repeated checks are
not an atomic defence against a hostile concurrent filesystem actor; disposable
checkout isolation remains the durable boundary planned for these runners.

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

Extracted from [`Rul1an/assay`](https://github.com/Rul1an/assay) at
`78c792f574e882aad683b690bfbff5445774056e`, under that repository's MIT
license. The root `LICENSE` is that upstream text, including the copyright
notice, copied without alteration.

The move is an extraction rather than a copy: two implementations of a
measurement drift, and the copy that drifts is the one that stops measuring.

Its own findings on the corpora it was built against, including the unflattering
ones, are published in that repository's `conformance/INDEX.md`.

## Trust boundary

A manifest is executable trusted input: an author declaration, not independent evidence. 100% is 100% of what that author declared. Do not run a manifest you do not trust. A third-party manifest is not independent evidence merely because it was written elsewhere.

That the tool itself uses no network does not mean a child or a manifest cannot. `runner: module` runs in-process; `process` and `batch` run the commands the manifest names. Isolation and least privilege are the caller's job; this is not a sandbox.
