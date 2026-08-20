# corpus-adequacy

Mutation adequacy for a **published conformance corpus**. Standard library only:
no dependency, no install, no network.

The version lives in one place: `VERSION` in `corpus_adequacy.py`. Every report
carries it as `tool_version`. Pin CI to the commit SHA; quote the version a
human can read.

A report also names the tool bytes that produced it. `tool_commit` is the
40-hex `HEAD` only when every declared runtime source — `bounded_run.py`,
`corpus_adequacy.py`, `isolated_tree.py`, `module_child.py` — is byte-identical
to that commit; otherwise it is `null`, because a commit id beside bytes it
does not name is not provenance. `tool_source_state` says which case it was:
`exact` when the bytes match, `dirty` when the comparison was made and they
differ, `unresolved` when it could not be made at all. `tool_content_sha256`
addresses the executing bytes in every case. `exact` names the bytes on disk,
not the index: a staged edit whose worktree is back at `HEAD` still executes
`HEAD` bytes. Dirt in a README or a test does not change tool identity.

This is not an attestation, a signature, or an SBOM. It does not prove the
recorded bytes are the code objects already loaded in `sys.modules`, and it
does not make the checkout or its environment reproducible.

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

## The silent class, and `diagnostic_from`

A corpus pins outcomes. Whether a mutant is *seen* therefore depends on which
channel the manifest declares as the outcome, and a rule can move a checker's
diagnostics while moving no pinned outcome at all. Scoring that as a kill would
credit the corpus for a rule its verdicts cannot see.

Declaring `diagnostic_from` beside `outcome_from` buys a third verdict:

| moved in `outcome_from` | moved in `diagnostic_from` | verdict |
|---|---|---|
| yes | either | `killed` |
| no | yes | `silent` |
| no | no | `survived` |

`silent` sits in the denominator and **never** in the numerator: an implementer
can still delete that rule and reproduce every pinned outcome. It is named
separately because the repair differs — a survivor needs a vector that moves an
outcome, a silent mutant may instead mean the corpus should declare its
diagnostics part of the pinned surface.

The two selectors may not name the same member: a member read as the outcome can
never produce a silent-only move, so the class would be unreachable and the
manifest would read as covering more than it does. That is a controlled refusal.
`diagnostic_from` needs a JSON outcome and is refused beside
`outcome_parse: test-names`, where the names *are* the outcome.

Without `diagnostic_from` the class is unreachable, so `"silent": 0` in a report
means it was not measured, not that none exist. The report says which by carrying
`diagnostic_channel_declared`.

## Runners

| Runner | For |
|---|---|
| `module` | a Python reference implementation with a callable entry point |
| `process` | a compiled implementation behind a command line, one invocation per vector |
| `batch` | a corpus consumed as a unit: one invocation, the summary is the outcome |

`batch` only discriminates if the summary names which cases moved. A checker
reporting a bare boolean makes every mutant kill everything or nothing. That
limitation belongs to the corpus and the tool says so rather than hiding it.

`process` and `batch` measure in a bounded disposable working-tree copy of
`repo_root`. Each run creates a unique temp root under the system temp
directory (never under the declared checkout) and remaps mutation, build, and
child cwd to that copy. The declared user checkout is not written. Cleanup
removes only that run's root after lstat, direct-child-of-system-temp, and
prefix checks. There is no stable pointer and no cross-run stale delete.
Abrupt `SIGKILL` of the tool cannot run Python finally, so a leftover copy
may remain under temp until the OS reclaims it; the next run uses a new
unique root and does not auto-delete the orphan. The copy is not an
atomic filesystem snapshot: concurrent external writes can produce mixed
bytes. Cleanup is best-effort; a normal cleanup error or SIGKILL can
leave an inert temp-root. The process/batch lock is
opened without following or truncating a symlink. Regular files are copied
in bounded chunks. A `.git` entry is skipped before type checks; files and
directories share one entry ceiling. This is not a sandbox, not a
git worktree, not the #4 output ceiling, not #11 module isolation, and not #2
HEAD-vs-dirty provenance. `.git` is omitted; build rules that need git metadata
in the tree are unsupported. A symlink, FIFO, socket, or device in the walk is
refused at materialization (in addition to existing load-time source
containment). Materialization over the file or byte ceiling is refused. On
platforms without `fcntl`, `process` and `batch` still refuse before work.

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

## Related work

This tool is not the first implementation of the measurement it performs, and the
honest place to say so is here.

`astrogilda/aee-conformance` ships a **forcing gate** that asks the same question
against one corpus, and asked it first. `scripts/forcing-gate.py` and
`cmd/mutgen/mutate.go` date to 2026-07-30, with the unforced-coverage ledger
`vectors/coverage-unforced.json` (2026-07-28) and `docs/FORCING-HONESTY.md`
(2026-08-01). The earliest ancestor of this tool is
`rge-bench/scripts/check_rule_liveness.py`, 2026-08-10. His gate states the
measurement plainly:

> Forcing is a property of the PAIR (corpus, rail) and it is measured, not
> argued: switch off exactly one rule in the rail, replay the whole corpus, and
> see whether the corpus notices. A rule the corpus never notices losing is a
> rule no third party is obliged to implement, whatever the vector count says.

That is this tool's question in another vocabulary: his *forcing* and *unforced*
for what is *killed* and *survived* here.

**How the two differ.** They are complementary, and the axis is not what each one
mutates — both weaken the implementation — but how the mutants are obtained:

- `mutgen` enumerates mutation sites from the **Go AST** of the rail it ships
  with, under eleven weakening operators. It needs no author declaration and
  cannot miss a site the AST exposes, but it is bound to that language and that
  repository: `forcing-gate.py` hardcodes the rail package, the baseline file and
  the build command. It is a gate for one corpus, not a tool.
- This tool refuses to infer rules and requires an **author-declared manifest**,
  one mutant per declared rule, so it runs against any implementation behind a
  module, a command, or a batch summary, and is language-agnostic through its
  `process` and `batch` runners. The cost is stated at the top of this README and
  repeated in every report: **100% is 100% of what the author declared.**

Neither bound is removable by trying harder. Enumeration cannot know which of the
sites it finds are *rules*; declaration cannot know what the author forgot.

**Where each is stronger.** His taxonomy is finer on the observation axis: KILLED,
SILENT, DEAD and INCONCLUSIVE, with `unkillable` and `masked` annotations. The
`silent` verdict here is his SILENT, adopted with the name kept. This tool is
stronger on ground truth: it requires **at least one control mutant** and voids
the entire run if one survives, which the forcing gate has no counterpart for.
All-survivors because a corpus is weak and all-survivors because nothing was
measured print identically, and only a control separates them.

## Trust boundary

A manifest is executable trusted input: an author declaration, not independent evidence. 100% is 100% of what that author declared. Do not run a manifest you do not trust. A third-party manifest is not independent evidence merely because it was written elsewhere.

That the tool itself uses no network does not mean a child or a manifest cannot. Every runner starts a child: `runner: module` loads the corpus in a disposable child process of this tool, while `process` and `batch` run the commands the manifest names. The module child is bounded by one deadline, one output ceiling and a POSIX process-group kill, which is trusted-local process isolation. Direct-child failure is classified by role: observed abnormal termination (timeout, output-cap, unexpected-exit, signal) of an ordinary mutant's child is a named kill; an unusable protocol result (empty output, parse error, incomplete) is unproved and never a kill; baseline or control child failure invalidates the score (no adequacy result). Same-user parent signalling (e.g. `kill(getppid())`), session escape and host resource exhaustion remain outside the process-isolation claim. The child inherits this process's filesystem, network, environment and credentials, nothing bounds its memory or its descriptors, and its protocol channel is not authenticated against a corpus written to forge a verdict. Isolation and least privilege are the caller's job; this is not a sandbox.
