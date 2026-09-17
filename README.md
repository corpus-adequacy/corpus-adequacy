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
python3 corpus_adequacy.py --survivors <report.json>
python3 corpus_adequacy.py --survivors <report.json> --json
python3 corpus_adequacy.py --rules <report.json> --manifest <manifest.json>
python3 corpus_adequacy.py --rules <report.json> --manifest <manifest.json> --json
python3 corpus_adequacy.py --diff <old.report.v0> <new.report.v0>
python3 corpus_adequacy.py --diff <old.report.v0> <new.report.v0> --json
python3 corpus_adequacy.py --inspect <manifest.json>
python3 corpus_adequacy.py --inspect <manifest.json> --json
python3 examples/reason-token-projections/walkthrough.py
```

`--inspect` bounded-reads one regular manifest file and validates only the
declarations in those exact bytes. Its JSON form is the closed,
deterministic `corpus-adequacy.inspect.v0` document. It keeps declared values,
static checks, runtime-unchecked facts, and review judgments separate. Each
selector is closed as `{status, value}` so an absent declaration remains
distinct from an explicitly declared empty or non-empty selector;
operator profile and contained resource settings are unavailable because the
manifest does not carry them. Manifest v0 reports rule inventory as absent,
while v1 summarizes only its validated author-declared inventory. Inspection
and normal loading share the same declaration checks: controls are exact JSON
booleans, child deadlines are positive JSON integers no greater than `2^53 - 1`,
a conservative bound within binary64's contiguous exact-integer range. The
bound does not claim that `2^53` itself is unrepresentable. Build argv may be
empty, and execution argv must be a non-empty array; every argv member is a
non-empty string. These are input-shape refusals, not tuned runtime policy.
Static inspection does not resolve or check paths, read vectors or a known-hole
digest file;
when that digest path is declared, inspection shows only its original relative
string and marks the target runtime-unchecked. It does not open that path,
select a backend, build, materialize, lock, import, or run anything.
`execution_authorized` is always false. Success is a static declaration result,
not readiness, sandbox evidence, execution permission, runtime validation,
rule completeness, or adequacy. Input or contract refusal exits 2; success
exits 0 without an adequacy verdict.

`examples/reason-token-projections/` is one offline process-runner example: the
same implementation, vector, mutation and control bytes under three
declarations. `outcome_from` of `accepted` plus `wire_code` kills the
reason-token mutant; `accepted` alone lets it survive; `accepted` as outcome
and `wire_code` as `diagnostic_from` makes it silent. Controls stay outside
the denominator. The walkthrough invokes this CLI with a timeout and inspects
only produced `report.v0` fields. On platforms without `fcntl` it returns a
named unsupported result and makes no result claim. The manifests are v0, so
absent inventory is not a measured zero. This example does not establish
whole-corpus adequacy, adapter fidelity, rule ownership, cross-platform
process support, security effectiveness, or reachability.

`--survivors` is a sibling projection over an existing `report.v0` file. It does
not measure, does not call the runner, and does not change `report.v0` bytes.
`--json` on that path writes `corpus-adequacy.survivors.v0`. Plain `--json`
without `--survivors` is still `report.v0`. Optional `--manifest` is used only
when its exact file bytes match `report.manifest_sha256`; the projection never
invents compared or unmoved vector IDs.
A digest-matched anchor that is empty after control stripping is an
intentional omission: no `anchor_excerpt` and no `anchor_omitted`. That is
not a missing field and not a new survivors key.
`--survivors` requires the exact `report.v0` key set at the document and
mutant-row boundary. Required keys are the producer set.
`originals_unverified_against_head` is required on `process` and `batch`
and forbidden on `module`. Mutant-row keys are closed per producer
verdict: `scope` is required except on `equivalent`, `raised` is optional
only on `killed`, and `moved_diagnostic` is required on `silent`,
optional on `unexercised`/`known-hole`, and forbidden otherwise. Unknown
keys and missing required keys fail closed on distinct routes. This is a
consumer closed-set, not a `report.v1` and not a change to production
`report.v0` or `survivors.v0` bytes.

`corpus-adequacy.manifest.v1` keeps the v0 measurement fields and semantics and
requires a closed `rules` inventory. Each author-written row is either
`mutated`, with one or more eligible mutation labels from the same group, or
`excluded`, with a reason. Every declared non-control, in-scope mutant and every
declared equivalent must be linked exactly once. This closes the mapping the
manifest author supplied; it does not infer rules from implementation source or
corpus text and does not establish that every normative rule was listed.

`--rules` is a read-only sibling projection. It bounded-reads an exact
`report.v0` and the required manifest, checks the report's manifest digest
against the exact manifest bytes before parsing them, and emits
`corpus-adequacy.rules.v0`. It never invokes a runner or candidate. A matched v0
manifest projects `inventory: null`, including a v0 document with a member named
`rules`; that member remains an uninterpreted extension. A valid v1
`"rules": {}` projects real zero counts. The projected counts are rule rows,
mutation-linked rule rows, excluded rule rows, and linked mutants. They are not
a percentage or a score. Flat projected rows add their exact `group` beside the
disposition-specific manifest fields so `(group, id)` remains a self-describing
identity when two groups use the same rule id.

This inventory is author-declared traceability. It is not rule coverage,
adequacy, owner ratification, certification, endorsement, partnership,
execution, remeasurement, or a change to historical evidence. `report.v0`, its
score and denominator, and `survivors.v0` do not gain inventory fields.

`--diff` is a nonexecuting sibling projection over two existing `report.v0`
files. It classifies by pinned identities only and never reads the corpus or the manifest. `--json` writes `corpus-adequacy.diff.v0`. It reports identity facts
(`same`, `changed`, `undeclared`, `unresolved`), one row per globally unique
label, and counts that are not one denominator. It does not print a percentage delta, does not infer a cause, and does not change `report.v0` or
`survivors.v0` bytes. `corpus_digest` remains an author-declared string.

Closed offline codecs `corpus-adequacy.class-provenance.v0` and
`corpus-adequacy.class-attempt.v0` address one evidence class beside `report.v0`,
not inside it. Loaders bound every path to the existing 4 MiB no-follow reader
and compare a dependent digest before parsing those bytes. They do not execute a
candidate, register a CLI, or emit an aggregate or overall adequacy score.
Field tables live in `docs/class-evidence-v0.md`. Publishable attempt
construction remains unreachable until a later visibility slice. `report.v0`,
`survivors.v0`, `rules.v0` and `diff.v0` bytes are unchanged.

```
python3 adapters/tersign_evidence_record.py <tersign-checkout> <empty-dest>
```

The Tersign adapter copies either of two explicit pinned evidence-record sources
(`1cc5ea32b3da4f195b55782c8a3573d8564673a7` or
`0e560c1ad47f08177042c62754ebe6e0b482ad9a`) into files the existing process
runner can consume. Git checkouts require an exact commit, manifest digest,
vectors tree, and vector-files digest; non-Git copies require a unique exact
manifest and vector-files digest identity. Unknown or mixed identities fail
closed. It does not import
`verify.py`, and copied vector bytes are not normalized. Kind is not an outcome.
`source.json` records the pin and the source-gate results; it is not a
`survivors.v0` document and does not score the suite. This is not authenticity,
endorsement, completeness, a Tersign partnership, or a certification.

```
python3 adapters/algovoi_jcs_edge.py \
  fixtures/algovoi-jcs-edge-aa53149c/jcs_edge_v1.json <empty-dest>
```

The AlgoVoi adapter copies one pinned `jcs_edge_v1` anchor set
(`chopmob-cloud/algovoi-jcs-conformance-vectors` at
`aa53149c670f1659dad511755168ad5231dc04de`) into files the existing process
runner can consume. The vendored producer `manifest.json` (SHA-256
`5e7c56fe353cd5c04adfc779191903d8cf79317301cc3402285a1881f1309865`) is the
single root of the chain: it is bounded-loaded and bound to its own digest, and
the anchor digest, vector count and invariant count are read from its
`jcs_edge_v1` entry. No second identity constant pins the anchor, so one digest
carries the whole chain. Its prose `anchors_to` field is never parsed. Each `cases/<id>.json` is the exact
byte slice of that row's `preimage` value plus one LF, so `1.0` and `1` stay
distinct spellings; the adapter never parses and re-serializes a preimage. On
this file a whole-document JSON round trip happens to be byte-identical to the
source, so emitted-byte equality alone does not prove the slice; the mechanism
is pinned separately.

`equal_sha256` is evaluated against the two declared digests. The one remaining
prose relation is recorded as typed `refused`, never skipped and never passed.
`rfc8785_section` is copied as `authored_section` and is source metadata, not a
rule inventory. This is not authenticity, endorsement, complete RFC 8785
coverage, correctness of the authored labels, correctness of the upstream
reference implementation, or adequacy of any implementation.

```
python3 measurements/tersign_checks.py <adapted-case.json>
```

The Tersign CHECKS wrapper is a process-runner implementation: it dispatches
`CHECKS[kind](input)` and emits `{verdict, reason|null}`. `verify.py`,
`keccak.py`, and the wrapper are the implementation sources. `accepted_exit_codes`
is `[0]`; nonzero stdout is not an outcome. Detail is dropped. The three
`verify.py` `main()` suite gates (kind agreement, reason closure, per-kind
two-sidedness) are out of scope for this wrapper and are not declared as
survivors. This run measures a reviewed declared subset at one pin. It is not a
complete inventory, upstream correctness, equivalence, endorsement, or a release.

The addressable measurement lives at `measurements/tersign-1cc5ea32/` (manifest,
adapted vectors, cases). The durable entrypoint is `python3`, not a host
interpreter path. Full `report.v0` bytes are recorded after that source commit.

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

After a valid run, a surviving mutant means only that the declared mutation
did not change the declared outcome on the pinned inputs. Reading that as a
hole in the contract also requires a faithful owner-pinned declaration and
rule ownership. The bar is still 100% of the rules the author declared rather
than the ~80% usual in mutation testing. Changing selectors changes the observational question; it does not improve a corpus.

## What it cannot do, stated first

It **cannot infer a corpus's rules from source**. That would be a static-analysis
project, and a tool that guessed would report a score it had not earned. A corpus
declares its own mutants in a manifest, which means:

**100% here is 100% of what the AUTHOR DECLARED.** It is never 100% of the rules
the implementation has. A rule nobody declared is invisible to this check, and
the manifest is written by the same hand as the corpus. The report therefore
never prints a bare percentage — it prints the numerator, the denominator, the
exclusions, and what the percentage is a percentage of.

## Agents and contributors

See [`AGENTS.md`](AGENTS.md) for where to start, the manifest-review checklist
(*enforced* vs *judgment*), and what a run proves. That file documents reviewer
practice and existing tool behaviour; it does not add tool rules.

## The rules it enforces on a manifest

- **One mutant per declared rule**, not per line, so a survivor names the rule an
  implementation could omit rather than a line number.
- **Ordinal axes are permuted, not deleted.** Deletion is the wrong operator for
  a ladder: the ordering lives in a table a comparison reads, not in a branch a
  mutant can cut.
- **Equivalence is declared with a reason, never inferred.** Deciding mutant
  equivalence is undecidable, so a tool claiming to detect it would be lying.
- **Child termination is classified before stdout is parsed.** Default
  `accepted_exit_codes` is `[0]`. Opt-in `unproved_exit_codes` is `[]` and
  must be disjoint from the accepted set. A parseable report on an undeclared
  code, a signal, or a missing code is not an outcome. Signals and `None` are
  never accepted or declared unproved. `outcome_parse: test-names` is
  batch-only and must include `101`. JSON `outcome_from` has no protocol ID;
  extra codes such as `2` are declared explicitly, not inferred from a
  command name. A child that exits with a declared-unproved code is reporting
  that its *inner* measurement did not complete; that exit is classified
  before stdout is read, so valid JSON on it is not an outcome. An ordinary
  mutant with any such exit is `unproved` (`moved` stays 0), even if another
  vector moved. Host-child timeout, signal, output-cap and unexpected-exit
  are unchanged. Process/batch direct-child parse-error and incomplete are
  `unproved`; this opt-in field is not what reclassifies them. The
  field is process/batch only; a module manifest that declares it is refused.
  An observed
  unexpected exit or signal on an ordinary mutant
  may be a kill with that class named as `how`. A control abnormality is
  `control-error` and invalidates the run (no score), even if another mutant
  already moved. Timeout and output-ceiling failures stay their own classes.
  This repository ships no corpus manifests and does not migrate downstream
  adapter manifests.
- **A mutant that never ran is `unproved`, never a kill.** It was never shown to
  the corpus, so the corpus said nothing about that rule. Counting it killed lets
  a typo in the substitution print as a covered rule.
- **Mutant labels are unique across the manifest, including declared
  equivalents.** A known-hole acknowledgement is keyed by that label, so one
  repeated name could otherwise excuse two rules. A label may be acknowledged
  at most once for each corpus digest. Labels are non-empty strings and remain
  exact, case-sensitive identities; the tool does not normalize them.
- **At least one positive control.** All-survivors because a corpus is weak and
  all-survivors because nothing was measured print identically. A legacy control,
  or one declaring `"control_polarity": "positive"`, MUST move and be killed.
  An optional `"control_polarity": "inert"` control MUST leave pinned outcomes
  unchanged. A moved inert control invalidates the run and emits no score; an
  absent or non-unique inert anchor is `control-error`, not evidence of unchanged
  behavior. Both polarities are excluded from the denominator, and an inert-only
  manifest does not satisfy the positive-control requirement. `control_polarity`
  is refused without `"control": true`; inertness is explicit, never inferred.
- **A group present in the corpus with no declared mutants is a hard failure** —
  the check may not silently cover less than its name claims.
- **Manifest containers have one declared JSON kind.** `mutants`, `equivalent`,
  and `known_holes` are objects; each group or digest value is an array of
  objects. A wrong kind is a controlled refusal (exit 2), not a traceback.
  `--json` then prints a `corpus-adequacy.error.v0` envelope on stdout.
  A missing manifest file takes the same catch: exit 2, the envelope on stdout,
  and the human `could not measure` line on stderr.

## Attributing failed-test changes

A non-control mutant may declare `"expected_mover": "test_name"` when using
`runner: batch` with `outcome_parse: test-names`. The named test must change
membership between the baseline and mutant failed-test tuples: it must be in
their symmetric difference. For example, if only `neighbor_test` starts failing
while the mutant declares `expected_mover: rule_test`, the mutant is `survived`.
If `rule_test` changes, the mutant remains `killed`, including when a neighboring
test also changes. A test failing in both runs does not witness a change.

The existing `how` field names the expected and observed changed tests for this
attribution; `moved` retains its existing batch-outcome meaning. No new report
field is added. Manifests without `expected_mover` keep their existing results.
Controls, module/process runners, JSON batch outcomes and empty or non-string
names refuse the field. Identity is not inferred from messages, coverage or
source. Termination kills remain unchanged because they have no parsed test-name
tuple; this option makes no attribution claim for them.

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

A diagnostic move never overrides a declared exclusion. `silent` says *the
corpus claims this rule and its pinned outcomes cannot see it*, and neither an
`out_of_scope` mutant nor an acknowledged known hole is making that claim, so
both keep their own verdict and stay unscored even when the diagnostic channel
moved. The row carries `moved_diagnostic` and says so in its `how`, because the
verdict alone would hide it. Only an in-scope, unacknowledged mutant becomes
`silent`. Outcome movement is unaffected: it still kills, and killing an
acknowledged rule still retires the acknowledgement.

`silent` sits in the denominator and is diagnostic-only and never the numerator.
That reading is only that the declared mutation moved the diagnostic channel
and not the declared outcome on the pinned inputs after a valid run. It is
named separately because the repair differs — a survivor needs a vector that
moves an outcome, a silent mutant may instead mean the corpus should declare
its diagnostics part of the pinned surface.

The two selectors may not name the same member: a member read as the outcome can
never produce a silent-only move, so the class would be unreachable and the
manifest would read as covering more than it does. That is a controlled refusal.
`diagnostic_from` needs a JSON outcome and is refused beside
`outcome_parse: test-names`, where the names *are* the outcome.

Every member a selector declares must be one the unmutated implementation
actually emits, and that rule is the same for `outcome_from` and
`diagnostic_from` because the defect is the same: a member nothing emits compares
`None` to `None` on every mutant. On the outcome it makes the score
over-generous; on the diagnostic it makes `silent` unreachable while the report
still says the channel was declared. Either one fails the run, and a partially
present selector fails on the members that are missing.

Without `diagnostic_from` the class is unreachable, so `"silent": 0` in a report
means it was not measured, not that none exist. The report says which by carrying
`diagnostic_channel_declared`. Both fields are on every report, including the
module runner's, which refuses the channel and therefore always reports
`0` and `false` rather than omitting them.

`hole_ratio` divides by the same denominator the score does,
`killed + survived + silent`, so the two numbers in a report describe the same
set of rules.

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
[`49953e94d563db1d5e16b349cf7f84f09db91309`](https://github.com/Rul1an/assay/commit/49953e94d563db1d5e16b349cf7f84f09db91309),
under that repository's MIT license. The root `LICENSE` is that upstream text,
including the copyright notice, copied without alteration.

That commit is on `main`, and it is the one that completes the extraction: it
stops vendoring the measurement upstream and consumes this repository instead.
The working commit it squashes, `78c792f574e882aad683b690bfbff5445774056e`, was
this document's anchor until 2026-09-07. It is retained upstream: its patch never
landed on `main` in that form, but the commit itself remains reachable through the
merged pull request that carried it, independently of whether the branch is later
deleted. The anchor is the merge because the merge is what `main` records, and the
working commit is named beside it so a reader can line the two up.

The move is an extraction rather than a copy: two implementations of a
measurement drift, and the copy that drifts is the one that stops measuring.

Its own findings on the corpora it was built against, including the unflattering
ones, are published in that repository's `conformance/INDEX.md`.

## One report shape

Every runner returns the same `corpus-adequacy.report.v0` keys, built by one
private projector that both constructors call. A report names its own producer
in `runner`, so a consumer never has to re-read the manifest to learn which
runner made it.

Successful JSON reports have one producer-owned byte form: UTF-8, keys sorted,
two-space indentation, and one trailing LF. `encode_report_v0()` is the only
serializer for that form. It refuses `corpus-adequacy.error.v0`, so a failed
measurement cannot be addressed as a successful report by the same function.
A lone Unicode surrogate cannot be valid UTF-8; the CLI refuses it through the
existing exit-2 `error.v0` path rather than replacing bytes or printing a
traceback. Valid Unicode remains unescaped UTF-8.

`manifest_sha256` is SHA-256 over the exact manifest bytes read and parsed at
the start of the run. No JSON canonicalisation occurs: changing whitespace or
key order changes the digest because it changes the governed input bytes.
This provides content addressing and an integrity check. It is not a signature,
an authenticity claim, or proof that the manifest declared every rule.

`control_status` directly reports `killed`, `survived`, `moved`, `error`, or
`absent-or-invalid`; a consumer does not reconstruct it from mutant rows. The
same producer rule emits each control row and its status. With multiple controls,
`error` takes precedence over `absent-or-invalid`, which takes precedence over
`survived`, then `moved`, then `killed`. A healthy inert control reuses the healthy
aggregate `killed` token and emits a `control-unchanged` row; a moved inert control
emits `control-MOVED`. The aggregate compares the number of observed controls with
the number declared; a stale, unloadable or otherwise unmeasured control therefore
yields `absent-or-invalid` instead of a partial `killed`. The existing structural
guard still makes that report inadequate. `report.v0` gains no field and manifests
without an inert control retain their existing report behavior and bytes.

`originals_unverified_against_head` is required on `process` and `batch`
and forbidden on `module`: those runners guard a working tree and always
emit the field (`[]` when nothing is unverified). The module runner has
no such guard, and a field present-but-meaningless there would be worse
than an absent one.

The module runner refuses `diagnostic_from`, so its `silent` is always `0` and
its `diagnostic_channel_declared` always `false`. Both are reported rather than
omitted, so a consumer can tell a measured zero from an unmeasured one.

This is shape and encoding parity. It says nothing about whether two runners
measuring the same corpus would agree, and nothing about adequacy, completeness
or safety.

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
stronger on ground truth: it requires **at least one positive control mutant** and
voids the entire run if one survives, which the forcing gate has no counterpart for.
All-survivors because a corpus is weak and all-survivors because nothing was
measured print identically, and only a positive control separates them. An inert
control adds the inverse metamorphic check: a declared semantically neutral
transformation must not move the pinned outcomes. It does not prove semantic
discrimination, infer equivalence, or replace a positive control.

With [Maaz Ahmed](https://github.com/MaazAhmed47)’s permission, a private candidate workflow was exercised against four owner-confirmed effective-permission rules at [Interlock](https://getinterlock.dev) snapshot bec2e8f0aa8c6c962333947a5b673182eab9e99e. Maaz confirmed the factual rule mapping and required this interpretation boundary: ‘distinguished’ means only that the named mutation changed the declared projection for the fixed private probe set. No Interlock source, mutations, per-rule results, denominator, score, or product-wide claim is published. This is not an audit, endorsement, or partnership.

## Trust boundary

The assets, trusted computing base, mechanisms and residual risks of the three execution routes are collected in [docs/threat-model.md](docs/threat-model.md); this section remains the authority on behaviour.

A manifest is executable trusted input: an author declaration, not independent evidence. 100% is 100% of what that author declared. Do not run a manifest you do not trust. A third-party manifest is not independent evidence merely because it was written elsewhere.

That the tool itself uses no network does not mean a child or a manifest cannot. Every runner starts a child: `runner: module` loads the corpus in a disposable child process of this tool, while `process` and `batch` run the commands the manifest names. The module child is bounded by one deadline, one output ceiling and a POSIX process-group kill, which is trusted-local process isolation. Direct-child failure is classified by role: observed abnormal termination (timeout, output-cap, unexpected-exit, signal) of an ordinary mutant's child is a named kill. On the module runner, an unusable protocol result (empty output, parse error, incomplete) is `unproved` and never a kill. On process and batch, a declared `unproved_exit_codes` exit from a living adapter is inner incompleteness and is `unproved`; direct-child parse-error and incomplete are `unproved` as well. Baseline or control child failure invalidates the score (no adequacy result). Same-user parent signalling (e.g. `kill(getppid())`), session escape and host resource exhaustion remain outside the process-isolation claim. The child inherits this process's filesystem, network, environment and credentials, nothing bounds its memory or its descriptors, and its protocol channel is not authenticated against a corpus written to forge a verdict. Isolation and least privilege are the caller's job; this is not a sandbox.

Execution profiles are a closed, operator-owned set: `trusted-local`, `contained-oci-v0` and `contained-oci-v1`, ordered in that strength and independent of runner (`module`, `process`, `batch`). The operator selects the profile; a candidate manifest may state only `minimum_execution_profile`. Downgrade is refused, so `contained-oci-v0` below a `contained-oci-v1` minimum refuses. Neither contained profile falls back to local execution or runs the module runner. `contained-oci-v1` is executable only through the sealed route, with a backend that declares its profile (#102): the engine never tells a backend which profile it resolved, so the backend declares the one it was built for and the engine compares the two before the first call. A `contained-oci-v1` run whose backend declares no profile is refused, and so is any contained run whose backend declares a profile other than the resolved one; a `contained-oci-v0` backend may still declare none, as every v0 caller did before. Those refusals, the module-runner refusal and the contained-to-local refusal each carry their own message. The sealed runtime's backend declares the profile the driver built it for and passes that same profile to candidate admission. `contained-oci-v1` carries no applied CPU, file-descriptor or other containment claim: its envelope records the configuration the daemon reported, not limits shown to be applied by the kernel. The external hosted route stays `contained-oci-v0`; a separate repository-owned `contained-oci-v1` rail uses only the first-party frozen candidate and corpus. `contained-oci-v0` is one inspect-verified Linux/Docker envelope, not complete sandboxing and not author authentication. `report.v0` does not record the profile. Every `run` and `_run_process` call must name `execution_profile`; omission is `TypeError`, not a trusted-local run.

A `contained-oci-v0` run leaves one sibling `envelope.v0` record beside the report, never inside it: `report.v0` is unchanged, and so are `prepare.v1`, `survivors.v0` and every published byte. The record keeps six states separate and closed — the requested profile; `setup_status` (`ready|unavailable|refused`); `envelope_status` (`verified|unverified`, naming the observation that was missing or contradicted); `candidate_outcome` (`completed|timeout|output-cap|unproved|not-run`); `cleanup` (`removed-and-absent|remove-failed|absence-unproved`); and a derived `publication_permission` (`permitted|withheld`). There is no `degraded` state: `contained-oci-v0` has no optional containment axis, so a missing or contradicted required field is `unverified` and the run is withheld. A completed candidate followed by a failed absence proof is still recorded as completed, and cleanup success never revalidates a refused setup. A completed candidate run whose inspect reports `State.OOMKilled: true` is unproved with the closed reason `oom-killed-reported`, whatever its exit code, and its inner report is not read (#102): the daemon reported an OOM kill in the container's cgroup during the run, from the container's memory limit or a host-wide OOM, so the result is named rather than scored and is never a mutant kill. A run whose contained setup never became ready (unavailable or refused) is unproved with the closed reason `setup`; before #102 C that reason was not in the closed set and such a run was reported as `malformed`. It is not proof that the measured process was the one killed; `false` or an absent or non-boolean value licenses no inference, so exit 137 (also `docker stop`'s SIGKILL) stays `inner-exit`, a deadline stays `timeout`, PID and `nofile` exhaustion stay cause-unobserved, and CPU throttling is not a cause. The envelope does not carry the observation: its `candidate_outcome` is `unproved` as for any unproved run, and the report's unproved reason is what names it.

Effective values come from one observation-only projector over `docker inspect` and the runtime version observed for that run. A second signal sits beside it: every stderr line `docker create` printed (moby reports a discarded limit only as a create-time warning, and its swap warning never says "discarded") makes a recorded envelope `unverified` as `create_warnings`, checked after the comparator so a more specific field keeps precedence; a transport that reports no create observation is unverified the same way, and the warning text itself is not recorded. PREPARE's probe runs do not judge create warnings, so a runner whose daemon discards a requested limit passes phase 1 of the hosted route and is withheld only at phase 3; the unverified envelope names the field to triage from (`memory_swap`, `pids_limit`, `cpu_period`, `create_warnings` and so on). For the requested limits every moby discard also changes the stored config, so the comparator's field usually names it first, and `create_warnings` adds only warnings without a stored-config trace or other stderr lines. No requested or declared value reaches it, no accessor there supplies a default — an observation the daemon did not make is `unverified`, not an empty value that satisfies a requirement — and PREPARE's inert-probe evidence cannot stand in, because it describes a different image and resource profile. Environment is recorded as a sorted set of names, never values, and is held against the pinned image's own observed environment. Mounts are a complete inventory, so absence of a Docker socket or a writable source mount is assertable rather than assumed. Versioned resource/PREPARE codecs (`resource-profile.v2`, `prepare.v2`) serve `contained-oci-v1`. The `prepare-v2` command emits canonical `prepare.v2` bytes through the same production PREPARE path and frozen v2 resource policy; it prepares inputs and inert probes but does not execute the candidate. The external v0 lane does not select `contained-oci-v1`; the separate repository-owned rail selects it through a fixed facade and a distinct workflow, packet namespace, concurrency group and artifact namespace. Acceptance and admission differ, and the two must not be read together: the authorizer's `load_prepare` (`measurements/aee_checker_sealed_authorize.py`) accepts a `prepare.v2` document alongside v1 and both public authorize entrypoints reach it, while execution admission is selected by profile: `aee_checker_sealed_execute.py` and `aee_checker_sealed_driver.py` each take a required `execution_profile` and, after authorization and before any effect, admit through the one dispatcher (`load_prepare_for_profile`) only a `prepare.v1` under `contained-oci-v0` and only a `prepare.v2` under `contained-oci-v1`. A v2 document authorized for a `contained-oci-v0` run therefore never reaches execution, and a `prepare.v1` is never read as CPU- or descriptor-limited. A v2 profile can encode an aggregate cgroup CPU rate and per-process `nofile` limits, which is an encoding and not an applied or observed ceiling; the wall deadline stays separately enforced. Daemon-reported kernel and cgroup identity is observed by the versioned execution-envelope reader described below; it is daemon evidence, not cgroup introspection. Historical v1 records retain it and new `contained-oci-v1` runs emit it in v2, which the separate repository-owned v1 rail selects without changing the external v0 route. `publication_permission` is enforced only by the hosted contained publication gate (`measurements/contained_hosted_publication.py`, used by workflows `contained-hosted-publication` and `owned-contained-v1-publication`): the lane probes Docker readiness and, when authorize/prepare/pins packets are present under a packet root confined beneath the checked-out workspace (in the hosted workflow, the fixed `hosted-packet/` directory filled by the fetch step described below and bound by its manifest digest), invokes the sealed contained-oci-v0 driver to produce an effective envelope after sealing dispatch bindings into prepare/envelope checks (`prepare.pins.subject_commit` equals `candidate_revision`; envelope `prepare_sha256` binds checked prepare bytes); inputs resolve through one confined-path helper with pre-parse byte ceilings and canonicalized path comparisons; setup, effective-envelope, candidate-result, rerun-evidence and withheld-diagnostic are separate uploaded artifacts, and their upload conditions differ by role: setup, candidate-result and rerun-evidence upload with `if: always() && !cancelled()` so a refusal stays observable, the withheld diagnostic package uploads with `if: always() && !cancelled() && steps.gate.outcome == 'failure'` (attempt-scoped name; `if-no-files-found: error`), while the effective-envelope collection uploads only with `if: steps.gate.outcome == 'success' && !cancelled()` -- publication of the collection is authorized by the gate step succeeding, and the gate exits 0 only on a `publish` decision (2 on a refusal, 3 when a run ends withheld or unavailable after writing its stubs), so a refused or withheld run, or one whose quarantine failed, cannot publish permitted members and fails with a named reason rather than on a missing upload. That is an upload authorization boundary, not a claim that a refused operation was clean (the `effective-envelope` artifact is the **collection directory** `effective-envelope-collection.v0/` -- its exact index plus every addressed member byte, which is the authoritative record; the legacy single `effective-envelope.v0.json` is written only as a refusal stub and never carries a collection document, and any stale copy is removed rather than reused. `envelope_collection.py` and `candidate_diagnostics.py` are inside the closed inner execution identity inventory, and only the adapter selected by the code-owned measurement contract is loaded before candidate effects, so a change to any selected inner source requires a fresh PREPARE; the full runner and workflow revisions separately bind hosted orchestration outside that inner content digest; no PREPARE or hosted execution is claimed here) (rerun upload named with run id/attempt; missing required files stay `if-no-files-found: error`; post-execute refusals write withheld/void/refused stubs and commit a closed `withheld-diagnostic-package.v0/` (manifest plus an optional byte-preserved `collection/`, never a second publication format) so no permitted member is published; the observations are retained verbatim as diagnostics, not rewritten; `contained_hosted_publication.py readback` validates those four downloaded artifacts without Docker, fetch, dispatch, score or publish); unavailable containment is void with no score; publication requires both `publication_permission: permitted` and `envelope_status: verified`; child-environment observation comes only from the contained OCI effective envelope (YAML `runner.environment`/`runs-on`/`persist-credentials` remain structural pins); reruns append evidence with run-attempt identity. Hosted residual ceilings are concurrency group `contained-hosted-publication` (cancel-in-progress false), 14-day artifact retention, 5 MiB artifact/input size and a 30-minute job timeout on a pinned `ubuntu-24.04` runner (the 300 s materialize deadline plus nine 120 s candidate invocations is 1380 s, 23 minutes; the rest covers setup, the packet fetch and uploads). Hosted intake is not hosted execution. A `trusted-local` run has no envelope, and that absence stays legacy rather than being read as contained or as failed.

The external hosted route (#107) runs in three phases, all on `contained-oci-v0`. The separate repository-owned `contained-oci-v1` rail reuses those canonical loaders, packet bindings, execution funnel and publication decisions under disjoint workflow and artifact identities; adding the rail is not a contained run or applied-limit proof. **Phase 1, hosted PREPARE.** A `workflow_dispatch` of `contained-hosted-prepare` on a tag that points at the runner revision R checks out that dispatched ref (`persist-credentials: false`, `contents: read`) on a pinned `ubuntu-24.04` runner, runs `aee_checker_sealed_run.py prepare-v1` against R's in-tree pins, and uploads two attempt-scoped artifacts: the `prepare.v1.json` bytes, and a `hosted-prepare-record.v0.json` holding their SHA-256 beside `GITHUB_SHA`, `GITHUB_WORKFLOW_SHA`, `ImageOS` and `ImageVersion`. That workflow has no driver, execution-funnel or gate step, so no candidate, baseline, control or mutant runs in it. **Phase 2, owner authorization, off the runner.** The owner checks the prepare bytes against the recorded digest (this proves transport only, because the same job computed it), checks `prepare.execution.commit == R` and the toolchain record, emits `authorize.v0` with the existing emitter, and publishes `authorize.v0.json`, `prepare.v1.json` and `hosted-dispatch-bindings.v0.json` (`image_digest` = `prepare.toolchain.image_id`, `candidate_revision` = `prepare.pins.subject_commit`, `runner_revision` = R) as assets of an immutable release, with one manifest asset, `hosted-packet-manifest.v0.json`, that lists each of those three files' SHA-256 (schema `corpus-adequacy.hosted-packet-manifest.v0`, keys `files` and `schema` only). The pins are not shipped. **Phase 3, hosted execute.** `contained-hosted-publication`, dispatched on the same tag, takes `candidate_revision`, `runner_revision`, `image_digest`, `packet_release_tag` and `packet_manifest_sha256`; the former `packet_root`, `authorize_path`, `prepare_path` and `pins_dir` inputs are gone because the packet location is now fixed. A fetch step (`measurements/hosted_packet.py fetch`) refuses unless `hosted-packet/` is absent on disk and untracked in R's checkout, downloads only from `github.com`, following at most two HTTPS redirects and only to `release-assets.githubusercontent.com` (the host GitHub's hosted-runner documentation names for downloading release assets; any other host, port or userinfo refuses), downloads the manifest under its own byte ceiling and compares its SHA-256 before parsing it (exact keys, duplicate keys refused, exactly the three names, and any name refused that is absolute or contains `..`, a path separator or a control character, or would leave the directory), downloads each listed asset individually under a per-file ceiling with no archive extraction and holds it to its digest, copies the pins from R's `measurements/aee-checker-25b9dfa/`, and only then writes, each file created new and regular and nothing outside that directory. The gate is then called with `--packet-manifest-sha256` and the fixed root and paths, and binds the packet again in its own code: the manifest digest before any parse, every listed file's digest, the authorize and prepare roles, and no entry the manifest does not list. It also refuses unless `GITHUB_SHA == GITHUB_WORKFLOW_SHA == runner_revision`, read from the runner's environment (an absent value refuses), and records both, with `ImageOS` and `ImageVersion`, in the rerun evidence and the setup artifact. Because the packet is untracked and outside the execution identity paths, PREPARE's `execution.commit` and the gate's `runner_revision` can both be R. A runner-image change between the phases changes `toolchain.image_id` and the driver's equality check refuses, which is the fail-closed direction. Non-claims: a successful run of this route is one contained v0 execution of the pinned first-party checker against the pinned corpus with a verified effective envelope. It is not authentication of the corpus or release author, not endorsement or certification, not an escape-proof sandbox, and not a CPU or file-descriptor bound. PREPARE's inert-probe evidence is observed on the phase 1 VM and is not re-observed on the phase 3 VM; phase 3's containment evidence is its own effective envelope, which is daemon-reported configuration, not kernel-applied limits. No hosted workflow is dispatched by this repository's CI; each phase on either rail needs an explicit owner dispatch. On a publish decision the owned rail also writes the canonical `report.v0` bytes as `report.v0.json` and uploads them as `owned-contained-v1-report` under the same gate-success condition as the verified collection; the gate refuses bytes that do not round-trip canonically or do not hash to the digest the collection and candidate result carry, and `readback --report` repeats those checks and compares the candidate's `control_status`, `unproved` and `adequate` with the report. This is first-party evidence about the owned fixture only; the external workflow uploads no report (#186). The owned rail pairs `prepare.v2` only with `contained-oci-v1`, derives the same closed packet bindings under its own v1 manifest schema, and publishes only the same bounded artifact roles under owned names. Its fixed `authorize-packet` owner step validates the downloaded PREPARE bytes and attempt record, derives the closed bindings from the canonical document, and atomically assembles the release assets; it does not fetch, publish, dispatch, call Docker or execute the candidate.

**Archiving a terminal attempt (#188).** Artifacts expire with the repository's retention setting, and from 2026-10-01 workflow runs do too, so the owner may keep a terminal attempt's bytes as assets of an immutable release. The asset set is the artifact ZIPs exactly as the Actions API served them, the API records for the run, its jobs and artifacts, the run log, and one `SHA256SUMS`. The tag is `<rail>-terminal-<run_id>-<attempt>`, annotated, at the runner revision, and the release notes name the run, attempt, runner revision, packet manifest digest and decision, and repeat the artifacts' non-claims. The first one is `aee-contained-v0-terminal-35194072925-1`. Steps, all off the runner: `python3 scripts/terminal_archive.py sums <dir> --write`, then `check <dir>`, create the release as a draft with the assets, compare the draft's asset digests with `SHA256SUMS`, and publish. A reader downloads the assets (`gh release download <tag> -R corpus-adequacy/corpus-adequacy -D <dir>`), runs `python3 scripts/terminal_archive.py extract <dir> <dest>`, and then `contained_hosted_publication.py readback` from a checkout at the runner revision with `--setup <dest>/setup/setup-status.json --candidate <dest>/candidate-result/candidate-result.json --rerun <dest>/rerun-evidence-<run_id>-<attempt>/rerun-evidence.jsonl --collection <dest>/effective-envelope` and the attempt's bindings. Archiving is an owner action per attempt and never a workflow step, and extending the visibility of an external corpus's run past the window its owner was told is the owner's decision, announced to that corpus owner. A set that does not check is refused as it is, not repaired in place. An archive preserves bytes; it adds no verification, authentication or claim.

**External candidate result (#184).** On the external rail the gate writes `corpus-adequacy.aee-contained-v0.candidate-result.v1` whenever a publish or withhold decision comes with a report that the collection binds and that passes the projection checks: the historical keys plus `report_sha256` (the SHA-256 of the canonical `report.v0` bytes, equal to the collection index), `control_status`, `unproved` and `outcomes` (one `{ordinal, candidate_outcome}` per collection member). It never carries `adequate`, verdict counts, failures or per-site verdicts, because the external corpus owner consented to no score and no per-mutant result, and its `decision` is the envelope decision, not a function of the report. A publish decision without a report refuses as `candidate_report_absent`; a report that does not hash to the collection's digest, or whose counts are inconsistent, refuses through the post-execute refusal path with its own reason; a withheld run without a report keeps the void result. The historical `corpus-adequacy.hosted-publication.v0` shape, which carries no report digest, is no longer written and stays readable for retained bytes. On a publish readback the carried digest must equal the collection index and the carried outcomes must equal the members, and `readback` prints `candidate_result_schema`. Carrying the digest commits to report bytes that are not published; it does not publish them.

**Sealed attempt statement (#187).** After the gate, on every gate outcome, the external workflow runs `contained_hosted_publication.py seal`, which writes `artifacts/attempt-statement.v0/`: `SHA256SUMS` (shasum text-mode lines, one per file of the upload surface: `setup-status.json`, `candidate-result.json`, `rerun-evidence.jsonl` and every file of exactly one of `effective-envelope-collection.v0/` or `withheld-diagnostic-package.v0/`; the materialize tree, a quarantined collection and the refusal stub are not subjects), `hosted-attempt-predicate.v0.json` (closed keys: the three bindings, the five dispatch inputs, run id and attempt, `GITHUB_SHA`/`GITHUB_WORKFLOW_SHA`/`ImageOS`/`ImageVersion` as the runner reports them, the gate step's outcome, the subject count and the SHA-256 of `SHA256SUMS`), and `hosted-attempt-statement.v0.json`, the in-toto Statement v1 with those subjects and that predicate under `predicateType` `https://github.com/corpus-adequacy/corpus-adequacy/attestations/hosted-attempt/v0`. The directory is uploaded as `attempt-statement-<run_id>-<run_attempt>` and a SHA-pinned `actions/attest` step signs the same `SHA256SUMS` and predicate with the workflow's Sigstore identity (the certificate carries the run invocation URI and the trigger), which is why the job holds `id-token: write` and `attestations: write`; `contents` stays read and no step gains write access to the repository. Offline, `readback --statement <dir>` requires the three files to be one canonical set, the predicate's bindings and run identity to equal the reader's expected values, and every subject to be exactly one downloaded file with the same bytes, and reports `statement: verified-unsigned`; it never verifies a signature. To verify the signature: `gh attestation verify <file> --repo corpus-adequacy/corpus-adequacy --predicate-type https://github.com/corpus-adequacy/corpus-adequacy/attestations/hosted-attempt/v0 --signer-workflow corpus-adequacy/corpus-adequacy/.github/workflows/contained-hosted-publication.yml` for any subject file, or `gh attestation download` first and `--bundle` for offline use. A signed statement authenticates the workflow that produced the bytes, not the candidate author, the corpus owner or the operator's intent, and proves nothing about containment or adequacy; the seal changes no decision and no artifact byte. The repository-owned rail seals the same way through its fixed facade (`owned_contained_v1_hosted.py seal`, into `owned-contained-v1-artifacts/attempt-statement.v0/`, uploaded as `owned-contained-v1-attempt-statement-<run_id>-<run_attempt>` and attested with `--signer-workflow corpus-adequacy/corpus-adequacy/.github/workflows/owned-contained-v1-publication.yml`); its subject set adds `report.v0.json` when the run published one, so its `readback --statement` needs `--report` for a published attempt. The predicate names the rail, and `readback` refuses a statement sealed for a rail other than the one the setup artifact names.

**Attempt attribution (#185).** A collection written since #185 has a v1 index whose ledger rows name the step the engine ran (`step`: `kind` build, baseline, control or mutant, the manifest `group` and mutation `id`), the candidate return code the runtime observed, one per-collection `run_nonce`, and the digest of the preceding recorded member (`previous_member_sha256`), recomputed on load. The engine hands `step` only to a backend that declares `accepts_step = True`, and refuses any other declared value before calling it; the sealed runtime declares it. On the publish path the hosted gate and `readback` require those steps to be the rail's authorized steps (from its digest-checked pinned sites) in authorized order, starting with the baseline and with every declared control before any mutant (the engine's control barrier runs no ordinary mutant otherwise), and `readback` prints them as `step_attribution`. Members are unchanged, so the attribution lives in the index only; a v0 index is read as before and reports `not-carried`. The nonce names this index, not its members, and does not make a byte-identical member from another run detectable. The record states the envelope one Docker daemon reported for one container on one host at one time. `docker inspect` is the daemon's own account of its own configuration. This is not a sandbox-completeness claim, and it does not prove kernel or runtime escape resistance, absence of side channels, an uncompromised daemon or operator, candidate authorship or candidate correctness. Kernel, seccomp/AppArmor content, cgroup introspection and CPU/FD ceilings stay outside it. The hosted lane's concurrency, retention and artifact-size ceilings are operator policy for that lane only; they are not authentication, endorsement, audit, certification, escape-proof OCI, or a third-party quality score.


Observe O adds versioned execution-envelope readers and builders.
Default construction and every `contained-oci-v0` run still emit v0. Historical v1
records remain readable byte-for-byte. A new `contained-oci-v1` run emits v2, whose
requested and daemon-stored tmpfs objects bind `rw`, explicit `exec`/`noexec`, mode,
uid, gid, byte size and inode count. The uid and gid are derived from the same closed
`CONTAINED_USER` value passed to Docker; malformed, duplicate, unknown, incomplete or
contradictory stored options refuse. `report.v0` is unchanged. Collections accept all
three versions through the same semantic validator and preserve member bytes/version
when binding a report. V1 and v2 records inspect CPU
period/quota, `NanoCpus` and nofile settings plus daemon kernel/cgroup/security observations;
under a v0 request these additional observations are shape-checked, not compared to v0 requested limits.
Under a `contained-oci-v1` (`resource-profile.v2`) request the daemon-stored `CpuPeriod`,
`CpuQuota` and nofile soft/hard are compared exactly against the request, and `NanoCpus` must
also be stored unset (0), since moby refuses it beside a CFS period; this is still
daemon-reported configuration, not a limit the kernel applied. The tmpfs object is
also Docker's stored configuration, not filesystem-stat evidence or proof that the
kernel applied the requested owner or mount flags.
Zero CPU values or null nofile mean only those named settings were reported unset,
not that inherited or other limits are absent. Missing observations refuse rather
than borrowing requested values. Synthetic fixtures establish expected daemon wire
names, not live Docker fidelity. No hosted v1 execution, applied-limit proof or source authentication follows from the reader alone. This is not a sandbox-completeness claim.
These execution-identity source changes require a fresh PREPARE for later execution;
no PREPARE is regenerated by this slice.
