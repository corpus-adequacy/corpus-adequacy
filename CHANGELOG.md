# Changelog

## Unreleased

`adapters/tersign_evidence_record.py` adapts one pinned Tersign evidence-record
checkout (`tersignhq/evidence-record-conformance` at
`1cc5ea32b3da4f195b55782c8a3573d8564673a7`) into `vectors.json`, exact-byte
`cases/`, and `source.json`. Kind stays metadata. The typed outcome is
`(expect, reason|null)`. Reads reuse `read_bounded_regular_file` and the
existing strict JSON parser. On Windows that reader and the adapter writer
set `O_BINARY` so newline translation cannot change the pin. Adapter failure
exits 2. This is not a Tersign partnership, certification, or a claim that
the wrapper makes the whole suite two-sided. Reason completeness is only the
pinned manifest. No release.

`--survivors` projects `corpus-adequacy.survivors.v0` from an existing
`report.v0` file: survived and silent rows become bound rule findings with a
verdict-specific discrimination obligation. `encode_survivors_v0` is its own
encoder (UTF-8, sorted keys, two-space indent, trailing LF) and never calls
`encode_report_v0`. Report and optional manifest inputs go through one bounded
regular-file / no-follow reader; the existing `OUTPUT_CAP_BYTES` ceiling is applied before `json.loads`.
An `anchor_excerpt` is emitted only when SHA-256 of the exact manifest file
bytes matches `report.manifest_sha256`. Oversized anchors are omitted with a
typed reason. `report.v0` bytes, `_report_v0`, `encode_report_v0`, plain
`--json`, measurement exits and VERSION are unchanged. No `report.v1`.

On platforms without `O_NOFOLLOW`, the same reader falls back to
lstat/open/fstat identity parity and still refuses a symlink or
non-regular path. Reads loop until EOF or cap+1. `--manifest` without
`--survivors` exits 2. Hostile report or mutant shapes raise instead of
KeyError or an empty projection.
A digest-matched `--manifest` is parsed by the same strict JSON reader
and typed before anchor lookup, so a list-shaped `mutants` map exits 2
without a traceback. Duplicate keys and non-finite numbers are refused
there too.
Deeply nested projection JSON is refused as ManifestError instead of
leaking RecursionError. Raw anchor size is measured before
control-stripping, so an oversized control-only anchor is omitted as
oversized. Report schema is checked once in `_require_report_rows`; the
CLI no longer repeats it.


Successful `corpus-adequacy.report.v0` output now has one deterministic
`encode_report_v0()` byte form: UTF-8, sorted keys, two-space indentation and
one trailing LF. The JSON CLI uses that encoder, while `error.v0` is explicitly
refused by it. Reports carry `manifest_sha256` over the exact manifest bytes
read and parsed for the run; whitespace and key-order changes therefore change
the digest. This is content addressing and integrity checking, not authenticity.
A lone Unicode surrogate is refused through the existing exit-2 `error.v0`
path; it is neither replaced nor emitted as invalid UTF-8. Valid Unicode remains
raw UTF-8.

Reports also carry producer-owned `control_status` (`killed`, `survived`,
`error`, or `absent-or-invalid`). One rule emits both the control row verdict
and its direct status, so consumers no longer scan rows and independently
reconstruct the answer. Completeness is checked against one declared-control
count, so an unobserved stale, unloadable or otherwise unmeasured control reports
`absent-or-invalid`; the precedence is error, absent-or-invalid, survived, then
killed. The existing score, verdict precedence and exits remain unchanged, apart
from encoding failures now using the existing exit-2 error envelope.

One private `_report_v0` projector now builds every `corpus-adequacy.report.v0`,
and both the module and process/batch constructors call it. Module reports carry
`runner` for the first time, so a consumer no longer has to re-read the manifest
to recover it; `runner` is read from the manifest rather than passed, since
`load_manifest` always populates it. The projector owns the schema, the common
fields, the derived denominator, `hole_ratio`, `declared_total`,
`out_of_scope_ratio`, `adequate`, one shared `score_means`, and the single
`_with_tool_identity` call. `originals_unverified_against_head` remains a named
optional included only when supplied, so it stays specific to process and batch
rather than becoming a universal `None`.

Three expressions that had drifted between the two constructors converge, each
numerically inert because the module runner cannot produce a silent mutant:
module `declared_total` now includes `silent`, module `out_of_scope_ratio` now
divides by the same denominator as the score, and the module report carries the
same `score_means` text as process and batch. That text is longer than the one
module reports previously carried and now describes the silent semantics.

No `report.v1`, no schema change, no scoring, verdict, precedence, exit-code,
error-envelope or stderr change.

`tool_commit` is the 40-hex `HEAD` only when every declared runtime source
is byte-identical to `HEAD:<path>`, and `null` otherwise. Reports and
`--version` additionally carry `tool_source_state` (`exact` | `dirty` |
`unresolved`) and `tool_content_sha256` over an ordered, length-delimited
stream of the declared sources. The declared sources are re-read once the
comparison is done and any observed change fails closed, so a runtime file
edited while identity is being resolved is never reported exact. One producer
answers all three renderers, on the module and the process/batch report paths
alike; `git status` is not consulted. A modified runtime source is therefore no
longer attributed to the clean commit. This is not an attestation, a
signature, an SBOM, or a reproducibility claim.

A diagnostic-only move no longer overrides a declared exclusion. An
`out_of_scope` mutant stayed out of scope and an acknowledged current-digest hole
stayed a known hole only while the diagnostic channel was quiet; a move on that
channel reclassified either one as `silent`, which scored a rule the author had
excluded and told an author to delete a still-valid acknowledgement for a rule
that was still unforced. Precedence is now killed, then out-of-scope, then
known-hole, then silent, and the excluded and acknowledged rows carry
`moved_diagnostic` plus a `how` saying the diagnostics moved while the pinned
outcomes did not. Outcome movement is untouched: it kills, and it still retires
an acknowledgement through the existing linger guard.

Selector presence is one rule for every declared selector. A member the
unmutated implementation never emits fails the run whether it was declared on
`outcome_from` or on `diagnostic_from`, and a partially present selector fails on
the members that are missing. Previously only `outcome_from` was checked, so a
`diagnostic_from` naming a member nothing emits reported
`diagnostic_channel_declared: true` with `silent: 0` and no failure, which reads
as measured. `hole_ratio` now divides by the scored denominator
`killed + survived + silent` on every path, so it no longer disagrees with the
score's own denominator. Module reports carry `silent` and
`diagnostic_channel_declared`; runner identity remains absent there and stays
with issue #6.

A `silent` verdict separates a mutant that moves a declared diagnostic from one
nothing noticed. Declaring `diagnostic_from` beside `outcome_from` enables it:
moved in the outcome is `killed`, moved only in the diagnostic is `silent`,
neither is `survived`. Silent counts in the denominator and never the numerator,
because an implementer can still delete that rule and reproduce every pinned
outcome; it is reported separately because the repair differs. The two selectors
may not share a member, which would make the class unreachable, and the channel
is refused beside `outcome_parse: test-names`. Reports carry `silent` and
`diagnostic_channel_declared`, so a zero is distinguishable from not measured.
`child_outcome` and `_process_outcomes` return an additional diagnostic slot.

The README gains a Related work section. The measurement is not original to this
tool: the forcing gate in `astrogilda/aee-conformance` (2026-07-30) precedes this
tool's earliest ancestor (`rge-bench/scripts/check_rule_liveness.py`, 2026-08-10),
and the `silent` verdict is his SILENT class adopted with the name kept.

Child stdout and stderr are drained continuously through pipes. Combined
retained output stays at most `OUTPUT_CAP_BYTES`; two reader threads may
briefly hold `2 * READ_CHUNK_BYTES` in-flight before charge. Crossing the
cap kills the POSIX process group and raises `_OutputTooLarge`. A clean
exit reaps descendants but drains both pipes to EOF. Timeout remains
`TimeoutExpired` and outranks a reader failure. Temporary output files
are no longer used. On Windows, process and batch already refuse without
fcntl; this helper kills only the direct child and claims no process tree.

Process and batch outcome children are classified against
`accepted_exit_codes` (default `[0]`) before stdout is parsed.
`outcome_parse: test-names` is batch-only and requires `101`. JSON
`outcome_from` has no protocol ID; extra codes such as `2` are declared
explicitly, not inferred from a command name. Signals and `None` never
parse. An accepted code with malformed output remains a parse error. A
mutant unexpected-exit or signal may kill with that class named;
unmutated and control abnormalities fail closed with no score
(`control-error`, not `control-killed`), even when another mutant already
moved. This change does not migrate downstream adapter manifests; this
repository ships none.

Malformed manifest containers (`mutants`, `equivalent`, `known_holes`, and
their group or entry values) are refused by one shape rule as a controlled
manifest error. `--json` prints a parseable `corpus-adequacy.error.v0`
envelope on stdout and still exits 2, with no traceback. Nested
`known_holes[digest]`, `known_holes[digest][i]`, `equivalent[group]`, and
`equivalent[group][i]` wrong kinds are pinned at the CLI. A missing file
under `--json` uses that same envelope; human stderr is retained.

Mutant labels are unique across the manifest, including declared equivalents.
Duplicate acknowledgements for one corpus digest are refused before any
mutation starts. Acknowledgement, orphan, and stale-hole checks use the same
label identity. Malformed or empty labels now produce a controlled manifest
error instead of an unhandled hash-key exception.

Process and batch manifests now reject declared source paths that resolve
outside `repo_root`, including symlink escapes, and revalidate containment before
source access. Invalid roots and outside paths are rejected before probing source
existence. Source-guard documentation now states its abrupt-termination limit.
On platforms without fcntl advisory locking, process and batch runs refuse
before source copy, build, child, mutation, or score.

Process and batch mutation now happens in a unique disposable working-tree
copy of `repo_root`, not in the declared checkout. Dirty working-tree bytes
are measured. Symlinks and special files are refused fail-closed at
materialization. `.git` is omitted. File and byte ceilings apply during the
copy. Cleanup removes only that run's root after validation. There is no
stable pointer and no cross-run stale delete. `SIGKILL` may leave orphaned
temp bytes; they stay until the OS reclaims them, and the next run uses a
new root without auto-deleting the orphan. The copy is not an atomic
filesystem snapshot; concurrent external writes can produce mixed bytes.
Cleanup is best-effort. The ignored `_tree_is_dirty` Git status call is
removed. MaterializeHelper tests skip where `O_NOFOLLOW` is absent;
process/batch already refuse before materialize. A cross-platform pin
proves `_copy_regular_bounded` fails closed before creating the
destination when `O_NOFOLLOW` is None. The process/batch lock opens
without following or truncating a symlink. File copy is chunked so a
post-lstat grow cannot load past the ceiling. A `.git` entry of any type is
skipped before the type check. Files and directories share one entry
ceiling. Short `os.write` is looped; mode is set with `fchmod` on the open fd.
This is not a sandbox, not a git worktree, not the output ceiling, and not
HEAD-vs-dirty provenance.

## 0.1.0 — 2026-08-19

First named cut of the extracted tool.

Reports now carry `tool_version` and, when the checkout is a git repository,
`tool_commit`. `--version` prints the same pair. A measurement pinned by SHA
can quote the version it ran. Quoting a version is not a tag and does not
make the tag addressable; the tag is `v` plus VERSION, only after the cut
order (cut → dated heading → VERSION → tag).

Prior history is the untagged extraction commits on `main`.
