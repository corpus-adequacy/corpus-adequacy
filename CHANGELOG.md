# Changelog

## Unreleased

One shared JSON decoder (`load_json_document`) serves manifest, vectors,
and `corpus_digest_file`: RecursionError and declared root shape are
refusals (rc 2, `error.v0`, no traceback), including known_holes digest
deep/array/missing-key and a non-string digest value.
Declared vector keys are required. Vectors decode once, then dispatch on
object or array root. `--json` on `--survivors` uses `could not project`.
A within-cap empty-after-control-strip anchor stays an intentional
omission. Released 0.1.0 tool bytes through `_tool_content_digest` match
the frozen report `tool_content_sha256`. MEASURED_ON is report provenance,
not a required Git object or local tag. No `report.v0` byte or scoring
change.

## 0.1.0 — 2026-08-22

Publication listing is an opt-in `publications/index.v0.json`. Generation
binds report and source file digests, refuses symlink and count/control
parity mismatches, and `--check` compares the checked-in page without
writing. The form no longer claims a workflow recomputes machine fields.

The same projector now writes a run page and one rule page per
`survivor_findings` row, addressed by the report `mutants[]` index. Overview
cards link to `runs/{id}/`. Run and rule pages reuse one non-claims
renderer so a shared deep link still carries the four ceiling lines.
Card and run page reuse one counts renderer, including `silent_label`
and `diagnostic_channel_declared`. Membership is that projection only:
leftover unconsumed findings fail closed, and `how` is the validated
report field. Displayed counts must be exact `int` values; a present
`diagnostic_channel_declared` must be an exact `bool` (absent is false).
`--check` inventories regular files under `site/`. Only an exact `CNAME`
is left unmanaged; any other regular file outside `index.html` and
`runs/**` (including a regular file named `runs`) fails closed as surplus.
A FIFO, symlink, or device anywhere under `site/` is refused without
opening it. Generation writes expected
owned files and refuses pre-existing owned surplus instead of deleting.
No ranking, latest, or identity widening.

The AlgoVoi adapter's mechanism boundary is pinned against a whole-document
re-serialize, not only the per-preimage form. The previous probe used the
pinned fixture, whose round trip is byte-identical, so a scanner that
re-serialized the whole document before slicing satisfied it. The new probe
uses `1.50` and `1E2`, which move under any round trip, with a companion test
proving the probe discriminates.

The oversize refusal is pinned as an ordering, not merely as an outcome. The
read loop caps at `cap + 1` on its own, so a refusal alone was satisfied with
the `fstat` pre-check removed; `os.read` is now patched so zero payload reads
is the property under test.

`tests/test_algovoi_jcs_edge.py` runs the same tests under direct execution as
under discovery. Thirteen top-level statements followed the `__main__` guard,
so five classes were undefined when the module was run directly. The guard is
now the last statement, checked by AST for the structural rule and by
subprocess for the effect. The subprocess probe asserts count parity only:
asserting the inner run's exit status would make it fail for every unrelated
mutation and destroy per-guard ownership.

A stale comment claiming the exponent-overflow walk was held back is removed;
it landed in a2f723fe and the Tersign re-measurement landed in fd25f2e.

Test-only. No product or tool bytes change, so no re-measurement. No release.

`read_bounded_regular_file` opens non-blocking where the platform provides
`O_NONBLOCK`. A FIFO is openable and parks `open()` until a writer arrives, so
the `S_ISREG` check after it never ran and a special file hung the caller
instead of being refused. The flag has no effect on a regular file. Its test
raises a non-`OSError` alarm on purpose: `TimeoutError` is an `OSError`, which
the loader converts into a refusal, so an `OSError`-based alarm passes after a
real five-second block. Elapsed time is asserted as a second signal.

`_parse_projection_json` refuses non-finite numbers reached by exponent
overflow. `parse_constant` sees only the named `NaN` and `Infinity` tokens, so
a nested `1e999` or `-1e999` previously parsed as `inf`. One iterative finite
walk covers every runner and projection, iterative so a deep document cannot
trade a refusal for a `RecursionError`.

Both edits move declared runtime-source bytes, so the Tersign measurement was
re-run on the new tool bytes through its own producer command and its recorded
`tool_commit` and `tool_content_sha256` updated from that run. No digest was
transcribed by hand.

The AlgoVoi adapter now has a single provenance root. `PIN_SHA256` is removed:
the anchor digest is declared by the pinned manifest entry and the manifest is
bound to its own digest, so one constant carries the chain. The tests keep the
expected anchor digest as an independent literal oracle. `SOURCE_CAP_BYTES` is
pinned by a literal contract and the oversize fixture is sized from a literal,
so raising the constant can no longer raise the probe with it. The manifest
load is guarded behaviourally against symlink, oversize and FIFO rather than by
a source-text scan, and a duplicate invariant name is now a tested hard error.
No release.

The AlgoVoi adapter binds its provenance to loaded bytes. The pinned producer
`manifest.json` (SHA-256
`5e7c56fe353cd5c04adfc779191903d8cf79317301cc3402285a1881f1309865`) is vendored,
bounded-loaded through the same single call site as the anchor, and bound to its
own digest; version, canon version and license are verified against it, and the
anchor digest, vector count and invariant count are derived from its
`jcs_edge_v1` entry instead of being emitted as constants. The prose
`anchors_to` field is not parsed. `equal_sha256` now requires exactly two
references and raises `AdapterError` rather than leaking `ValueError`. Imports
are checked against an AST allowlist, so `from runner_python import run` and
dynamic import are refused. The end-to-end round-trip mutant preserves the
trailing LF, so it is killed by a normal parsed movement over all ten vectors
rather than by `unexpected-exit`, and the control row is asserted to move
exactly ten. No release.

`adapters/algovoi_jcs_edge.py` adapts one pinned AlgoVoi `jcs_edge_v1` anchor
set (`aa53149c670f1659dad511755168ad5231dc04de`, anchor SHA-256
`a8a1a1a8839553ea5309c381b39ba156e6b6a23a5a3e6aab59b53940cc386033`, 7,622
bytes, manifest `0.38.0`, canon `jcs-rfc8785-v1`) for the existing process
runner. Case bytes are exact source slices of each `preimage` value plus one
LF, so the `1.0` and `1` spellings survive; there is no numeric round trip. A
whole-document JSON round trip is byte-identical to this source, so the
mechanism boundary is pinned by its own tests rather than by output equality.
Ten vectors are emitted and consumed through the real `corpus_adequacy.run()`.
Both declared `pair_invariants` are accounted for exactly once: `equal_sha256`
is evaluated against the declared digests, and the prose relation is typed
`refused`. Upstream LICENSE and NOTICE are retained under
`fixtures/algovoi-jcs-edge-aa53149c/`. No new scorer, no generic JCS parser.
Not authenticity, endorsement, complete RFC 8785 coverage, correctness of the
authored labels or of the upstream reference implementation, or adequacy of any
implementation. No release.

The isolated Tersign CHECKS wrapper uses the same no-`O_NOFOLLOW` fallback as
`read_bounded_regular_file` (lstat/open/fstat `(st_dev, st_ino)` parity) without
importing the scorer. NOTICE absence is bound to the pinned upstream tree
`8003d51692a1e77d7bca8ec07015ca3c03c00242`. The claimed process run is the
durable `measurements/tersign-1cc5ea32/manifest.json` (`python3`,
`accepted_exit_codes` `[0]`). Report bytes are a later provenance commit.
No release.

`measurements/tersign_checks.py` is a process-runner wrapper over the pinned
Tersign verifier (`verify.py` / `keccak.py` at
`1cc5ea32b3da4f195b55782c8a3573d8564673a7`). It dispatches `CHECKS[kind](input)`
and emits `{verdict, reason|null}`. `accepted_exit_codes` is `[0]`. The declared
inventory includes the integral-float survivor, safe-integer reason drift, two
canonical-region controls, one unique mutation per remaining CHECK, and keeps
the masked boundary mutation as a measured survivor. The three `main()` suite
gates are omitted, not reported as survivors. No completeness, equivalence, or
release claim.

`adapters/tersign_evidence_record.py` adapts one pinned Tersign evidence-record
checkout (`tersignhq/evidence-record-conformance` at
`1cc5ea32b3da4f195b55782c8a3573d8564673a7`) into `vectors.json`, exact-byte
`cases/`, and `source.json`. Kind stays metadata. The typed outcome is
`(expect, reason|null)`. Reads reuse `read_bounded_regular_file` and the
existing strict JSON parser. On Windows that reader and the adapter writer
set `O_BINARY` so newline translation cannot change the pin. Case-file emit
calls the one public `isolated_tree.write_all` (the former private helper,
same function) so a short `os.write` cannot publish truncated bytes; zero
progress refuses and EINTR retries. That is a shared production change to
`isolated_tree.py`, a declared `TOOL_SOURCE_PATHS` member, so tool-content
identity is dirty against HEAD until this tree is the commit being
measured. Adapter failure exits 2. This is not a Tersign partnership,
certification, or a claim that the wrapper makes the whole suite
two-sided. Reason completeness is only the pinned manifest. No release.

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

Reports now carry `tool_version` and, when the checkout is a git repository,
`tool_commit`. `--version` prints the same pair. A measurement pinned by SHA
can quote the version it ran. Quoting a version is not a tag and does not
make the tag addressable; the tag is `v` plus VERSION, only after the cut
order (cut → dated heading → VERSION → tag).

Prior history is the untagged extraction commits on `main`.
