# Changelog

## Unreleased

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
