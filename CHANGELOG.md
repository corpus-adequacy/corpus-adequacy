# Changelog

## Unreleased

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
before dirty check, source capture, build, child, mutation, or score.

## 0.1.0 — 2026-08-19

First named cut of the extracted tool.

Reports now carry `tool_version` and, when the checkout is a git repository,
`tool_commit`. `--version` prints the same pair. A measurement pinned by SHA
can quote the version it ran. Quoting a version is not a tag and does not
make the tag addressable; the tag is `v` plus VERSION, only after the cut
order (cut → dated heading → VERSION → tag).

Prior history is the untagged extraction commits on `main`.
