# Changelog

## Unreleased

Mutant labels are unique across the manifest, including declared equivalents.
Duplicate acknowledgements for one corpus digest are refused before any
mutation starts. Acknowledgement, orphan, and stale-hole checks use the same
label identity.

## 0.1.0 — 2026-08-19

First named release of the extracted tool.

Reports now carry `tool_version` and, when the checkout is a git repository,
`tool_commit`. `--version` prints the same pair. A measurement pinned by SHA
can quote the version it ran; a measurement quoted by version can be resolved
to the tag `v0.1.0`.

Prior history is the untagged extraction commits on `main`.
