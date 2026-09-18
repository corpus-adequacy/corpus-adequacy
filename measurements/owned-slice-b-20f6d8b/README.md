# Slice B evidence, measured at `20f6d8b1fb99283ce70fd1d8f6016958df5d02b3`

A clean re-measurement of the Slice B pair from `measurements/owned-slice-b-5918ec4/`, taken so the
result can be published (#103). The earlier reports record an absolute manifest path, and the
publication renderer refuses exactly that since #208. These were produced by the fixed facade in
`measurements/owned_slice_b_local.py`, which runs the driver from the repository root with the
repository-relative pins directory, so each report's `manifest` field is a repository path.
Every byte here is pinned by `tests/test_owned_slice_b_evidence.py`.

| | declared | independent |
|---|---|---|
| Selection | `measurements/owned-contained-v1` | `measurements/owned-independent-v0` |
| Mutants | 2 ordinary, 1 positive and 1 inert control | 1 ordinary, the same two controls |
| Result | killed 2, survived 0, adequate true | killed 0, survived 1, adequate false |
| Control | killed | killed |
| `unproved` | 0 | 0 |
| Attempts recorded | 5 | 4 |

The results are the same as at `5918ec4`. So is every execution identity, because no execution path
changed in between. The two runs share the candidate toolchain image, the Docker runtime and the
materialized subject and corpus trees. Their execution identities differ only by the manifest path
each contract names. The inert probe image is built per PREPARE, so its host-local id differs by
construction; it is not the candidate image and runs no candidate code.

The two denominators are 2 and 1. They are never combined, and neither is a population estimate.

The independent directory adds the class evidence: `class-provenance.v0.json`, byte-identical to the
earlier one because it binds only the frozen selection, and `class-attempt.v0.json`, derived from
this report, which reads `completed` / `independent` / `declared` with a healthy survivor.

## How it was taken

Resource admission as #199 requires, on two samples 41 seconds apart with Docker running:
27 to 30 GiB disk free, 36 to 37% system-wide memory free as `memory_pressure` reports it, and swap
falling. The checkout was a clean detached `20f6d8b`. Every one of the nine envelope members reads
setup `ready`, envelope `verified`, candidate `completed`, cleanup `removed-and-absent`, network
`none` and user `65532:65532`. No retained file carries a host path.

The earlier directory stays as it is. It is retained evidence of the same measurement, and its
README says why its reports cannot be published.

## Non-claims

Local contained evidence, not hosted containment proof. A survivor is bounded to this selection,
corpus, projection, environment and host; it does not establish implementation incorrectness,
corpus completeness, security, conformance or adequacy. Authorship names in the provenance are
unauthenticated. The 2/2 and 0/1 results are not combined into any score.
