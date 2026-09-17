# Slice B evidence, measured at `5918ec4495b64397b069c3cb3973e9153fee7e7a`

Two local `contained-oci-v1` measurements of the same owned candidate and corpus, one per
selection, produced by `measurements/owned_slice_b_local.py` on the operator's own Docker
(#199, Slice B of #169, parent #103). Every byte here is pinned by
`tests/test_owned_slice_b_evidence.py`.

| | declared | independent |
|---|---|---|
| Selection | `measurements/owned-contained-v1` | `measurements/owned-independent-v0` |
| Mutants | 2 ordinary, 1 positive and 1 inert control | 1 ordinary, the same two controls |
| Result | killed 2, survived 0, adequate true | killed 0, survived 1, adequate false |
| Control | killed | killed |
| `unproved` | 0 | 0 |
| Attempts recorded | 5 | 4 |

The two denominators are 2 and 1. They are never combined, and neither is a population estimate.

Both runs share the candidate toolchain image, the Docker runtime and the materialized subject and
corpus trees. Their execution identities differ, and only by the manifest path each contract names.
The inert probe image is built per PREPARE, so its host-local id differs by construction; it is not
the candidate image and runs no candidate code.

The independent directory adds the class evidence: `class-provenance.v0.json` (requested class
`independent`, one `selection-committed` event, authorship from the frozen bundle) and
`class-attempt.v0.json`, derived from the validated report, which reads `completed` /
`independent` / `declared` with a healthy survivor.

Each report's `manifest` field records the manifest path exactly as it was handed to the tool,
which here is absolute and names the operator's worktree. Earlier retained measurements were run
from the repository root and record a repository-relative path instead. Nothing binds on that
string: the manifest is bound by `manifest_sha256`, and the publication renderer refuses host
markers before anything is public. Public corpus-adequacy#204 makes the facade record the
repository-relative path so the next retained measurement matches the earlier ones.

## Reading it back

From a checkout at the measured revision:

```
python3 -c "import sys; sys.path[:0]=['.','measurements']; import corpus_adequacy as ca, owned_slice_b_local as s; \
  d='measurements/owned-slice-b-5918ec4/independent'; \
  m=s.manifest_beside_subject; \
  ctx=m(); p=ctx.__enter__(); \
  print(ca.load_class_attempt_v0(d+'/class-attempt.v0.json', provenance_path=d+'/class-provenance.v0.json', \
    manifest_path=p, report_path=d+'/report.v0.json', environment_path=d+'/prepare.v2.json')['status'])"
```

## Non-claims

Local contained evidence, not hosted containment proof. A survivor is bounded to this selection,
corpus, projection, environment and host; it does not establish implementation incorrectness,
corpus completeness, security, conformance or adequacy. Authorship names in the provenance are
unauthenticated. The 2/2 and 0/1 results are not combined into any score.
