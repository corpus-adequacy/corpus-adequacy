# Owned corpus revision: second upper-bound case

This five-vector revision adds `above-max-by-two` (`value: 12`) to the four
original owned vectors. It is separate from the frozen corpus at
`fixtures/contained-v1-owned/corpus/vectors/`. No sealed contract selects this
revision automatically.

## Expected distinction

The [owned rule](../../contained-v1-owned/candidate/src/check.rs) rejects values
above the declared maximum. With maximum `10`, the new case must return
`accepted: false` and `reason: above-maximum`.

The [fixed target mutation](../../../measurements/owned-independent-v0/mutation-bundle.json)
`upper-guard-first-overflow-only` replaces the upper-bound condition with
`value > maximum && value <= maximum.saturating_add(1)`. It still rejects `11`,
but accepts `12`. The expected distinction concerns the selected `accepted`
and `reason` fields, not diagnostic wording.

## Corpus identity

The original four vector files retain their exact bytes. The new vector and
manifest match the reviewed derived base corpus from the local assessment.

`corpusDigest`: `e44c04584ef74999eb72d72b3245eec99e88d519042eca0a2e3bf94a00d02e8c`

The digest is SHA-256 over each manifest entry's UTF-8 filename, a NUL byte,
and its exact file bytes, concatenated in manifest order. It is distinct from
the hash of `MANIFEST.json` and the assessment receipt. From the repository root,
verify it without executing a candidate:

```sh
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path('fixtures/owned-suggestion-revisions/above-max-by-two-v1/vectors')
manifest = json.loads((root / 'MANIFEST.json').read_text())
digest = hashlib.sha256()
for row in manifest['vectors']:
    digest.update(row['file'].encode('utf-8') + b'\0')
    digest.update((root / row['file']).read_bytes())
actual = digest.hexdigest()
if actual != manifest['corpusDigest']:
    raise SystemExit('corpus digest mismatch')
print(actual)
PY
```

## Retained local evidence

The [operator's result record](https://github.com/corpus-adequacy/corpus-adequacy/issues/224#issuecomment-5745973220)
names the assessment at source `8c4034cabb7aac165ce4831b5191ae5cf315f23b`.
It observed the distinction under base and outer-whitespace variants, with
healthy positive and inert controls. The original four rows agreed between
baseline and target in those augmented-corpus observations.

Receipt SHA-256:
`b6bfce33e73bd2cb279aa2ecca0976a792a70028a5930bf7d8eb4af977dbc86c`.

The raw local assessment is not included here; its digest alone does not make
that run publicly reproducible or authenticate its origin. This revision ships
only the base corpus bytes, not the whitespace variant or an execution manifest.
There was no separate pre-addition run. This known, targeted example does not
establish general model effectiveness. Historical corpus files, selection and
PREPARE records remain tied to their original identities.

Prepared with Codex assistance. See [#226](https://github.com/corpus-adequacy/corpus-adequacy/issues/226).
