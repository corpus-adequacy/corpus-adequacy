# class-evidence.v0

Offline codecs for one evidence class. They do not execute a candidate, write
an attempt directory, or publish. They do not add an aggregate score.

Schemas:

- `corpus-adequacy.class-provenance.v0`
- `corpus-adequacy.class-attempt.v0`

`report.v0` is unchanged. Class fields never enter the report document or a
mutant row.

## Non-claims (fixed, ordered)

1. No evidence class proves rule completeness, corpus quality, implementation correctness, real-world prevalence, security, conformance, or author independence.
2. Each denominator is one declared selection and is not a population estimate.
3. This artifact defines one class only; no aggregate score or overall adequacy exists.

## `class-provenance.v0`

Exact top-level keys: `schema`, `class_id`, `requested_class`,
`manifest_sha256`, `mutation_bundle_sha256`, `candidate_freeze`, `authoring`,
`visibility_events`, `origin`, `expected_distinctions`, `non_claims`.

| Field | Form |
|---|---|
| `schema` | `corpus-adequacy.class-provenance.v0` |
| `class_id` | closed rule-id token |
| `requested_class` | `declared` \| `independent` \| `held_out` \| `real_fault` \| `adaptive` |
| `manifest_sha256` | `sha256:` + 64 lower hex of exact manifest bytes |
| `mutation_bundle_sha256` | `sha256:` + 64 lower hex of exact bundle bytes |
| `candidate_freeze.candidate` / `.corpus` | `repository` (`owner/name`), `commit` (40 lower hex), `tree_sha256` |
| `candidate_freeze.observation_declaration_sha256` | canonical digest |
| `authoring` | `mutation_author`, `candidate_builder` (≤256 UTF-8 bytes), `relationship` (`same` \| `independent` \| `unknown`), `candidate_outcomes_seen` (JSON boolean) |
| `visibility_events[]` | 1–64 rows; `ordinal` 0..n-1; `event` `selection-committed` \| `candidate-frozen` \| `selection-disclosed`; bundle digest; `actor`; predecessor null at 0 |
| `origin.kind=authored` | required for `declared` / `independent` / `held_out`; nested `source` |
| `origin.kind=historical_fault` | required for `real_fault`; distinct commits; HTTPS `reference` |
| `origin.kind=adaptive` | required for `adaptive`; `source` plus predecessor-attempt digest |
| `expected_distinctions[]` | 1–8192; unique canonical Unicode order by `(group, label, channel, member-or-empty)` |

`relationship=independent` requires distinct identity strings and
`candidate_outcomes_seen=false`. F1 does not authenticate those strings. F2
owns visibility-chain hashing and effective-class downgrade. Until F2, no
`held_out` provenance may be used to construct a publishable attempt.

### Distinction binding (after exact manifest digest match)

`(group, label)` names exactly one ordinary `mutants` entry (`control` false,
`scope=declared`). Equivalent, control, and out-of-scope labels refuse.

- module: only `channel=outcome` with `member=null`
- JSON process/batch `channel=outcome`: null means the outcome object as a whole; a non-null member must occur in `outcome_from`
- `channel=diagnostic`: member required and must occur in `diagnostic_from`
- batch `test-names`: diagnostic refuses; a non-null outcome member must equal that mutation's `expected_mover`; absent mover permits only null

## `class-attempt.v0`

Exact top-level keys: `schema`, `attempt_id`, `class_id`, `provenance_sha256`,
`manifest_sha256`, `report_sha256`, `environment_sha256`, `effective_class`,
`visibility_status`, `predecessor_attempt_sha256`, `status`, `result`, `rows`,
`non_claims`.

| Field | Form |
|---|---|
| `effective_class` | requested class ids plus `unknown` |
| `visibility_status` | `declared` \| `hidden-until-freeze` \| `disclosed-before-freeze` \| `unknown` |
| `predecessor_attempt_sha256` | null or canonical digest |
| `status` | `completed` \| `unproved` |
| `result` | `control_status`, seven ordinary counts, `denominator` from `_scored_denominator`, `score_percent`, `adequate`, `failures` |
| `rows` | deep copies of validated `report.v0` mutant rows, producer order, max 8192 |

`status=completed` only when the report has a non-null score, `unproved=0`,
positive-control `control_status=killed`, and no baseline/control abnormality.
A healthy survivor is `completed` with `adequate=false`. It is not `unproved`.

Publishable attempt construction (`derive_class_attempt_v0`) is unreachable
until F2. F1 may encode and load codec bytes. Callers cannot supply result
counts; the decoder refuses parity mismatches against the validated report.

## Loaders

`load_class_provenance_v0` and `load_class_attempt_v0` open only the explicit
paths, through `read_bounded_regular_file` at `CLASS_INPUT_CAP_BYTES` (the
existing 4 MiB cap), one at a time. Digest mismatch of a dependent input is
decided before that input is parsed. No filesystem path is serialized into
either artifact. Encoders share one class-artifact byte contract: UTF-8,
`ensure_ascii=False`, two-space indent, sorted keys, one trailing LF.
`encode_report_v0` is unchanged.

## Out of scope

F2 visibility state machine, F3 experiment, F4 recorder/publication, CLI
registration, candidate/Docker execution, hosted dispatch, and any
cross-class score.
