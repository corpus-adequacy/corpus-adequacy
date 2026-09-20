# Execution observations v0

Operator-selected, process-only raw execution evidence. These artifacts have no
adequacy score or movement verdict. They do not authenticate a policy or prevent
replay across independent copies of an operator ledger. Existing `report.v0`
continues to describe scored measurements.

## Encoding

Canonical UTF-8 JSON, sorted object keys, two-space indentation, one final LF.
Duplicate keys, non-finite numbers, invalid UTF-8, depth above 64, input above
8 MiB, unknown fields and noncanonical bytes refuse. SHA-256 values use
`sha256:` followed by 64 lowercase hex characters. Arbitrary outcome and
diagnostic JSON values may themselves contain words such as `verdict` or
`score`; the closed metadata shapes, not recursive word filtering, exclude
measurement claims.

## Closed objects

Prefix schema: `corpus-adequacy.execution-observation-prefix.v0`.
Final schema: `corpus-adequacy.execution-observation.v0`.
Both contain exactly: `schema`, `session`, `phase`, `bindings`, `schedule`,
`steps`, `closure`, `non_claims`.

`bindings` contains exactly `tool_version`, `tool_commit`, `tool_content_sha256`,
`tool_source_state`, `manifest_sha256`, `corpus_sha256`, `source_sha256`,
`execution_profile`, `backend_sha256`, `environment_sha256`, `context_sha256`,
`policy_identity`, `interpreter_identity`, `selectors`, `exit_policy`.
The engine derives tool identity from its runtime source inventory; a codec
alone only validates the representation. `selectors` contains `outcome_from`
and `diagnostic_from`; `exit_policy` contains `accepted_exit_codes` and
`unproved_exit_codes`.

Every schedule declaration contains exactly `step_id`, `kind`, `group`, `label`,
`control_polarity`, `vector_ids`, `mutation_sha256`. There is one build step,
then one baseline per group, then controls, then ordinary steps. Group vector
sets remain identical. Build has no vectors; baseline has no mutation digest.
Control polarity is explicit. Declaration order determines suffixes.

Every step contains exactly `step_id`, `state`, `source_sha256`, `application`,
`anchor_hits`, `build_state`, `restored`, `preflight`, `failure`, `slots`.
`preflight`, when present, contains `decision` (proceed/stop), `reason` (null for
proceed), `evidence_sha256`; it is permitted only for controls. `failure`, when
present, contains `reason`, `evidence_sha256`.

Each vector slot contains exactly `vector_id`, `state`, `outcome`, `diagnostic`,
`selector_presence`, `receipt`, `reason`, `evidence_sha256`. States are observed,
abnormal, pending or not_run. Parsed values exist only for observed slots.
`selector_presence` has exactly boolean `outcome`, `diagnostic` fields and
records selector completeness. A missing required selector produces an abnormal
slot, never equality. An invocation receipt contains `invocation_id`, `step_id`,
`vector_id`, `source_sha256`, `raw_sha256`, `raw_size`, `evidence_sha256`.
Invocation IDs are unique; identical raw digests from fresh calls are allowed.
An unstarted slot has no invocation receipt. Build has no vector receipts.

`closure` contains exactly `reason`, `stop_step`, `prefix_sha256`,
`admission_sha256`, `consumption_sha256`; unused bindings are null.
`non_claims` is exactly `["no-adequacy-score", "no-policy-authentication",
"no-global-replay-prevention"]`.

## Phase boundary

An awaiting_admission prefix has complete build/baseline/control steps and
pending ordinary steps. A stopped prefix has the actual stopped step and a
complete not_run suffix, no pending slots. A control preflight can stop before
any mutation/build/child: its closed stop record is mandatory and current slots
are not_run with no fabricated abnormal invocation. A stopped prefix cannot be
admitted. Actual execution failures retain their abnormal evidence instead.

A final artifact has no pending slots. A refused final binds the predecessor
prefix/admission, with ordinary slots not_run. A completed allowed final also
binds the consumed admission record. A stopped final retains the stop and
predecessor bindings. The private ledger is bound by a separate completion
receipt, not by a circular digest embedded in the public final.

## Admission

Schema `corpus-adequacy.execution-admission.v0` contains exactly `schema`,
`session`, `prefix_sha256`, `context_sha256`, `decision_sha256`, `policy_identity`,
`interpreter_identity`, `next_step`, `decision`, `reasons`, `nonce`,
`decision_binding_sha256`. The last digest hashes the canonical object without
that field. `decision` is allow/refuse. Reasons use the closed generic codes
`policy-refused`, `evidence-incomplete`, `binding-mismatch`, `operator-refused`;
allow has none and refuse has at least one. Public validation binds the exact
private decision/context bytes but does not interpret their policy semantics.
