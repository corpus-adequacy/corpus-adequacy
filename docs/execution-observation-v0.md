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
`steps`, `cleanup`, `closure`, `non_claims`.

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

`cleanup` contains exactly boolean `restored`, boolean `isolated_tree_removed`,
and `evidence_sha256`. A non-stopped artifact requires both booleans true.

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

## Backend transport

Observation execution uses a separate `_ObservationExecution(process, receipts)`;
legacy six-field `_ProcessExecution` alone is refused on this route. Each receipt
transports immutable original stdout/stderr bytes in addition to the public
bindings. Snapshotting recomputes byte hashes and selector projections using the
same `child_outcome` implementation; a hash of selected JSON is not the hash of
the original response. `raw_sha256`/`raw_size` name stdout; the invocation-evidence
object binds both streams, return code and capture state. Transport bytes are
stored separately from the public observation artifact.

Receipts cover the exact invoked prefix of the scheduled vectors. After an
abnormal invocation there is no subsequent child call; the remaining vector
slots become `not_run`. Omitting a vector without such a stop is a refusal.
The shared byte drain retains only its bounded prefix on timeout/output-cap or
incomplete collection. It makes no claim to have captured a failing child's full
output. The legacy text adapter preserves replacement decoding and exception
types.

## Prefix API and initial restrictions

`observe_prefix(manifest_path, execution_profile=..., backend=..., context_raw=...,
output_root=..., policy_identity=..., interpreter_identity=..., control_preflight=...)`
executes only build, baseline and controls. Policy/interpreter digests are explicit
operator arguments because the context bytes remain opaque. The built-in local
backend derives its identity from tool sources and the Python runtime; custom
backends declare `backend_identity`, `environment_identity`, `execution_profile`
and `accepts_step=True`. A subclass is a custom backend.

The optional control preflight receives a frozen step, immutable retained
receipts and context digest. It returns a closed proceed/stop object with exact
step ID and immutable evidence bytes matching its digest. It runs before source
mutation and is never available to ordinary resume. Changing declared sources
inside this hook refuses before mutation.

The first route accepts process JSON outcomes, explicit control polarities,
relative contained vector files, trusted-local or contained-oci-v1. It refuses
exclusions, known holes and expected-mover declarations instead of dropping them.
Output must be outside the measured tree. Execution requires the existing POSIX
advisory lock and no-follow file operations; unsupported platforms refuse before
effects. Raw observed values still do not imply qualified controls.

A new session directory retains exact context, an execution intent, completed
step checkpoints, digest-addressed blobs and (on success) `prefix.json`. Unexpected
backend exceptions or unverifiable results retain an `interrupted.json` record
and completed checkpoints, but produce no valid prefix. An unclosed attempt
must not be called not_run when its backend progress is unknown. This partial
record cannot be admitted, interpreted as a complete run or silently resumed.

## One-use continuation and recovery

`resume_observation` validates the prefix, admission, opaque context and decision,
current manifest/corpus/source/tool/backend/environment and schedule before effects.
The operator supplies one authoritative `ledger_root` outside the measured tree.
A lock and a session-derived create-exclusive consumption file are fsynced before
ordinary substitution. Even a torn consumption record blocks reuse. Changing the
output directory or admission nonce cannot release that session. Using a different
ledger is outside this local guarantee.

Continuation serializes backend calls into build-only and individual vector calls.
Each canonical dispatch binds session, step, vector, invocation, mutated source,
profile, backend and consumption. A pre-call marker and dispatch are durable before
calling the backend. Receipt evidence binds the dispatch and retained raw streams,
and is fsynced before the next vector. Custom observation backends must honor
`vectors=None` for build-only and `rebuild=False` for an individual vector call.

`recover_observation` never executes a backend. Exactly one unmatched dispatch may
produce an `abnormal` slot with reason `interrupted`, `receipt: null`, no outcome,
diagnostic or selector claims, and the dispatch digest as evidence. This is the
only receipt-less abnormal case. The codec validates its shape; recovery validates
the actual canonical dispatch, ordering and bindings. It does not claim the child
actually started, completed, or produced empty output. Later proven-unstarted slots
are `not_run`. Missing, contradictory or multiple unmatched intents refuse closure.
A malformed/torn consumption record remains consumed and cannot be recovered into
a trustworthy final artifact automatically.

Recovery retains an isolated tree still present after a hard crash and reports
cleanup false; it does not kill an unverified PID or assume an orphan child stopped.
A stopped final is not an admission to continue. An interruption during final
publication can be reconciled using the same consumption and retained receipts,
without repeating a vector. Recovery may conservatively retain `stopped` even when
all vector receipts survived; it does not reconstruct a lost successful return.

`prepare_closure` is pure and `close_observation` persists its exact bytes. A stopped
prefix takes no admission; an awaiting prefix needs a fully bound refusal. An allow
admission cannot be used to close without consuming/executing. Binding validation
is not authentication of the policy author or correctness of a private decision.
