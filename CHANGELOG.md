# Changelog

## Unreleased

Daemon-reported OOM kill as a named unproved reason (#102, slice C: freeze item 5 and section 4 of the 2026-09-10 research): `run_contained` now keeps `oom_killed` beside `create_warnings`, read by `observed_oom_killed` from the same inspect it already reads: `True` or `False` when the daemon reported a bool, `None` when the field is absent or not a bool. It refuses nothing there. On both the recorded and the unrecorded candidate path, one function (`candidate_result`) makes a completed run with `oom_killed` `True` unproved with the new closed reason `oom-killed-reported`, whatever the exit code (0, 1, 137 or any other), instead of reading the inner report; `corpus_adequacy.py`'s `CLOSED_UNPROVED_REASONS` gains the token, so it survives `sanitize_unproved_reason` and reaches the report as the unproved execution detail (`[oom-killed-reported]`). containerd publishes TaskOOM when the cgroup's `memory.events` `oom_kill` counter rises, which counts processes killed by any OOM killer in that cgroup, a host-wide OOM included, and moby then sets `State.OOMKilled`; so the token names a daemon observation, is never scored and never a mutant kill, and does not claim the measured process was the one killed. `False` or `None` changes nothing: exit 137 (also `docker stop`'s SIGKILL) stays `inner-exit`, and a timeout or output cap keeps its own state even with `OOMKilled` true. PID and `nofile` exhaustion stay cause-unobserved and CPU throttling is not a cause. The execution envelope is unchanged: no key is added to v0 (its keyset is frozen) or v1, so the envelope does not carry the OOM observation; its `candidate_outcome` for such a run is `unproved`, as for any unproved run, and the report's unproved reason carries it. No verdict changes other than through this token. `contained_oci.py`, the candidate and `corpus_adequacy.py` are execution paths, so a fresh PREPARE is required; none is regenerated here. The path set differs from the frozen C ceiling: `corpus_adequacy.py` and `README.md` are added because the closed reason set lives in the engine, `tests/test_aee_checker_sealed_runtime.py` is added for the detail and report-suffix tests, and `effective_envelope.py` is not touched. Leaves #102 open.

Hosted packet redirect pinning (#107): `hosted_packet.py`'s fetch now starts only at `github.com` and follows at most two redirects, each over HTTPS and only to `release-assets.githubusercontent.com`, the host GitHub's hosted-runner documentation lists as needed for downloading release assets. Another host, an explicit port or userinfo refuses with `fetch_host` or `fetch_redirect_host`, and the final response URL is held to the same two hosts. Before this, any HTTPS redirect target was followed. The manifest digest already bound every byte, so this adds no integrity; it bounds where the runner can be sent. If GitHub moves release downloads to another host the fetch refuses rather than widening on its own. `hosted_packet.py` is outside the execution identity paths, so no fresh PREPARE is needed for this change; the first hosted proof still fetches with the code at `hosted-proof-r1`.

Create-time warnings as a second signal (#102, freeze section 3; PR #134 review finding 4): `DockerTransport.create` now returns every non-empty stderr line of `docker create` (a leading `WARNING: ` removed) instead of discarding it, and `run_contained` keeps it as `create_warnings`. moby v28.0.4 (`verifyPlatformContainerResources`) can discard a requested limit, store the changed config and say so only as a create response warning, which docker/cli prints to stderr as `WARNING: <text>`. On the recorded candidate path, after the comparator accepts the stored config, any create warning, or a transport that did not observe create warnings at all (`None`), makes the envelope `unverified` with `unverified_field` `create_warnings`, for v0 and v1 envelopes alike; the candidate outcome is kept. Every stderr line counts, not only lines naming a discard, because moby's swap warning ends "Memory limited without swap.". A discard the stored config already shows keeps its more specific field (for example `cpu_period`); a discarded PIDs limit is refused earlier by the inspect contract. Non-claims: the warning text is not stored in the record, and this is daemon-reported configuration, not a kernel-applied limit. `contained_oci.py` and the candidate are execution paths, so a fresh PREPARE is required; the unrecorded legacy path and PREPARE's probe runs do not judge `create_warnings`.

Hosted gate exit and runtime declaration follow-ups (#107, #102): `contained_hosted_publication.py gate` now exits 0 only when the publication decision is `publish`. A run that ends withheld or unavailable writes its stubs and moves its collection out of the upload path as before, then exits 3 with `hosted publication not permitted: <decision>`; anything but an explicit publish decision is treated the same way. Before this, such a run exited 0, the effective-envelope upload (authorized by gate success) then failed on the missing collection directory, and the run went red for the wrong reason. A refusal still exits 2. The sealed runtime refuses a backend whose `execution_profile` declaration was deleted or replaced by a non-string after construction with a named `PrepareError` before the candidate is reached, instead of a bare `AttributeError` (PR #136 review finding 1). The runtime is an execution path, so a fresh PREPARE is required; the first hosted proof's packet (`hosted-packet-r1`, runner revision `hosted-proof-r1`) is bound to the earlier tree and still carries the old exit behaviour.

`NanoCpus` required unset (#102, A2 review finding 2 on #134): an `execution-envelope.v1` record now stores the daemon-reported `NanoCpus`, and a `contained-oci-v1` request requires it unset. moby refuses `NanoCpus` together with a CFS period, so an inspect that carries the requested `CpuPeriod`, `CpuQuota` and `nofile` beside a nonzero `NanoCpus` does not describe what the `resource-profile.v2` codec asked for; before this change it verified. The v1 effective document gains `nano_cpus`, read from `HostConfig.NanoCpus` by the v1 projector and kept in the record, so the value is held by the record and checked by every reader, not only at projection. An absent `NanoCpus` is `unverified` (`HostConfig.NanoCpus`), as an absent `CpuPeriod` already was. The shared stored-value rule refuses a non-integer, bool or negative `nano_cpus` in the projector, in `validate_envelope_record` and in the collection loader that reuses it. For a v2 request the comparator requires `nano_cpus` to be 0, checked after the CPU quota and before nofile with every existing refusal order kept; a nonzero value is `unverified` with `unverified_field` `nano_cpus`, and the candidate outcome is kept as it happened. A v1 envelope that carries a v0 request does not compare it, since that request makes no CPU claim. The v0 envelope and its canonical bytes are unchanged. A v1 record stored before this change has no `nano_cpus` and no longer validates. This is still configuration the daemon reported, not a limit the kernel applied. The envelope module is an execution path, so a fresh PREPARE is required; none is regenerated here. Leaves #102 open.

Outer activation A3 (#102): `contained-oci-v1` is executable, only through the sealed route and only with a backend that declares its profile. `runtime.make_sealed_backend` takes a required keyword `execution_profile`; the backend it returns declares that profile and passes it to `run_sealed_candidate` instead of A2's literal `contained-oci-v0`, and its envelope binding reads the PREPARE through the shared dispatcher. The engine compares a contained backend's declared profile with the one it resolved before the first call: a mismatch is refused, a `contained-oci-v1` backend that declares no profile is refused, and an undeclared `contained-oci-v0` backend still runs as before. Each refusal has its own message, distinct from the module-runner and contained-to-local refusals, which still apply to both contained profiles. `contained-oci-v1` joins the executable set. `run_execution_funnel` and `run_authorized` take a required keyword `execution_profile` with no default, so omitting it is `TypeError`; each replaces its prepare.v1-only check with `load_prepare_for_profile` after authorization, so `contained-oci-v0` admits only `prepare.v1` and `contained-oci-v1` only `prepare.v2`, and a crossed pair refuses before the execution identity, materialization or any engine call. The driver passes its profile to the backend and the funnel; the execution identity, pin and toolchain checks are unchanged and still follow the PREPARE check. The hosted gate passes `execution_profile=contained-oci-v0` to the driver explicitly, so the hosted lane stays `contained-oci-v0` (#107). No command emits a `prepare.v2`, so the v1 route is reachable only by a library caller that supplies one. Nothing here claims applied CPU or file-descriptor limits: a v1 envelope records the configuration the daemon reported, not limits shown to be applied by the kernel. An unrecorded run (no binding, so no envelope record) is refused under every profile but `contained-oci-v0`, whose legacy unrecorded run is unchanged: `run_sealed_candidate` refuses it after admission and before any effect, and `make_sealed_backend` applies the same rule (`require_recording`) at construction, so a `contained-oci-v1` backend without an envelope sink is never built. Carried from the A2 review, and since addressed by the `NanoCpus` entry above: the comparator now requires `NanoCpus` stored unset. Execute, driver, runtime and `corpus_adequacy.py` are execution paths, so a fresh PREPARE is required; none is regenerated here. Leaves #102 open.

Hosted packet delivery (#107). The hosted route is three phases on `contained-oci-v0`: a new `contained-hosted-prepare` workflow runs `prepare-v1` against R's in-tree pins on a pinned `ubuntu-24.04` runner and uploads the prepare bytes with a record of their SHA-256, `GITHUB_SHA`, `GITHUB_WORKFLOW_SHA`, `ImageOS` and `ImageVersion` (it has no driver, execute or gate step); the owner authorizes off the runner and publishes the packet as immutable-release assets with one manifest; and `contained-hosted-publication` fetches it with the new stdlib-only `measurements/hosted_packet.py` into the fixed `hosted-packet/` directory before the gate. The inputs `packet_root`, `authorize_path`, `prepare_path` and `pins_dir` are replaced by `packet_release_tag` and `packet_manifest_sha256`. The fetch refuses an existing or tracked destination before any network call, compares the manifest digest before parsing, parses strictly (duplicate keys, a closed name set, absolute, `..`, separator and escaping names refused), downloads each asset individually under a byte ceiling and holds it to its digest, and writes only after every check, nothing outside the destination. The gate gains `--packet-manifest-sha256` and binds the manifest, each listed file and the authorize/prepare roles itself, and refuses unless `GITHUB_SHA == GITHUB_WORKFLOW_SHA == runner_revision` (absent values refuse), recording both in the rerun evidence and setup artifact. The phase 3 job moves from `ubuntu-latest` and 15 minutes to a pinned `ubuntu-24.04` and 30 minutes: 300 s materialize + 9 x 120 s invocations = 1380 s, plus setup. Every existing gate check and refusal is unchanged, and the operator profile stays `contained-oci-v0`. `prepare.v1`, `authorize.v0`, `report.v0`, the driver, execute, runtime and every execution identity path are untouched, so this change does not by itself require a fresh PREPARE. The slice's path ceiling grew from nine to ten, adding `tests/test_hosted_member_validation.py`: its two full-gate runs call `run_gate` directly, so they now dispatch at R (`GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` set to the runner revision), write the fixed packet file names and pass the sealed manifest's digest; neither new gate check is made optional. Non-claims: not authentication, not a CPU or file-descriptor bound, and not a sandbox-completeness claim; PREPARE's probe evidence is not re-observed on the phase 3 VM, and the effective envelope is daemon-reported configuration. No workflow was dispatched and no hosted run is claimed.

Inner consumers A2 (#102): one PREPARE dispatcher, `load_prepare_for_profile`, selects the loader by resolved execution profile. `contained-oci-v0` admits only `prepare.v1` and `contained-oci-v1` only `prepare.v2`; each crossed pair refuses under its own name before any container is created, so a historical `prepare.v1` is never read as CPU/nofile-bounded, and every other profile has no loader. Validation stays in the two existing loaders. `run_sealed_candidate` takes a required keyword `execution_profile` with no default, so omitting it is `TypeError`, and it records the profile admission resolved instead of the constant `contained-oci-v0`. Docker create emits `--cpu-period`, `--cpu-quota` and `--ulimit nofile=S:H` for a v2 resource profile only, in period/quota form; a v1 argv is byte-identical to before. A request pairs `contained-oci-v0` only with a v1 resource profile and `contained-oci-v1` only with v2. A `contained-oci-v1` candidate record is `execution-envelope.v1`, carrying this run's daemon report; `contained-oci-v0` still emits v0 exactly as before, and a v1 envelope may still carry a v0 request. For a v2 request the comparator holds the daemon-stored `CpuPeriod`, `CpuQuota` and `nofile` soft/hard exactly against the request. A mismatch, an unset value or a limit the daemon discarded makes the envelope `unverified` and keeps the candidate outcome as it happened; the post-start inspect contract does not check CPU or nofile, so a container that ran is never recorded as refused. These are the configuration the encoding asked for and the daemon reported, not limits shown to be applied by the kernel. Nothing new is reachable from a production route: the engine still refuses `contained-oci-v1` before any backend (A1), and execute and driver are untouched. The slice's path ceiling grew from eight to ten, adding `measurements/aee_checker_sealed_runtime.py` and its test: a required keyword with no default reaches the runtime's call to `run_sealed_candidate`, which now passes the literal `contained-oci-v0`. Threading the resolved profile through the runtime stays with A3. Candidate, contained, envelope and runtime modules are execution paths, so a fresh PREPARE is required; none is regenerated here. Leaves #102 open.

Profile vocabulary A1 (#102): `contained-oci-v1` joins the closed operator-owned execution profiles, above `contained-oci-v0` in strength. It resolves, satisfies or fails a `minimum_execution_profile` like any member, so `contained-oci-v0` below a `contained-oci-v1` minimum is a refused downgrade, and the module-runner and contained-to-local refusals apply to it. It is recognised but not yet executable: the engine refuses every run under it before a backend is called, because downstream admission is keyed on the PREPARE schema rather than on the resolved profile, and a v1 run would otherwise reach a `prepare.v1` backend and record `contained-oci-v0`. No CPU, file-descriptor, kernel or containment claim follows. `report.v0`, `prepare.v1`, envelope formats and the hosted lane, which stays `contained-oci-v0`, are unchanged. The README no longer says kernel observation is unimplemented; the daemon-reported observation from the v1 envelope reader is named as such.

CLI summary denominator (#131). The human summary line printed `killed + survived` as its denominator while `score_percent` divides by `killed + survived + silent`, so a run with a silent mutant printed a fraction that disagreed with the percentage beside it: one silent mutant and nothing else printed `0 of 0 DECLARED in-scope rules killed (0.0%)`. The denominator is now one function, `_scored_denominator`, called by the report builder, both score closers and the CLI, so a printed fraction cannot disagree with the percentage it sits beside. No `report.v0` key or computed value changes; only the human summary line changes, and the tool identity fields differ as for any source change. Two mocked report fixtures, used by three tests, gained the `silent` key every real report carries, and the structural guard that looked for the literal sum in the process closer now checks the call and the function's value.

Observe O (#102): adds explicit execution-envelope.v1 observation and shared stored-record validation, and dual v0/v1 collection acceptance. Existing production emitters and default builders remain v0; historical report and envelope formats are preserved. CPU/nofile/daemon fields record supplied observations, not applied-limit or source-authentication proof. Unset settings do not establish absence of inherited limits. Synthetic daemon fixtures are not live wire evidence. Execution identity changes require a fresh PREPARE; none is regenerated here. Activation and hosted proof remain separate work.

Versioned resource/PREPARE codecs (#102, first slice). Adds `corpus-adequacy.aee-checker-sealed.resource-profile.v2` and `corpus-adequacy.aee-checker-sealed.prepare.v2` as siblings: v1's keys, its bounded fixture and its named loader are unchanged, and neither loader admits the other. One shared validation rule selects a closed per-schema policy rather than copying an implementation, so the two versions cannot drift apart. The v2 profile carries an aggregate cgroup CPU rate (`cpu_rate_millicpu`, exact integers mapped to `--cpu-period`/`--cpu-quota`, so no float, NaN or bool can reach the wire) and per-process descriptor limits (`nofile_soft`/`nofile_hard`, refused when soft exceeds hard). Operator policy is one CPU and 1024:1024; these are policy values, not measured tuning, and not a cumulative CPU-seconds budget. A well-formed v2 profile that is not the frozen candidate constant is still refused as a PREPARE, because the generic validator is not the equality check. The v2 rate and descriptor limits are finite as well as positive: a rate whose emitted quota could not be represented in the signed 64-bit microsecond value the cgroup interface reads is refused by the codec rather than encoded. That ceiling is representational, not a tuned CPU policy and not an applied host limit. The image rule the two PREPARE codecs apply is one shared function rather than two identical copies, with unchanged error strings and refusal order; a malformed-image control runs across both versions, since sharing removes one blind spot rather than making future divergence impossible. `authorize.v0` binds canonical prepare.v2 bytes with its wire keys unchanged, since `prepare_schema` and `prepare_sha256` already carry the version and the bytes; changed bytes and a forged schema with a recomputed digest refuse independently. **This is codec infrastructure and activates nothing**: no PREPARE command emits v2, the production v1 argv path is byte-unchanged, and candidate/runtime/driver/execute/publication continue to require v1. Encoding an argument is not applying or observing a limit. No applied-limit, kernel observation, exhaustion diagnosis, contained execution, publication readiness, #107 integration or #102 completion is claimed. Leaves #102 and #107 open.

## 0.2.0 — 2026-09-07

Execution-profile migration: command-line invocation still selects
`trusted-local`, but the new profile checks also apply to command-line users.
A manifest must not declare `execution_profile`. It may declare
`minimum_execution_profile`: `trusted-local` is accepted with the default
operator profile, while `contained-oci-v0` refuses that run as a downgrade.
Unknown or non-string minimum values are refused. These checks do not silently
select a contained backend or fall back to local execution.

Direct Python callers of `run` and `_run_process` must now supply the keyword-only
`execution_profile` argument; omission raises `TypeError`. Passing
`execution_profile="trusted-local"` selects the previous execution route but
does not bypass the new manifest checks. This migration note does not establish
a stable library API. Release distribution remains a source checkout at an
annotated tag; no package-index distribution or binary assets are introduced.

Add optional per-mutant `expected_mover` for batch `test-names` outcomes. A
change witnessed only by neighboring tests becomes a survivor when the declared
test does not change. Attribution reuses the existing parsed failed-test tuples;
`how` carries the names and `moved` keeps its existing meaning. Undeclared mover
behavior and termination kills are unchanged. Controls, unsupported outcome
modes and invalid names refuse the field.

Validate execution envelope member semantics and re-derive publication permission on consumer load (#106 prerequisite). Consumer boundary `contained_hosted_publication.load_envelope` now strictly validates execution envelopes via `effective_envelope.validate_envelope_record`, reconstructing the record through `bind_report` and requiring exact equality with the original loaded document. Nested `requested` declarations and `effective` observations are verified against explicit schemas: `resource_profile` must satisfy `RESOURCE_PROFILE_SCHEMA` with positive integer limits and boolean `work_exec`, `mount_spec` destinations must be strictly sorted non-empty absolute paths without duplicates sharing destination validation via `contained_oci.validate_mount_destinations`, and boolean/integer types are checked strictly without numeric coercion. Inconsistent records (such as stale `permitted` permission following failed cleanup, stale withheld reasons, altered schema or non-claims, out-of-bounds states, contradictory state tuples, or malformed nested structures) refuse with `HostedPublicationError("envelope_corrupt")` and materialize post-execute refusal artifacts rather than escaping as infrastructure failure. JSON decoders at confined envelope and prepare parsing boundaries catch `ValueError` (such as integer literals exceeding integer string conversion limits), ensuring named pre-execute `json_input` refusal for prepare and post-execute refusal for envelope without escaping as infrastructure failure. The hosted gate `check_envelope_bindings` strictly binds `requested` to candidate executor policy constants (`sealed=True`, `contained.CANDIDATE_RESOURCE_PROFILE`, `CANDIDATE_MOUNT_SPEC`, and `contained-oci-v0`), preventing self-consistent forged ceilings or mount sets from publishing. Because `measurements/effective_envelope.py` is declared in `EXECUTION_PATHS`, execution identity changes and a fresh PREPARE is required for live contained candidate runs; no frozen artifacts are regenerated in this PR. Closes a synthetic consumer acceptance boundary; does not claim any public result was published incorrectly. Not a score, not a collection schema change, and leaves #102, #106, and #107 open.

Correct hosted `image_digest` binding to candidate/toolchain image B (#107 slice). Preflight requires `prepare.image.id` (inert probe A) and `prepare.toolchain.image_id` (B), delegates identity/type/distinctness to `require_candidate_image`, and keeps envelope `requested.image_id` compared to B; probe A remains bound via prepare bytes/`prepare_sha256`. Workflow input description updated to match. Not a score, not hosted proof, and does not close #107/#102.

Bound the verified effective OCI envelope before scoring. A `contained-oci-v0` run now emits one sibling `envelope.v0` record (`corpus-adequacy.execution-envelope.v0`) carrying the requested profile, `setup_status`, `envelope_status` with the named failed observation, `candidate_outcome`, `cleanup` and a derived `publication_permission`. Effective values come from one observation-only projector with no defaulting accessor, held against the request by one comparator; projector, comparator and record share one closed key set, so a field cannot be recorded without being checked or checked without being recorded. Observed image id, runtime version, `Privileged`, `CapAdd`, host PID/user namespaces, devices, environment names and a complete mount inventory are now observed and refused when they drift; environment values are never read or recorded. A completed candidate whose cleanup fails is preserved as `completed` plus `remove-failed`/`absence-unproved` and withheld, instead of being lost to an exception. `report.v0` is unchanged, and so are `prepare.v1`, `survivors.v0` and published records; the binding runs envelope to report digest only. `measurements/effective_envelope.py` is declared in `EXECUTION_PATHS`, so execution identity changes and a fresh PREPARE is required; existing PREPARE bytes no longer drive the driver. This is not a score, not a sandbox-completeness claim, and not publication authorization by itself; enforcement of `publication_permission` is owned by the hosted publication gate (#107).

Gate hosted contained publication (#107). A `workflow_dispatch`-only hosted lane binds candidate revision, runner revision and image digest, forces `contained-oci-v0`, and attempts a real contained execution via `contained_oci.require_docker_ready` plus `aee_checker_sealed_driver.run_authorized` when authorize/prepare/pins packets are supplied under one packet root confined beneath the checked-out workspace. Dispatch bindings are sealed: packet-root `hosted-dispatch-bindings.v0.json` must match the workflow bindings; `prepare.pins.subject_commit` must equal `candidate_revision` (sole producer candidate identity — a candidate sidecar swap with unchanged prepare bytes refuses); `prepare.execution.commit` / image id and the produced envelope's `execution_commit`/`requested.image_id` must match runner/image; envelope `prepare_sha256` binds the exact checked prepare bytes. Authorize/prepare/pins/envelope JSON resolve only through one confined-input helper (no absolute/`..`/symlink/non-regular; byte ceiling before read/parse; path comparisons canonicalize both sides). Child-environment observation comes only from the contained OCI effective envelope (`env_names`/`mounts`); `HOSTED_FORWARDED_ENV_NAMES` is removed. `runner.environment`, `runs-on`, and `persist-credentials` remain structural workflow pins only. Workflow-dispatch inputs reach the gate only through step `env:` (never interpolated inside `run:`). Publication requires both `publication_permission: permitted` and `envelope_status: verified`. The effective-envelope artifact is the collection directory: its exact index plus every addressed member byte. Members are written as observed -- report binding attaches the digest and rewrites no field, so a contradicted member stays contradicted and is refused on read as `collection member semantics` rather than being normalized into an honestly-withheld one. A collection document at the legacy single-envelope path is refused, and a stale legacy file is removed rather than reused; there is no fallback from a corrupt collection. `measurements/envelope_collection.py` joins the execution identity inventory, so editing it dirties the execution gate and moves the content digest, and a fresh PREPARE is required; none is claimed here. Setup, effective-envelope, candidate-result and rerun-evidence are separate uploaded artifacts under concurrency, retention and size ceilings; the three diagnostic uploads use `if: always() && !cancelled()`, while the effective-envelope collection requires a successful gate; all four retain `if-no-files-found: error` and without turning gate refusal green; a post-execute `HostedPublicationError` writes withheld/void/refused stubs plus distinguished rerun evidence and moves this run's collection into a fresh `withheld-collection.diagnostic.v0/attempt-NNNN/`, outside every upload selection, so a refused run publishes no permitted member; raw observations are moved, never rewritten, and a repeated refusal never overwrites the bytes an earlier one retained. Publication of the collection artifact is authorized by the gate step succeeding rather than by `always()`, so a quarantine that fails still cannot publish permitted members; setup, candidate and rerun diagnostics stay always-on and a cleanup failure is recorded beside the refusal without replacing it. Collection members are read through the shared bounded regular-file reader, so a symlinked member is refused even when the index digest matches; rerun evidence is append-only and the upload name includes `github.run_id` plus `github.run_attempt`. Missing Docker is unavailable/void (never a score). Intake is not execution. This is not authentication, endorsement, audit, certification, escape-proof OCI, or a third-party quality score.

Closed operator-owned execution-profile selection (`trusted-local`,
`contained-oci-v0`), independent of runner (`module|process|batch`). The
operator supplies the profile; a candidate may declare only
`minimum_execution_profile`. Unknown values, operator-shaped manifest keys,
downgrade from contained to local, `contained-oci-v0` with `runner: module`,
and `contained-oci-v0` without an explicitly supplied contained backend are
refused. There is no contained-to-local fallback. `contained-oci-v0` is one
inspect-verified Linux/Docker envelope, not complete sandboxing and not
author authentication. `report.v0` is unchanged and does not record the
profile. `run` and `_run_process` require `execution_profile`; omission is
`TypeError`, not a trusted-local run. This is not a score, not `report.v1`,
and not a sandbox claim.

## 0.1.3 — 2026-09-02

Accumulated hardening since 0.1.2 covers bounded child-process cleanup,
closed report consumers, inert-control polarity, pinned adapter provenance,
and owner-approved related-work records.

The execution boundary remains trusted-local: manifests and candidate code are
trusted inputs. Process supervision is bounded, but it is not a sandbox,
containment claim, security certification, or product-wide adequacy claim.

Controls may now explicitly declare `control_polarity: inert`; legacy controls
remain positive. A moved inert control reports `control-MOVED`, gives aggregate
`control_status: moved`, invalidates the run, and emits no score. An unchanged
inert control reports `control-unchanged` while reusing the healthy aggregate
`killed` token. Missing or non-unique inert anchors are `control-error`, and an
inert-only manifest does not satisfy the positive-control requirement.
`control_polarity` is refused without `control: true`. Module, process, and batch
share the polarity rule and precedence `error` > `absent-or-invalid` > `survived`
> `moved` > `killed`. Controls remain outside the denominator; `report.v0` gains
no field, and manifests without inert controls retain existing report bytes. This
is a declared metamorphic check, not inferred equivalence, a score, or `report.v1`.

`--survivors` now refuses unknown top-level and mutant-row keys on a
decoded `report.v0` document through one shared closed-set helper, with
distinct missing-key and extra-key routes. Required keys come from the
same producer document factory that emits `report.v0`.
`originals_unverified_against_head` is required on `process` and `batch`
and forbidden on `module`. Mutant rows are closed per producer verdict
(`scope` required except `equivalent`; `raised` only on `killed`;
`moved_diagnostic` required on `silent`, optional on
`unexercised`/`known-hole`, forbidden otherwise). Tests pin that
verdict-shape independently of production helpers. Valid `report.v0` and
`survivors.v0` production bytes are unchanged. This is a consumer
closed-set, not a score, adequacy, ranking, or `report.v1`.

The Tersign evidence-record adapter now selects from one closed table containing
the historical `1cc5ea32` pin and the `0e560c1` pin. Git sources require exact
commit, manifest, vectors-tree, and vector-files identities; non-Git sources
require a unique exact manifest and vector-files digest identity. Vector case
bytes, including nested `payload_text`, are copied without normalization. This
is adapter support only, not a measurement, score, publication, upstream
endorsement, or correctness claim.

POSIX pipe readers now wait interruptibly and report `_OutputDrainIncomplete`
when a leader exits without both captured streams reaching EOF inside the
bounded drain grace. An escaped descendant that retains pipe writers can no
longer hang cleanup or leave a reader thread behind. This is a supervisor
liveness refusal, classified as an incomplete measurement rather than a
mutation kill; the module, process and batch runners share the same termination
rule. Process and batch `parse-error` and declared `unproved` failures now
match the module runner (`parse-error` was previously a process/batch kill);
module `no-result` is unchanged. Timeout, output-cap, unexpected-exit, and
signal remain termination kills after a completed baseline. It is not
descendant containment or a sandbox claim. Windows remains direct-child-only.

## 0.1.2 — 2026-08-23

Instrument and publication changes since 0.1.1, covering first-parent
1347651 through 1593ccc.

Opt-in `unproved_exit_codes` beside `accepted_exit_codes` (default `[]`,
disjoint). `accepted_exit_codes` stays default `[0]`. A declared-unproved child exit is classified before stdout is
parsed and never becomes a projected outcome. An ordinary mutant with any
such exit is `unproved` (`killed == 0`, `moved == 0`), including when
another process vector moved. Baseline voids; control is `control-error`.
Host-child timeout, signal, output-cap and unexpected-exit are unchanged.
Module unusable protocol remains `unproved`. Process/batch parse-error and
incomplete keep their existing disposition; only a declared
`unproved_exit_codes` exit on a living adapter is the new `unproved` class.
A module manifest that declares the field is refused.
This names adapter-declared inner incompleteness; it does not infer why
the inner checker failed and does not turn a host-child crash into
`unproved`. No new report verdict.

Controls now run before ordinary process or batch mutants. Baseline or
control failure voids before a scored result can be published.

A sealed candidate accepts the pinned checker's JSON report when it ends
in exactly one final LF, and retains a closed unproved reason
(`timeout`, `output-cap`, `inner-exit`, `empty-or-missing`, `malformed`,
`projection`). Return code 75 and `unproved` are unchanged. Hosted
Docker readiness timeout maps to `PrepareError` reason
`docker readiness timed out`, distinct from a missing executable and
from a completed daemon-not-ready result. Hosted Windows and macOS skip
that exact reason; hosted Linux still raises.

Publication no longer invents a copyable measurement command when a
sibling `manifest.json` is absent. A fail-closed void run attempt is a
typed, digest-bound projection and cannot enter the standard measurement
renderer. It does not manufacture a zero score.

The inverse AEE rail on this interval is execution-funnel and OCI
plumbing, not a product score: preregistered `check_sealed` sites, Phase
B inert OCI, Phase C sequence and authorization, sealed candidate
backend, inspect evidence from one mount contract, PREPARE image as an
explicit reusable input, regenerated PREPARE and four-key authorization,
candidate resource contract, one reusable process mutation step,
provenance-bound driver, residual mount guards, authorization emitted
from canonical PREPARE bytes, streaming and `docker_ok` characterization,
primary-failure preservation during sealed cleanup, and CI syntax
discover.

Authorized one-shot, consumed: one invocation at execution commit
`a95d2344` produced a void result with no score. Baseline is `unproved`.
`control_status` is the recorded raw value `absent-or-invalid` (no valid
control; this is not evidence that a control ran or was skipped as a
verdict). There are no scored mutants. Do not retry.

Raw report, PREPARE, and AUTHORIZE hashes on the public attempt are
recorded values. Those source bytes are not recomputed on the public
page. Only the public attempt digest
`7b7e430145f0489107274ba92956bb3d1aaa87364923f92e74e1f0f70c613ee0` is
recomputable from published bytes.

This cut publishes fail-closed instrument and projection behavior. It
does not claim adequacy, ranking, certification, or outreach.

## 0.1.1 — 2026-08-22

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
