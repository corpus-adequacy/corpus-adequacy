# Threat model

**Status:** describes `main` as of #102 (2026-09-17). It adds no rule. Where it names behaviour,
the README section "Trust boundary" and the named source files are authoritative; where it names
what is *not* claimed, those non-claims are the ones the code and records already carry.

## 1. Scope

Corpus Adequacy runs an implementation under test (the *candidate*) against a published
conformance corpus, mutates declared rules, and records which mutants the corpus distinguishes.
A manifest is executable input: whoever runs it runs the commands it names. This document names
what the tool protects, what it trusts to do so, and what stays outside its claims, for three
execution routes:

| Route | Profile | Where it runs | Who dispatches |
|---|---|---|---|
| Local | `trusted-local` | the operator's own session | the operator |
| External hosted rail | `contained-oci-v0` | GitHub-hosted `ubuntu-24.04` runner | the owner, per consented packet |
| Repository-owned hosted rail | `contained-oci-v1` | GitHub-hosted `ubuntu-24.04` runner | the owner, per packet |

"Contained" here means one Docker container whose configuration the daemon reported back and the
tool compared with the request. It never means an escape-proof sandbox.

## 2. Assets

- **The operator's host session:** files, credentials, network identity and processes of whoever
  runs a local measurement.
- **The repository checkout and pins:** tool source, adapters, pinned corpora and sites, whose
  bytes define the sealed execution identity.
- **The hosted runner VM:** its checkout, its `GITHUB_TOKEN` (`contents: read`; plus `id-token` and
  `attestations` write for the signing step only) and no repository secrets.
- **Published evidence:** workflow artifacts, immutable packet and archive releases, and signed
  attempt statements.
- **The integrity of a result:** that `report.v0`, the effective-envelope collection, the candidate
  result, the rerun ledger and the statement describe the attempt they claim, and that a refused,
  withheld or incomplete attempt is never presented as a clean one.

## 3. Trusted computing base

**Local (`trusted-local`).** The host kernel and Python, the operator, and the manifest and corpus
authors. A local run is process isolation only: one deadline, one output ceiling and a
process-group kill for the module child, a disposable copy of the declared sources for process and
batch runners. The README's "Trust boundary" section is the authority; nothing here upgrades it.

**Hosted rails (`contained-oci-v0`, `contained-oci-v1`).**

- GitHub Actions: the control plane that schedules the job, the hosted VM image and its kernel,
  the `GITHUB_SHA`/`GITHUB_WORKFLOW_SHA` and run identity it reports, artifact storage, and
  immutable releases.
- The container runtime on that VM: the Docker daemon, containerd and runc, and the cgroup and
  security settings the daemon reports. Envelope v1/v2 records keep the daemon-reported kernel
  version, cgroup version and driver, and security options as observations, not as kernel
  introspection.
- The pinned runner revision: the gate (`measurements/contained_hosted_publication.py`), the
  sealed driver, runtime and candidate modules, and the pins they verify.
- What the workflows pull in by pin: the checkout, setup-python, upload-artifact and attest
  actions (by commit SHA), the Python toolchain `setup-python` installs, which runs the gate
  itself, and the packet fetch's single permitted redirect host,
  `release-assets.githubusercontent.com`.
- The owner, who reviews PREPARE bytes, publishes packets, obtains an external corpus owner's
  consent where one applies, and dispatches each attempt.
- For signed statements: Sigstore (Fulcio, Rekor) and GitHub's attestation store.

## 4. Untrusted

The candidate source and its build, the corpus vectors, every process and byte inside the
container, a manifest's declared commands, and anything a candidate writes to stdout or stderr.
Candidate output reaches evidence only as closed tokens and projected outcomes; host paths, stderr
text and exception messages do not.

## 5. Mechanisms

| Concern | What the code does | What is observed or recorded |
|---|---|---|
| Untrusted manifest without a contained profile | Refused before any command runs; no fallback from contained to local | `ManifestError`, exit 2 |
| Credentials in the child | Only the image's own environment plus `CARGO_NET_OFFLINE` | Environment *names* compared against the image's |
| Network | `--network none` for every candidate container; the only unsealed containers are PREPARE's inert network-control probe and online materialization, which run no candidate code | Daemon-stored network mode; the gate refuses a record whose request is not sealed |
| Source and host checkout | Read-only root and read-only binds; mutation happens on an isolated copy | Complete mount inventory, `rw: false` |
| Time and output | Host-enforced deadline and output ceiling | Closed reasons `timeout`, `output-cap` |
| Memory | `--memory`/`--memory-swap` requested | Daemon-stored values compared; a daemon-reported `OOMKilled` becomes `oom-killed-reported` |
| PIDs, open files, CPU, disk | Requested (`--pids-limit`; v1 adds CPU period/quota and `nofile`; tmpfs size and inode limits) | Daemon-stored values compared field by field. Exhaustion surfaces as `inner-exit` or a wrapper stage, cause unobserved, never a kill |
| A limit the daemon discarded | Any `docker create` warning makes the envelope `unverified` | Named `unverified_field` |
| Missing runtime | `unavailable`/`refused`, never local | Closed reason `setup`, no score |
| Publication | Only when every collection member is `verified` and `permitted` | Gate exits 0 only on publish; upload conditions pinned by workflow contract tests |
| Attempt identity | Dispatch bindings, `GITHUB_SHA == GITHUB_WORKFLOW_SHA == runner_revision`, append-only rerun ledger, per-attempt step attribution (collection v1) | Sealed and signed statement over the upload surface |
| External corpus consent | The external rail publishes no score and no per-mutant result | Reduced candidate result; no report upload |

"Limit applied" in this project means: the daemon-stored configuration equals the request field
for field, `docker create` emitted no warning, and any run failing either check is `unverified`
and withheld. Kernel-interface read-back of cgroup values and cause attribution for PID,
file-descriptor and disk exhaustion are not claimed; public #197 tracks them.

## 6. Residual risks

- A container runtime or kernel escape, including through a daemon or runc defect.
- Side channels between the container and the VM.
- A compromised Docker daemon, which could report configuration it did not apply.
- A compromised operator, owner account or GitHub control plane.
- A host-wide OOM kill reported as the container's (`oom-killed-reported` names the report, not the
  cause).
- PID, open-file, CPU and disk limits that are configured and compared but not observed at the
  kernel interface.
- A byte-identical collection member substituted from another run (the collection's own non-claim).
- Local runs: everything a trusted child process can reach.

## 7. Change control

Every file in a sealed measurement contract's `execution_paths` is part of the inner execution
identity. Changing any of them requires a new tag and a fresh PREPARE before the next hosted
measurement on either rail. Workflow files and the hosted gate are bound separately by the runner
revision. Historical records are never reinterpreted: older envelope, collection, candidate-result
and statement shapes stay readable as they were written.

## Non-claims

Not an audit, a certification, an escape-proof sandbox, a CPU or file-descriptor bound, or
authentication of any candidate, corpus or release author. A signed statement authenticates the
workflow that produced bytes, not the intent of the person who dispatched it.
