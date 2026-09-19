# Owned suggestion assessment producer v0

`measurements/owned_suggestion_assessment.py` produces an assessment for the
owned fixture through five explicit commands. It does not run an external
corpus, obtain consent, or approve its own proposal or review. Agent-assisted
implementation and synthetic tests are not evidence of a real candidate run.

## Inputs and command sequence

Run `python measurements/owned_suggestion_assessment.py COMMAND --help` for the
required flags. Each output directory must be new and its parent must exist.
Keep the trusted basis and externally approved expected identity outside the
produced package. They must not be reconstructed from the package being checked.

1. `plan`: supply a proposal, reference bytes, the independently checked reference
   digest and approval, the source checkout, and the basis directory. The source
   identity binds the clean Git commit and each of the fixed 30 source paths.
   The plan derives two five-case corpora: base and outer ASCII whitespace.
2. `prepare`: run once per variant with the plan, expected identity, basis,
   probe image ID and local inputs. The local input directory contains exactly
   `subject.tar.gz`, `toolchain.json` and an empty `vendor` directory. Preparation
   extracts the pinned owned subject, derives the corpus and binds the tool
   configuration at `tool/config.toml`. It observes existing images and runs
   containment probes. This command has host effects and requires the operator's
   execution permission; it does not pull images, build the candidate or fetch
   a corpus. Probe and candidate toolchain images have distinct roles.
3. `authorize`: bind the plan, both preparation records, expected identity and
   operator string into parent and per-variant authorization records. Writing
   these records does not authenticate an operator or grant execution consent.
4. `execute`: supply both complete preparation directories and authorization
   directory. The producer checks current source identity, re-reads bounded
   local materials and admits the derived context at the funnel, driver,
   runtime and candidate boundaries. This command executes the candidate and
   needs separate operator authorization. Each variant has baseline, positive
   control, inert control and target slots, with no separate build invocation.
5. `finalize`: replay a settled assessment against external expected identity
   and basis, and supply either an independently obtained review or explicit
   `--pending-review`. It writes a new package with decision and receipt without
   altering the original observations, journal, gates or evidence index.

Verify the resulting package independently:

```sh
python -I /absolute/path/to/measurements/suggestion_readback.py verify \
  --package /absolute/path/to/final \
  --basis-dir /absolute/path/to/trusted-basis \
  --expected /absolute/path/to/approved-expected.json
```

The reader is offline. A consistent package or review record does not
independently authenticate its writer, reviewer, execution origin or consent.

## Durable evidence and interrupted execution

Before each backend entry, the producer flushes and fsyncs a `started` journal
record. It then retains the detached backend observation and its validated JSON
view before settling the journal entry. Engine selector tuples are encoded as
JSON arrays, using the existing recorder representation. Exception messages are
not exported; a failed call records a closed exception kind. The envelope
collection records actual invocation accounting, including missing envelopes.

`engine_control_events` contains the actual engine verdict for evaluated
controls. An interrupted control has state `interrupted` and a null verdict;
unentered controls have no event. The producer does not infer engine verdicts
from views. The evaluator independently checks event, observation, journal and
control-summary agreement. Earlier pre-release synthetic packages without this
required field are incompatible with this v0 shape.

A settled interruption can produce an inspectable `unproved` assessment. A
storage or internal failure leaves diagnostic staging and its lease, with no
published output or fabricated completed receipt. There is no retry, resume or
repair command. Preserve the diagnostic directory before deciding on cleanup.
A publication failure can leave a fully written but unpublished stage; this
still does not prove that publication succeeded.

Publication uses the existing lease, destination precheck and rename model.
It preserves existing foreign outputs and does not claim atomic exclusive
creation: a destination race between the precheck and rename remains. Directory
and file durability depend on the filesystem and operating system.

## Results and verification limits

Commands emit one canonical `command-result.v0` JSON object. Exit 0 means the
command completed, not that an assessment was accepted: finalization can
successfully retain `pending-review`, `refused` or `unproved`. Execution returns
1 for a retained refused or unproved assessment. Exit 2 reports invalid inputs,
unsupported structures or an internal command failure. Inspect the retained
receipt and reader disposition rather than treating process exit 0 as approval.

The implementation tests use synthetic terminal responses while exercising the
real producer, process engine, driver and offline reader. They replace Docker,
image and candidate effects. They establish software behavior only. They do not
establish hosted proof, external corpus permission, production peak memory,
full-capacity operation or the separate experiments' outcomes. A real run needs
fresh preparation, approved inputs, resources and independent final review at
its exact source identity.
