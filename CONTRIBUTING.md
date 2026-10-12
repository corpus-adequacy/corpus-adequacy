# Contributing to Corpus Adequacy

Corpus Adequacy asks a narrow question about a published conformance corpus:
whether a declared rule can be removed without changing the corpus's declared
observation. Contributions should keep that question, its evidence, and its
limits explicit.

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Conduct concerns go to the private route it names, not to a public issue.

## Before opening a pull request

Open an issue first and agree on one concrete target. Good targets identify a
specific rule, projection, runner boundary, refusal, or publication contract.
Broad bug hunts and speculative refactors are difficult to review against the
tool's evidence model.

Read [AGENTS.md](AGENTS.md) before changing manifests, runners, measurements, or
generated publication files. It distinguishes checks enforced by the tool from
judgments that a reviewer must make.

## Development and verification

Corpus Adequacy uses the Python standard library and supports CPython 3.13.
Run the complete local test suite from the repository root:

```console
python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

For a behavioral change:

1. add a focused test and show that it fails for the intended reason;
2. make the smallest production change that passes it;
3. demonstrate that removing or reversing the changed rule makes the focused
   test fail again;
4. run the complete suite and record the exact commit and Python version.

Documentation-only changes should still check links, commands, generated-file
ownership, and `git diff --check`.

## Generated publication files

Files under `site/` that are rendered from measurements are generated evidence,
not hand-edited summaries. Change their source data or renderer, then check the
generated publication from the repository root:

```console
python3 scripts/render_publication_page.py --root . --out site/index.html --check
```

The generated output, its source commit, and any retained report must agree
before publication. Files under `docs/` are maintained reference documents.

## Pull requests and review

Keep one writer on one branch. Stage only the paths belonging to the change.
The pull request should name:

- the issue it closes;
- the exact changed paths;
- RED, GREEN, and reverse-mutation evidence where behavior changed;
- compatibility effects on existing manifests and report formats;
- generated files and their source inputs;
- claims the change does not establish.

The final commit needs review by someone who did not build the change. A new
push invalidates an earlier exact-head review. GitHub Actions is the integration
proof for the supported operating systems.

## Agent assistance

Disclose agent-assisted code, manifests, measurements, or reviews in the pull
request. Name the responsible human or agent role and keep authorship separate
from independent review.
