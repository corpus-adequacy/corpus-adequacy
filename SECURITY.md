# Security policy

## Supported versions

Security fixes target the latest software release tagged `vVERSION` and the
current `main` branch. Older releases may be assessed when a report shows that
they remain affected, but they are not promised separate fixes or backports.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** link in this repository's Security tab.
That opens a private vulnerability report with the maintainers. Please include:

- the affected release, commit, command, and runner;
- a minimal reproducer or hostile input when safe to share;
- the observed result and the result you expected;
- resource use, platform details, and any relevant evidence artifact;
- the impact you believe follows from the behavior.

This route is for vulnerabilities only. A conduct concern goes to the private route in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Do not open a public issue for an undisclosed vulnerability. Do not include
credentials, access tokens, private candidate material, or third-party secrets.

The project does not promise a response or remediation SLA. We will preserve
the distinction between a reported behavior, a reproduced finding, a fix, and
published verification.

## Scope

The assets, trusted computing base and residual risks are described in
[docs/threat-model.md](docs/threat-model.md).

Useful reports include input-bound failures, path or archive escapes, resource
ceiling bypasses, unsafe candidate execution, evidence/provenance confusion,
and cases where a refusal or incomplete run is presented as a clean result.

Corpus Adequacy reports mutation observations over author-declared rules. A
surviving mutant by itself is a corpus finding under the declared projection;
it is not automatically a security vulnerability in the implementation.
