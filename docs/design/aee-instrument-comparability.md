# AEE instrument comparability: design-only proposal

**Status: proposal, not an execution plan.** No measurement was performed under
this document. Publishing it does not authorize a run, a retry, an adapter or
an extension of either instrument's claims.

This responds to the [owner's design-only consent and boundaries](https://github.com/astrogilda/aee-conformance/issues/5#issuecomment-5464590241).
The useful question is what information a second instrument could add, not
whether one instrument reproduces another's score.

## Sources and populations

Two pinned sources inform this proposal:

- [corpus-adequacy source at d8b238805e54400ee908c21262ca8cca64f209ff](https://github.com/corpus-adequacy/corpus-adequacy/blob/d8b238805e54400ee908c21262ca8cca64f209ff/corpus_adequacy.py).
  Its process and batch runners consume declared source replacements and
  declared outcome projections. They do not enumerate arbitrary implementation
  sites or provide a general seeded site sampler.
- [The Go forcing baseline at 59faf842098183ae7b5387ad13e6351c44687279](https://github.com/astrogilda/aee-conformance/blob/59faf842098183ae7b5387ad13e6351c44687279/docs/FORCING-BASELINE.json),
  interpreted with the [forcing gate at that same revision](https://github.com/astrogilda/aee-conformance/blob/59faf842098183ae7b5387ad13e6351c44687279/scripts/forcing-gate.py).
  This is a historical record of one instrument against one corpus, not ground
  truth for another instrument or a claim about the current upstream revision.

A native Go site key identifies a source file, function, operator and mutated
span. It does not identify a corresponding Rust site. Neither matching names
nor matching counts supplies that correspondence. This proposal therefore
does not enumerate, select or align native Go sites for a Rust experiment.

## Preserve the distinctions

The Go record keeps `KILLED`, `SILENT`, `DEAD` and `INCONCLUSIVE` separate.
Its own description distinguishes a rail change visible to the corpus while
the suite stays green (`SILENT`) from no dependency observed by that corpus
(`DEAD`). Do not sum them into a shared "unforced" or adequacy figure.

The Go `unkillable` and `masked` annotations are owner-authored, falsifiable
claims with different meanings. The pinned gate fails when an annotated site
is `KILLED`. Preserve the annotations and their reasons; do not silently turn
them into unforced rows or infer equivalent mutations in another instrument.

For in-scope, unacknowledged process/batch mutations, corpus-adequacy's
`silent` records movement only on a declared diagnostic projection, without
movement on the declared outcome projection. `survived` records neither kind
of movement being observed through the selected vectors and projections. It
does not establish that no other behavior changed. Exclusions, acknowledged
holes and controls have their own handling; similarly spelled labels are not
a cross-instrument mapping.

Execution failure also needs its original meaning retained. At the pinned
corpus-adequacy revision, specified child-termination classes can produce a
mutation kill, whereas an incomplete non-termination measurement can produce
`unproved` and fail the run. An `unproved` row does not universally make the
numeric score field null. A failed run must not be presented as a successful
adequacy result merely because a numeric field remains. Native `INCONCLUSIVE`
must not be relabeled as a forcing gain.

## Minimum protocol for any later proposal

Before requesting execution, a separate proposal would need to fix:

1. Each instrument, implementation and corpus revision, plus the source
   population and exclusions. Keep the populations separate.
2. A mechanical selection rule for the proposed instrument's own source
   sites, including a seed if sampling is used, committed before outcomes
   are inspected. This is work to specify and implement, not a capability
   claimed for corpus-adequacy today.
3. The exact mutation, normative outcome projection, optional diagnostic
   projection and expected distinction for every selected case. Retain
   owner-authored annotations without reinterpreting them across instruments.
4. Separate positive and inert controls, baseline acceptance, resource
   ceilings, termination handling and a stop policy. Preserve failures and
   incomplete or void attempts instead of treating them as corpus findings.
5. A reporting form with per-case provenance and limitations. No site-level
   agreement fraction, common denominator, ranking or score translation.

Whether a distributional comparison would be informative remains an open
design question: the populations and observation channels differ. No such
comparison is planned or measured here. The next decision is whether a
specific question justifies a separate, explicitly authorized execution
proposal; publication of this note does not make that decision.

## Non-claims

No new corpus-adequacy result, specification-completeness claim,
implementation-quality comparison, certification, endorsement or partnership.
No upstream changes, request for upstream hosting or execution, or new entry
in an independent-run ledger. The existing void-attempt record is not
reinterpreted as a successful run and is not retried by this proposal.
