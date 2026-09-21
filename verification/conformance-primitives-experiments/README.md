# Primitive-conformance experiments

Experiments provide dated executable evidence for proposed or rejected constructions. A passing experiment
does not add a DCA conformance requirement or select a protocol profile.

This directory sits beside [`verification/conformance-primitives/`](../conformance-primitives/README.md) and holds
executable cross-runtime proofs that need the conformance framework's kind of byte-level comparison but are
not selected public behavior.

An experiment may prove that a candidate construction works, that runtimes
disagree, or that a deliberately insufficient construction produces a stated
harmful result. Green means the experiment reproduced that stated outcome. It
does not approve the construction or make it protocol authority.

Each experiment owns one subdirectory containing its description, shared
inputs and expected observations, runtime probes and focused check. It may
reuse the selected conformance framework, fixtures or toolchain conventions,
but the dependency points from here toward public conformance. Public
conformance never imports this directory, and removing it must not change base
or extension conformance results.

```text
conformance-primitives-experiments/
  README.md
  <experiment>/
    README.md
    check
    _shared/
    <runtime>/
```

Keep experiments free of product dependencies and absolute paths from
one machine. The experiments directory stays beside stable
`verification/conformance-primitives/` rather than inside it. Selecting a construction
is a separate promotion: specify it, implement it in the owning reference
boundary, and record its vectors with the vector owner. A stock-library
operation or case enters public primitive conformance only when it
independently meets that corpus's admission rules. Rejected or historical
proofs may stay here only while they provide useful evidence.
