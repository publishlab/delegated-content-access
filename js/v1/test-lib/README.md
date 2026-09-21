# JavaScript test library

`test-lib/` contains test-only reusable library code and no executable test
entry points. Its `suites/` directory contains reusable behavioral requirement
definitions registered unchanged against one or more implementation targets. A
suite owns its cases, fixtures, assertions, diagnostics and completeness
accounting. It accepts a small implementation adapter from the entry point,
and imports no target itself.

The reference test library lives here, and nothing under it imports
`experiments/`. A suite still being evaluated belongs in `../experiments/<experiment>/test-lib/`, or in
an experiment's `test-lib/suites/` while it is unselected; promotion moves the
suite here only after its requirement is selected.

Each `suites/` module represents one reusable behavioral requirement. Do not
move unrelated test code here just because a test uses it.

Discovered `.test.js` entry points live in [`../test/`](../test/README.md) and
[`../experiments/`](../experiments/README.md). Portable public-boundary
contracts remain in [`../test-contract/`](../test-contract/README.md), which
runs its tests against a binding supplied on the command line.

`suites/` owns reusable behavioral requirements, cases, assertions and
completeness checks. `adapters/` contains test implementations of a seam;
`harnesses/` composes public calls for a test flow; `fixtures/` supplies named
worlds and values; `helpers/` contains narrow assertion or inspection tools.

## Topology

```text
test-lib/suites/<requirement>.js
  identical cases + fixtures + assertions + registrar
             |                       |
             v                       v
       test/*.test.js       experiments/*/test/*.test.js
             ^                       ^
             |                       |
  standard implementation    experiments/*/implementation/<variation>

          all pass     same assertion; exact todo failures pinned
```

Other test-only code is named by responsibility:

```text
test-lib/adapters/    test implementations of an interface seam
test-lib/harnesses/   multi-call reference-test flows
test-lib/fixtures/    named worlds and fixture values
test-lib/helpers/     small assertion, inspection and parser tools
```

An entry point selects an adapter, display name and, only in the variant
lane, an exact expected-failure profile. The profile classifies runner results;
it does not change suite cases or assertions, and the suite checks that each
expected failure still returns the exact moved key and still fails the shipped
refusal assertion. A target-local characterization test carries its own name;
do not cite it as evidence for a shared requirement.

## Directory naming

`test-lib/` contains reusable test-only code, while `suites/` contains
registrars for shared behavioral requirements. Keeping those registrars
outside a directory literally named `test/` prevents Node's default test
discovery from executing them as standalone tests.

These names describe repository organization only. They do not define a DCA
protocol, profile or conformance boundary.
