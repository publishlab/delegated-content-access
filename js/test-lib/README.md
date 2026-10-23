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

`suites/envelope-behavior.js` owns carrier-independent envelope recovery, saved
envelope replay, wrong-recipient refusal and BIND relabel assertions. The stock
key-sealing tests and nonce-free-envelope comparison each supply their own
adapter. Period and chain coordinates here exercise supported envelope BIND
vocabulary; they select no optional derivation implementation and establish no
complete optional-profile conformance claim. Carrier layouts, primitive known
answers and experimental selector controls stay with their owning tests.

Each `suites/` module represents one reusable behavioral requirement. Do not
move unrelated test code here just because a test uses it.

Discovered `.test.js` entry points live in `../test-reference/`, extension-owned
`../extensions/<name>/test/`, [`../test/`](../test/README.md) and
[`../experiments/`](../experiments/README.md). Portable public-boundary
contracts remain in [`../test-contract/`](../test-contract/README.md), which
runs its tests against a binding supplied on the command line.

`suites/` owns reusable behavioral requirements, cases, assertions and
completeness checks. `harnesses/` composes public calls for a test flow;
`fixtures/` supplies named worlds and values; `helpers/` contains narrow
assertion or inspection tools.

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

## Selected fixtures and evidence limits

`harnesses/client.js` composes production client components with period-key
relay selected by default; production composition defaults that option off.
`harnesses/issuer-endpoint.js` counts real endpoint calls with period-key input
selected. Its `requestFor` uses the same selected client. These are testing
configurations, including the public `reference.mjs` testing export, rather than
assertions about production defaults. Tests claiming defaults must construct the
production component directly or explicitly disable the fixture selection.

`harnesses/sealedSection.js` models a whole-section walk for construction comparisons;
production issuer results are per coordinate. `harnesses/bindSelfTest.js` is a fixture
classifier, not an installed issuer diagnostic. `harnesses/openAndPlace.js` models an
application hand-off, not a shipped presenter. Consuming tests must preserve
these limits when citing results. Real-role examples include
`../test-reference/core-issuer/jwt-proof.test.js`,
`../test-reference/integration-client/createBrowserClient.test.js` and
`../test-reference/integration-client/client-lifecycle.test.js`; the lifecycle
test still models its application's presentation guard.

Feature-owned support stays with its owning tests. The client-bound sealed
cache alternative lives under `../extensions/client-bound-transport/test/_lib/`,
the lifecycle model under `../test-reference/integration-client/support/`, and
reference endpoint-port cases and driver under `../test-vectors/support/`.

The envelope behavior suite accepts the owning file's test registrar as its
optional second argument. The baseline owner passes its selection-aware registrar,
so ordinary reference assertions do not silently enter a portable selection.
Extension owners use the default Node registrar for their local test runs.
