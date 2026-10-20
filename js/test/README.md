# Reference JavaScript tests

The reference implementation's cross-layer JavaScript regression tests run from
this directory. Tests with one primary source layer live in sibling
`test-reference/` directories. Every implementation or alternate profile admitted here must satisfy
every registered requirement it exercises. Expected failures and deliberately
deviant targets belong in `experiments/<experiment>/test/`; a passing profile or a comparative
control may remain here when it is part of the standard green contract.

## One invariant, injected implementations

A behavior deliberately registered against more than one implementation target
has one definition under [`../test-lib/suites/`](../test-lib/README.md). The
test-only library's suite owns its cases,
fixtures, assertions, readable diagnostics, completeness checks and registrar.
Keep each `.test.js` entry point thin: it hands one implementation to that
shared registrar.

The same shared invariant may then be pointed at a deliberately deviant
implementation from [`../experiments/`](../experiments/README.md). Do not:

- copy or rewrite the invariant in a variant entry point;
- import a `.test.js` file, because importing it registers that file's target;
- weaken a fixture or assertion for a variant;
- let an implementation adapter perform the behavior under test.

An adapter may translate the implementation's module or call shape into the
small interface the invariant consumes.

The same invariant runs against both implementations:

```text
shared invariant + reference implementation -> pass
shared invariant + deviant implementation  -> exposed failure
```

For the relabel pilot, the topology is:

```text
core-shared/                         stable primitives
    |                                      |
    v                                      v
reference binding            experiments/_implementation/bind-on-accessGroup/
    |                                      |
    v                                      v
test-reference/core-shared--  experiments/bind-on-accessGroup/
publisher-issuer/binding-     test/comparison.test.js
relabel-invariant.test.js
    ^                                      ^
    |                                      |
    +------------------+-------------------+
                       |
test-lib/suites/binding-relabel.js
  cases + carriers + fixtures + assertions + registrar

    all pass                    named failures exposed
```

Each entry point combines the shared registrar with one implementation; the
suite module does not import or choose either target.
`core-shared/` never imports a variant, and one variant never imports another.

## Discovery

`npm run test:reference:base` recursively runs every `*.test.js` file under
`test/` and `test-reference/`. `test/test-inventory.json` assigns each file an
authority group and a target, and its inventory test keeps that list aligned
with recursive discovery. `test-lib/` sits outside discovery and holds
test-only reusable library code; behavioral registrars live in
`test-lib/suites/`, while other library code is named under `harnesses/`,
`fixtures/` or `helpers/`. Feature-owned helpers live with their tests.

`npm run check:boundaries` owns the extension-boundary and extension-absent
barrel smoke tests under `test-base/`. Portable contracts have their own
`test:contract` family. Named reference-extension commands run one extension,
and `test:reference:compositions` runs tests that require two or more. See
`../README.md` for the complete command map.

Complete scenarios for named protocol profiles live under
[`../test-profiles/`](../test-profiles/README.md). They compose reference
components through real role seams and link back to focused tests here; they do
not import or wrap these `*.test.js` files.

## Relabel-invariant pilot

`../test-lib/suites/binding-relabel.js` owns the relabel cases, the two
carrier algorithms they run under, fixtures, assertions, completeness
accounting and the registrar used by the standard and accessGroup-only runs.
Both entry points invoke that one registrar; neither carries a registration
loop. When a required refusal fails, the invariant validates the exact
returned key inside the expected-failure path, so the suite registers no
second test beside it. The variant entry supplies its implementation, display
name and expected-failure classification; a refusal on a pinned expected
failure turns the completeness test red so it can be reclassified. For moved
content keys, that path opens the source ciphertext with its original AAD. For
moved periodKeys, it unwraps a source contentKey and opens source-period
content. These checks therefore separate an issuer-side access refusal from an
honest client failing at the destination slot.
