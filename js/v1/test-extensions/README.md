# Selected-extension composition tests

This directory holds tests that intentionally compose two or more optional
extensions. A test inside either extension would leave that extension's test
package importing a sibling, so it lives here instead.

## Where a test goes

| What the test proves | Put it in |
| --- | --- |
| Base source and barrels load with every extension removed | `test-base/` |
| A portable implementation contract | `test-contract/` |
| One optional extension | `extensions/<name>/test/` |
| Two or more optional extensions working together | `test-extensions/` |
| One complete scenario for a named protocol profile | `test-profiles/` |
| A JavaScript reference implementation behavior | `test/` |
| An extracted reference target | `test-reference/<target>/` |
| A deliberately different or failing implementation | `experiments/<experiment>/test/` |

Place each test by ownership. If removing one extension should remove the
test, it belongs to that extension. If the test remains meaningful only while
several named extensions are selected, it belongs here. Code inside one
extension, including its tests, must not import a sibling extension.

For example, `client-bound-period-chain.test.js` belongs here because it proves
the client-bound transport and period-chain extensions work together. An ECDH
seal/open test belongs under `extensions/client-bound-transport/test/`.

`support/` holds composition code a test here needs and no shipped role owns,
for instance an issuer that selects two extensions at once. The composition
run collects only the `*.test.js` files here, and nothing under `support/`
ships.

`npm run test:reference:compositions` runs this directory. `npm test` reaches these
files through its own glob over the package, but no named single-extension command
runs them.

This README owns the test-purpose description for the files directly under
this directory; they need no per-test README. When a new combination lands,
record here the selected protocol profiles or implementation extensions, the
boundary the tests exercise and any applicable recorded or independent
evidence. Passing this JavaScript composition lane remains implementation
evidence and does not by itself establish a protocol-conformance claim.

[`../test-profiles/README.md`](../test-profiles/README.md) indexes meaningful
profile combinations that live here. Keep the executable test here when it
requires sibling implementation extensions; do not copy it into the profile
directory merely to make that index self-contained.
