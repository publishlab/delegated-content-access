# Recorded fixture and vector tests

This directory owns tests that read recorded protocol fixtures or vector
bytes. Base behavior, optional-extension behavior and selected-extension
compositions each run from their own directory.

Run it with `npm run test:reference:vectors` from `js/`. `npm test` reaches these
files through its own glob over the package, but `npm run test:reference:public` and the
public `js/check` gate leave them out.

Keep tests here when their assertion depends on bytes recorded in
`verification/fixtures/` or `verification/vectors/`. Tests that generate their own inputs and
exercise reference behavior belong in `test/`, `test-reference/`, or an
extension's test directory according to ownership.
