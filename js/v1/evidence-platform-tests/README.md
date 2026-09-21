# Platform evidence tests

These hand-run Node and browser checks record empirical runtime or host
behavior: WebCrypto key handling, structured cloning and browser storage.
They are evidence, not formal proofs, DCA correctness tests, conformance cases
or gated npm lanes.

Run a Node check from `js/v1/` with its path under this directory, for
example:

```sh
node evidence-platform-tests/nonExtractabilityBoundary.mjs
```

Open `browser-crypto-tests.html` in a browser for the browser and storage
checks. A failing Node check exits nonzero and the browser page marks the
failing row red; either one means the recorded platform behavior did not hold in
that environment.
