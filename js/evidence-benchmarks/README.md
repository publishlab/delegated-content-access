# Benchmarks

Each directory here holds one set of scripts that gathers data or evidence for a
design decision. No benchmark depends on another, and no lane runs any of them:
measurement captures are opt-in; ordinary tests can exercise the runner. Read a directory's README for
what it measures and how to run it.

`chain-keys-bounds/` measures what the chain-key limits cost at their
ceilings: chain construction, period-key projection, client candidate trial, and
request and response bytes. The **Bounds** section of
[`spec-profile--chain-keys.md`](../../docs/spec-profile--chain-keys.md) sets
those limits.

`compression-before-sealing/` compares wire sizes when content is compressed
before encryption with transport compression applied after encryption.

`chain-keys-wire-cost/` measures what period-key-only, period-key-plus-chain
and chain-only supply cost in the publisher's delivery and in one unlock
exchange, raw, gzip and Brotli, on renders and exchanges the reference
produces. It reports the break-even period-key count and the marginal bytes.

`scenario-bench/` runs full publisher, issuer and client scenarios, including a
[matched comparison of period keys/chains and content groups](scenario-bench/README.md#compare-period-keys-and-chains-with-content-groups),
with exact wire captures, compression sizes, work counters and retained-reader
workloads. Its local `check` verifies the tool independently of reference tests.
