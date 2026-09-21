# Benchmarks

Each directory here holds one set of scripts that gathers data or evidence for a
design decision. No benchmark depends on another, and no lane runs any of them:
neither `sh js/check` nor the npm scripts name them. Read a directory's README for
what it measures and how to run it.

`period-chain-bounds/` measures what the period-chain limits cost at their
ceilings: chain construction, exact-leaf projection, client candidate trial, and
request and response bytes. The **Bounds** section of
[`spec--period-key-chains.md`](../../../docs/spec--period-key-chains.md) sets
those limits.

`compression-before-sealing/` compares wire sizes when content is compressed
before encryption with transport compression applied after encryption.
