# Shared test fixtures

This directory holds recorded inputs shared by more than one test tier. The
tiers that read them hold their own assertions, and the recorded vector sets
live under [`../vectors/`](../vectors/README.md).

Each versioned package includes a manifest stating exact membership and whether
portable base contracts or reference tests assert from each file.

This subtree is passive recorded data. It imports and executes nothing; each
consumer names the package and files it reads through its own manifest or test
configuration. The conformance-primitives corpus does not read these fixtures.

Start with [`protocol-v1/README.md`](protocol-v1/README.md).
