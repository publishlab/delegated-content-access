# Conformance (Node)

The JavaScript lane. This lane's crypto binding comes from WebCrypto, reached through `globalThis.crypto.subtle` and
nothing else. `v1/bridge.mjs` answers the contract's seven operations: HKDF-SHA-256 under an empty salt,
AES-GCM under a 16 or a 32 octet key with the tag appended, an ECDH agreement over P-256, a public key
exported as its uncompressed SEC 1 point, and an RSA-OAEP decryption under SHA-256. base64url uses `Buffer`
plus the canonical rules the contract states, applied by decoding and re-encoding and comparing against the
input. `JSON.parse` reads the batch.

The bridge imports nothing outside this directory. It reaches no module elsewhere in the repository, reads
no vector and never opens the case corpus.

## Boundary

This directory owns the Node binding, its bridge implementation and its
`bridge.json` operation declaration. The
[shared contract](../_shared/contract/v1/bridge.md) owns request and observation
shapes; the [conformance README](../README.md) owns selection, expected values,
comparison and result folding. Cases, policy and endpoint behavior do not belong
in this lane.

## Running it

    ./check                     # every corpus set this lane declares, through v1/bridge.mjs
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

There is no `--base` and no `--cache-root`, because there is nothing to install.

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs node --case rsa-oaep/01

`../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## No pinned toolchain

This lane runs on whatever `node` is on `PATH`, the runtime the JavaScript reference already promises. The
runner starts the command as a program, so the bridge runs under the node its own shebang names,
whichever runtime `DCA_JS` gave the driver.

`bridge.json` names no `prepare`, so the command the runner starts is `v1/bridge.mjs` directly, with no
wrapper between it and the batch. One JSON document arrives on stdin and one leaves on stdout; every
diagnostic goes to stderr.

## What holding here does and does not say

A held run says this runtime's own WebCrypto answers the contract's shapes, refusal codes and bytes over the
corpus. It says nothing about the JavaScript reference, which this bridge does not call, and `js/check`
deliberately runs none of this.
