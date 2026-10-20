# Conformance (Node, OpenSSL)

The JavaScript lane. This lane's crypto binding comes from WebCrypto, reached through `globalThis.crypto.subtle` and
nothing else. `_source/js/v1/answer.mjs` answers the contract's seven operations: HKDF-SHA-256 under an empty salt,
AES-GCM under a 16 or a 32 octet key with the tag appended, an ECDH agreement over P-256, a public key
exported as its uncompressed SEC 1 point, and an RSA-OAEP decryption under SHA-256. base64url uses `Buffer`
plus the canonical rules the contract states, applied by decoding and re-encoding and comparing against the
input. `JSON.parse` reads the batch.

The answer source lives in [`../../_source/js/v1/`](../../_source/README.md), where every JavaScript lane can run
the same files. This lane runs `bridge.mjs`, the stdin entry there, which imports `answer.mjs` beside it. This
lane owns how that entry is started, which Node runs it, its `bridge.json` declaration and its check. The entry
imports only `node:fs` and `answer.mjs`, and `answer.mjs` imports nothing. Neither reaches a module elsewhere
in the repository, reads a vector or opens the case corpus.

## Who answers what

`bridge.json` names the members of this binding and the member that answers each operation, and a run
with `--record` writes the same pairs as `operation=` rows. The member is the code that computes the answer
bytes or the accept/refuse verdict the corpus compares. The rows attribute; they claim no independence
from a library, and each `lane` row names the library call its lane code still rests on.
`openssl` is the OpenSSL built into the pinned Node, reached through WebCrypto, and `lane` is code written in
this lane.

- `decode-base64url`: `lane`. `Buffer.from(value, 'base64url')` accepts `+`, `/`, padding and non-zero
  trailing bits; the alphabet test, the length rule and the re-encode comparison in `decodeStrictBase64url`
  decide every refusal (`decodeStrictBase64url()` in `_source/js/v1/answer.mjs`).
- `hkdf-sha256`: `openssl`.
- `open-aes-gcm`: `openssl`.
- `seal-aes-gcm`: `openssl`.
- `ecdh-p256`: `openssl`.
- `p256-point`: `openssl`. WebCrypto imports the JWK and `subtle.exportKey('raw')` writes the uncompressed
  point; the lane assembles no bytes (`observeP256Point()` in `_source/js/v1/answer.mjs`).
- `open-rsa-oaep`: `openssl`.

This lane writes no JWK member code: WebCrypto's own importer reads every JWK. The name `openssl` is a
reading, not a checked fact: the lane code shows only the `subtle` call, and Node's own source was not read
to confirm that each call reaches OpenSSL rather than Node's own code.

## Boundary

This directory owns the Node binding, its bridge implementation and its
`bridge.json` operation declaration. The
[shared contract](../../_shared/contract/v1/bridge.md) owns request and observation
shapes; the [conformance README](../../README.md) owns selection, expected values,
comparison and result folding. Cases, policy and endpoint behavior do not belong
in this lane.

## Running it

    ./check                     # every corpus set this lane declares, on Node 24 and on Node 22
    ./check --version 24        # on Node 24 alone
    ./check --record <file>     # also write the lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs node/openssl --case rsa-oaep/01

`../../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Pinned runtime

This lane runs on the Node release [`../install-toolchain`](../README.md) pins for the selected version,
never on the `node` on `PATH`, which runs the driver. `bridge.json` names `bridge` for both steps:
`bridge --prepare` installs that release when it is absent and sends it one empty batch, and `bridge` then
asks the installer `--print-bin` for the same version and execs that binary on `_source/js/v1/bridge.mjs`. The version
arrives as `DCA_VERSION`, which the lane check sets per run. One JSON document arrives on stdin and one
leaves on stdout; every diagnostic goes to stderr.

## What holding here does and does not say

A held run says this runtime's own WebCrypto answers the contract's shapes, refusal codes and bytes over the
corpus. It says nothing about the JavaScript reference, which this bridge does not call, and `js/check`
deliberately runs none of this.
