# Conformance (workerd, BoringSSL)

The workerd lane. This lane's crypto binding comes from workerd's WebCrypto, reached through
`globalThis.crypto.subtle` and nothing else. workerd implements `crypto.subtle` in C++ under
`src/workerd/api/crypto/` and calls the BoringSSL it links for every operation the contract names.

The lane runs the shared answer module, [`../../_source/js/v1/answer.mjs`](../../_source/README.md), unchanged:
the same answering code the Node, Deno and Bun lanes run. It does not run `bridge.mjs`, their stdin entry,
because a workerd isolate cannot: fd 0 reads empty inside it and `process.exitCode` ends nothing. This lane
owns `worker.mjs`, the Worker that imports `answer.mjs`, `config.capnp`, the `bridge` launcher, its
`bridge.json` declaration and its check. `answer.mjs` imports nothing and `worker.mjs` imports only
`answer.mjs` and the batch; neither reaches a module elsewhere in the repository, reads a vector or opens the
case corpus.

## Who answers what

`bridge.json` names the members of this binding and the member that answers each operation, and a run
with `--record` writes the same pairs as `operation=` rows. The member is the code that computes the answer
bytes or the accept/refuse verdict the corpus compares. The rows attribute; they claim no independence
from a library, and each `lane` row names the library call its lane code still rests on.
`boringssl` is the BoringSSL built into the pinned workerd, reached through WebCrypto, and `lane` is code
written in the shared answer source.

- `decode-base64url`: `lane`. workerd's `Buffer`, from its `nodejs_compat` layer, decodes
  `Buffer.from(value, 'base64url')`; the alphabet test, the length rule and the re-encode comparison in
  `decodeStrictBase64url` decide every refusal (`decodeStrictBase64url()` in `_source/js/v1/answer.mjs`).
- `hkdf-sha256`: `boringssl`. `hkdf()` in `hkdf.c++` calls `ncrypto::hkdfInfo`, and Node's `ncrypto` v1.1.4,
  which workerd builds in, calls BoringSSL's `HKDF()` under `OPENSSL_IS_BORINGSSL` (`src/ncrypto.cpp:1864-1866`
  at that tag).
- `open-aes-gcm`: `boringssl`. `AesGcmKey` in `aes.c++` picks `EVP_aes_128_gcm()` or `EVP_aes_256_gcm()` by
  key width (`lookupAesGcmType`, `aes.c++:36`), decrypts through `EVP_DecryptInit_ex` and sets the tag with
  `EVP_CTRL_GCM_SET_TAG` (`aes.c++:327`).
- `seal-aes-gcm`: `boringssl`. The same class encrypts through `EVP_EncryptInit_ex` and appends the tag it
  reads with `EVP_CTRL_GCM_GET_TAG` (`aes.c++:258`).
- `ecdh-p256`: `boringssl`. `ec.c++:238` calls `ECDH_compute_key`.
- `p256-point`: `boringssl`. WebCrypto imports the JWK, and `Ec::getRawPublicKey` writes the point with
  `EC_POINT_point2cbb` and `POINT_CONVERSION_UNCOMPRESSED` (`ec.c++:87`, `:108`); the lane assembles no bytes
  (`observeP256Point()` in `_source/js/v1/answer.mjs`).
- `open-rsa-oaep`: `boringssl`. `rsa.c++:162-168` sets `RSA_PKCS1_OAEP_PADDING` and the OAEP and MGF1
  digests, and `rsa.c++:651` decrypts with `EVP_PKEY_decrypt`.

The file and line references are to workerd's
[`src/workerd/api/crypto/`](https://github.com/cloudflare/workerd/tree/v1.20261008.1/src/workerd/api/crypto) at
the pinned tag `v1.20261008.1`, and to [`nodejs/ncrypto`](https://github.com/nodejs/ncrypto/tree/v1.1.4) at
`v1.1.4`, the ncrypto archive workerd's `build/deps/gen/deps.MODULE.bazel` names at that tag. They were traced
through that source when the lane landed. The trace reads source, not the binary: nothing here checks that the
released binary was built from exactly these files. The BoringSSL revision itself is cited in
[`../README.md`](../README.md#boringssl-at-this-pin). A workerd pin bump rereads these files at the new tag.

## Boundary

This directory owns the workerd binding, its Worker entry and configuration, its bridge launcher and its
`bridge.json` operation declaration. The [shared contract](../../_shared/contract/v1/bridge.md) owns request
and observation shapes; the [conformance README](../../README.md) owns selection, expected values, comparison
and result folding. Cases, policy and endpoint behavior do not belong in this lane.

## Running it

    ./check                     # every corpus set this lane declares, on workerd 1.20261008.1
    ./check --version 1         # the same, naming the token
    ./check --record <file>     # also write the lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs workerd/boringssl --case rsa-oaep/01

`../../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Pinned runtime

This lane runs on the workerd release [`../install-toolchain`](../README.md) pins for the selected version,
never on a `workerd` on `PATH`. `bridge.json` names `bridge` for both steps: `bridge --prepare` installs that
release when it is absent and sends it one empty batch, and `bridge` then asks the installer `--print-bin`
for the same version. The version arrives as `DCA_VERSION`, which the lane check sets per run.

Each batch runs as `workerd test`, with no HTTP, no socket and no listener. `bridge` makes a `mktemp -d`
directory, copies `config.capnp`, `worker.mjs` and `answer.mjs` into it and writes stdin there as `batch.txt`.
`config.capnp` embeds `batch.txt` as a text module, and `workerd test` runs the Worker's `test()` handler once.
The handler passes the batch text to `answerLine` and prints the line it returns with one `console.log`. A batch
the bridge cannot serve makes the handler write the `bridge: ...` line `faultLine` returns with `console.error`
and throw, and
`workerd test` then exits 1. `bridge` copies workerd's stdout to its own only when workerd exits 0; otherwise
it writes nothing on stdout and exits 1. It drops workerd's own test-runner lines from stderr, `[ TEST ] main`,
`[ PASS ] main`, `[ FAIL ] main` and `Tests failed!`, because a bridge never prints a verdict or a pass word,
and passes every other stderr line through. A trap removes the directory on exit.

`config.capnp` pins the compatibility date `2026-08-04`. `answer.mjs` needs the global `Buffer`, which
`nodejs_compat` provides, and workerd turns `nodejs_compat` on by default from that date: at `2026-08-03` the
first base64url decode throws `ReferenceError: Buffer is not defined`. The config does not name the flag,
because naming a default flag makes workerd print a warning on every run. workerd refuses a date later than
the day it runs, so a date is never picked ahead of the release it pairs with.

## Output routing

In test mode `console.log` writes to workerd's stdout with no prefix, `console.error` writes to stderr, and
`process.stdout.write` would add a `stdout: ` prefix. workerd documents none of this, so the lane measured it at
the pin: on 2026-10-09 all 29 corpus cases in one batch, the largest batch the driver sends, came back from
`console.log` as one 3104-byte line, byte-identical to the Node lane's stdout for the same batch. A pin bump
repeats that measurement.

## What holding here does and does not say

A held run says this runtime's own WebCrypto answers the contract's shapes, refusal codes and bytes over the
corpus. It says nothing about the JavaScript reference, which this bridge does not call, and `js/check`
deliberately runs none of this.
