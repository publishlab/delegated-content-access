# Conformance (Bun, BoringSSL)

The Bun lane. This lane's crypto binding comes from Bun's WebCrypto, reached through `globalThis.crypto.subtle`
and nothing else. Bun takes its WebCrypto from WebKit's WebCore, whose `CryptoAlgorithm*OpenSSL.cpp` files
call the OpenSSL API, and Bun links BoringSSL to answer those calls.

The lane runs the shared JavaScript answer source in [`../../_source/js/v1/`](../../_source/README.md)
unchanged: `bridge.mjs`, the stdin entry, and `answer.mjs`, which it imports, the same files the Node and
Deno lanes run. This lane owns how the entry is started, which Bun runs it, its `bridge.json` declaration and
its check. The entry imports only `node:fs`, which Bun provides through its Node compatibility layer, and
`answer.mjs`, which imports nothing. Neither reaches a module elsewhere in the repository, reads a vector or
opens the case corpus.

## Who answers what

`bridge.json` names the members of this binding and the member that answers each operation, and a run
with `--record` writes the same pairs as `operation=` rows. The member is the code that computes the answer
bytes or the accept/refuse verdict the corpus compares. The rows attribute; they claim no independence
from a library, and each `lane` row names the library call its lane code still rests on.
`boringssl` is the BoringSSL built into the pinned Bun, reached through WebCrypto, and `lane` is code written
in the shared answer source.

- `decode-base64url`: `lane`. Bun's own `Buffer`, from its Node compatibility layer, decodes
  `Buffer.from(value, 'base64url')` and accepts `+`, `/`, padding and non-zero trailing bits; the alphabet
  test, the length rule and the re-encode comparison in `decodeStrictBase64url` decide every refusal
  (`decodeStrictBase64url()` in `_source/js/v1/answer.mjs`).
- `hkdf-sha256`: `boringssl`. `CryptoAlgorithmHKDFOpenSSL.cpp` calls `HKDF()`.
- `open-aes-gcm`: `boringssl`. `CryptoAlgorithmAES_GCMOpenSSL.cpp` calls the `EVP_aes_*_gcm` ciphers.
- `seal-aes-gcm`: `boringssl`. The same file and ciphers.
- `ecdh-p256`: `boringssl`. `CryptoAlgorithmECDHOpenSSL.cpp` derives through `EVP_PKEY_derive`.
- `p256-point`: `boringssl`. WebCrypto imports the JWK and `subtle.exportKey('raw')` writes the uncompressed
  point; the lane assembles no bytes (`observeP256Point()` in `_source/js/v1/answer.mjs`).
- `open-rsa-oaep`: `boringssl`. `CryptoAlgorithmRSA_OAEPOpenSSL.cpp` decrypts with `RSA_PKCS1_OAEP_PADDING`.

The pinned Bun names its BoringSSL in `process.versions.boringssl`: `41bf9b59c2ebf277a7aa427e1ecad5cc80dd4d4f`
for Bun 1.4.2, and the lane check prints it in its banner. Bun reports `process.versions.openssl` as `1.1.0`,
a compatibility string that names no library Bun links, so the lane does not cite it.

The calls above are a qualified reading, not a checked fact of this lane. They come from reading Bun's
[`src/jsc/bindings/webcrypto/`](https://github.com/oven-sh/bun/tree/bun-v1.4.2/src/jsc/bindings/webcrypto) at
the tag `bun-v1.4.2` once, before the lane was added, and were not re-derived from source when it landed. The
lane code shows only the `subtle` call. A Bun pin bump rereads those files at the new tag.

## Boundary

This directory owns the Bun binding, its bridge wrapper and its `bridge.json` operation declaration. The
[shared contract](../../_shared/contract/v1/bridge.md) owns request and observation shapes; the
[conformance README](../../README.md) owns selection, expected values, comparison and result folding.
Cases, policy and endpoint behavior do not belong in this lane.

## Running it

    ./check                     # every corpus set this lane declares, on Bun 1.4.2
    ./check --version 1         # the same, naming the token
    ./check --record <file>     # also write the lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs bun/boringssl --case rsa-oaep/01

`../../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Pinned runtime

This lane runs on the Bun release [`../install-toolchain`](../README.md) pins for the selected version, never
on a `bun` on `PATH`. `bridge.json` names `bridge` for both steps: `bridge --prepare` installs that release
when it is absent and sends it one empty batch, and `bridge` then asks the installer `--print-bin` for the
same version and execs `bun run --no-env-file <absolute path of _source/js/v1/bridge.mjs>` from `/`. The
version arrives as `DCA_VERSION`, which the lane check sets per run. One JSON document arrives on stdin and
one leaves on stdout; every diagnostic goes to stderr.

The wrapper picks the cwd because Bun reads it. The driver starts every bridge with its cwd in the
conformance directory. A `bunfig.toml` in the cwd can name a `preload` script, and Bun runs that script before
the bridge, so a preload that prints `PRELOADED` puts that line ahead of the batch on stdout. A `.env` in the
cwd lands in the environment. Starting Bun from `/` with `--no-env-file` keeps both out.

## What holding here does and does not say

A held run says this runtime's own WebCrypto answers the contract's shapes, refusal codes and bytes over the
corpus. It says nothing about the JavaScript reference, which this bridge does not call, and `js/check`
deliberately runs none of this.
