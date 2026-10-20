# Conformance (Deno, RustCrypto and AWS-LC)

The Deno lane. This lane's crypto binding comes from Deno's WebCrypto, reached through
`globalThis.crypto.subtle` and nothing else. Deno implements `crypto.subtle` in Rust, in its `ext/crypto`
crate, and that crate answers the contract's operations from two providers: RustCrypto crates for AES-GCM,
RSA-OAEP and P-256, and aws-lc-rs for HKDF. The binding's name, `rustcrypto-awslc`, names both.

The lane runs the shared JavaScript answer source in [`../../_source/js/v1/`](../../_source/README.md)
unchanged: `bridge.mjs`, the stdin entry, and `answer.mjs`, which it imports, the same files
the Node lane runs. This lane owns how the entry is started, which Deno runs it, its `bridge.json` declaration and
its check. The entry imports only `node:fs`, which Deno provides through its Node compatibility layer, and
`answer.mjs`, which imports nothing. Neither reaches a module elsewhere in the repository, reads a vector or
opens the case corpus.

## Who answers what

`bridge.json` names the members of this binding and the member that answers each operation, and a run
with `--record` writes the same pairs as `operation=` rows. The member is the code that computes the answer
bytes or the accept/refuse verdict the corpus compares. The rows attribute; they claim no independence
from a library, and each `lane` row names the library call its lane code still rests on.
`rustcrypto` is the RustCrypto crates the pinned Deno compiles in, `awslc` is aws-lc-rs, the Rust binding to
AWS-LC that the pinned Deno compiles in, and `lane` is code written in the shared answer source.

- `decode-base64url`: `lane`. Deno's own `Buffer`, from its Node compatibility layer, decodes
  `Buffer.from(value, 'base64url')` and accepts `+`, `/`, padding and non-zero trailing bits; the alphabet
  test, the length rule and the re-encode comparison in `decodeStrictBase64url` decide every refusal
  (`decodeStrictBase64url()` in `_source/js/v1/answer.mjs`).
- `hkdf-sha256`: `awslc`. `ext/crypto` derives HKDF through `aws_lc_rs::hkdf`, aws-lc-rs 1.16.3.
- `open-aes-gcm`: `rustcrypto`. The `aes-gcm` crate, 0.10.3.
- `seal-aes-gcm`: `rustcrypto`. The `aes-gcm` crate, 0.10.3.
- `ecdh-p256`: `rustcrypto`. The `p256` crate, 0.13.2, imports the JWK and agrees the secret.
- `p256-point`: `rustcrypto`. The `p256` crate, 0.13.2, imports the JWK, and `subtle.exportKey('raw')` writes
  the uncompressed point; the lane assembles no bytes (`observeP256Point()` in `_source/js/v1/answer.mjs`).
- `open-rsa-oaep`: `rustcrypto`. The `rsa` crate, 0.9.10, opens the ciphertext, and the `sha2` crate
  supplies the SHA-256 that OAEP hashes with.

The crate names and versions above are a qualified reading, not a checked fact of this lane. They come from
reading Deno's `ext/crypto` source and its `Cargo.lock` at the tag
[`v2.9.7`](https://github.com/denoland/deno/tree/v2.9.7/ext/crypto) once, before the lane was added, and were
not re-derived from source when it landed. The lane code shows only the `subtle` call. Deno has moved
operations between providers across releases: its `ext/crypto/lib.rs` derives HKDF through `ring` at
`v2.0.0` and through `aws_lc_rs` at `v2.5.0`. A Deno pin bump therefore rereads `ext/crypto` at the new tag
and corrects this list, the member descriptions in `bridge.json` and, if a provider leaves, the binding's
name.

## Boundary

This directory owns the Deno binding, its bridge wrapper and its `bridge.json` operation declaration. The
[shared contract](../../_shared/contract/v1/bridge.md) owns request and observation shapes; the
[conformance README](../../README.md) owns selection, expected values, comparison and result folding.
Cases, policy and endpoint behavior do not belong in this lane.

## Running it

    ./check                     # every corpus set this lane declares, on Deno 2.9.7
    ./check --version 2         # the same, naming the token
    ./check --record <file>     # also write the lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs deno/rustcrypto-awslc --case rsa-oaep/01

`../../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Pinned runtime

This lane runs on the Deno release [`../install-toolchain`](../README.md) pins for the selected version,
never on a `deno` on `PATH`. `bridge.json` names `bridge` for both steps: `bridge --prepare` installs that
release when it is absent and sends it one empty batch, and `bridge` then asks the installer `--print-bin`
for the same version and execs `deno run --no-config --no-prompt _source/js/v1/bridge.mjs`. The version
arrives as `DCA_VERSION`, which the lane check sets per run. One JSON document arrives on stdin and one
leaves on stdout; every diagnostic goes to stderr.

The wrapper pins how Deno starts the file. `--no-config` stops Deno from reading a `deno.json` it finds up the
directory tree. `--no-prompt` turns a missing permission into an error rather than a prompt that waits out
the batch budget; the file reads stdin and writes stdout and stderr, which Deno allows with no permission
flag. `DENO_DIR` points into the runtime's cache dir and `DENO_NO_UPDATE_CHECK=1` stops the release check
on every start.

## What holding here does and does not say

A held run says this runtime's own WebCrypto answers the contract's shapes, refusal codes and bytes over the
corpus. It says nothing about the JavaScript reference, which this bridge does not call, and `js/check`
deliberately runs none of this.
