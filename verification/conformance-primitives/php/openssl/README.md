# Conformance (PHP, OpenSSL)

The PHP lane. ext-openssl provides the crypto binding, and the pinned build carries its own OpenSSL rather than
the host's, so this lane reports what openssl does with the bytes it is handed. `v1/bridge.php`
answers the contract's seven operations and `v1/crypto.php` holds what PHP has no single call for.
base64url is spelled out in the bridge, because PHP decodes only the standard alphabet: the bridge tests the
alphabet, translates, decodes through `base64_decode` in strict mode, then re-encodes and compares against
the input. AES-128-GCM and AES-256-GCM are `openssl_encrypt` and `openssl_decrypt`, which take the tag beside
the buffer, so `crypto.php` joins and splits the `ciphertext || tag` layout the contract names. ECDH-P256 is
`openssl_pkey_derive` over a PEM built from the JWK's own members and from the peer's raw point, since
openssl reads no JWK. HKDF-SHA256 is `hash_hkdf`. RSA-OAEP is the one primitive stock PHP will not do at
SHA-256: openssl performs the raw modexp under `OPENSSL_NO_PADDING` and the EME-OAEP steps of RFC 8017 are
PHP. `json_decode` reads the batch.

## Who answers what

`bridge.json` names the members of this binding and the member that answers each operation, and a run
with `--record` writes the same pairs as `operation=` rows. The member is the code that computes the answer
bytes or the accept/refuse verdict the corpus compares. The rows attribute; they claim no independence
from a library, and each `lane` row names the library call its lane code still rests on.
`openssl` is ext/openssl, `hash` is ext/hash, and `lane` is code written in this lane.

- `decode-base64url`: `lane`. `decodeStrictBase64url` applies every strict rule, and `base64_decode` only
  converts a spelling the lane has already accepted (`decodeStrictBase64url()` in `v1/bridge.php`).
- `hkdf-sha256`: `hash`. `hash_hkdf` is ext/hash over PHP's own SHA-256, so OpenSSL computes nothing here
  (`hkdfSha256()` in `v1/crypto.php`).
- `open-aes-gcm`: `openssl`.
- `seal-aes-gcm`: `openssl`.
- `ecdh-p256`: `openssl`. The PEM built from the JWK members around `openssl_pkey_derive` is lane code and
  does not change the member.
- `p256-point`: `lane`. No ext/openssl call takes part: `pointFromJwk` writes `0x04 || x || y` from the JWK's
  `x` and `y` (`pointFromJwk()` in `v1/crypto.php`), over ext/standard's `base64_decode` and `str_pad`.
- `open-rsa-oaep`: `lane`. ext/openssl's `openssl_private_decrypt` under `OPENSSL_NO_PADDING` does the raw
  private-key operation, `d` mod `n` (`observeOpenRsaOaep()` in `v1/bridge.php`); the EME-OAEP and MGF1-SHA-256
  decoding the corpus tests is PHP over ext/hash's `hash('sha256', ...)` (`mgf1Sha256()` and `oaepDecodeSha256()` in
  `v1/crypto.php`).

## Boundary

This directory owns the PHP and ext-openssl binding, its bridge implementation
and its `bridge.json` operation declaration. The runtime directory above owns the
pinned toolchain ([`../README.md`](../README.md)). The
[shared contract](../../_shared/contract/v1/bridge.md) owns request and observation
shapes; the [conformance README](../../README.md) owns selection, expected values,
comparison and result folding. Corpus cases, case selection, product code,
policy and endpoint behavior do not belong in this lane. This lane reads no
vectors.

## Running it

    ./check                     # the driver steps, through v1/bridge.php
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs php/openssl --case ecdh/01

`../../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## The bridge

`bridge.json` names `php/openssl/bridge` as both the command and the prepare step.

`php/openssl/bridge` is a wrapper in two forms. `--prepare` installs the pinned build when it is absent and pushes
one empty batch through it, which proves that this binary starts and answers; the runner runs that
first, outside the request budget. The bare form asks the installer for `--print-bin`, a query that
downloads nothing, and execs php on `v1/bridge.php`. A run that reaches it with no php installed says so and
exits nonzero rather than fetching 30 MB while a batch waits on stdin.

One JSON document arrives on stdin and one leaves on stdout. Nothing in the wrapper may write to stdout, so
every line it prints goes to stderr, where the runner reprints it beside a failure.

## Where a PHP warning goes

The CLI SAPI sends `display_errors` to stdout, so an ordinary warning would land in the middle of the
response and break it. `v1/bridge.php` pins `display_errors` to `stderr` before it reads anything. It does this
to meet the contract's rule that stdout carries one JSON value and nothing else.
