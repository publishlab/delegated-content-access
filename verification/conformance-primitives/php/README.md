# Conformance (PHP)

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

## Boundary

This directory owns the PHP and ext-openssl binding, its bridge implementation,
its `bridge.json` operation declaration and its pinned toolchain. The
[shared contract](../_shared/contract/v1/bridge.md) owns request and observation
shapes; the [conformance README](../README.md) owns selection, expected values,
comparison and result folding. Corpus cases, case selection, product code,
policy and endpoint behavior do not belong in this lane. This lane reads no
vectors.

## Running it

    ./check                     # the driver steps, through v1/bridge.php
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs php --case ecdh/01

`../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Toolchain

PHP 8.4.23, a static `php-cli` built by crazywhalecc/static-php-cli and served from `dl.static-php.dev`,
taken from the `bulk` distribution, which is the one carrying the `openssl` extension.
It links nothing on the host and has no glibc floor to miss. Linux x86_64 and aarch64 are pinned; the
x86_64 line is the one this lane has executed, and the aarch64 line stays unproven until an aarch64 run.

    ./install-toolchain                    # install if absent, print BASE
    ./install-toolchain --base <dir>       # use this install as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the install under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the php binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

The tarball holds one file, so the install is that one binary, at `<cache>/php-8.4.23-cli-linux-<arch>/php`.
This lane compiles nothing, writes no artefact and keeps no bytecode cache. Nothing goes on `PATH`;
`--print-bin` prints the binary's path, and the binary is run from that path. The download was roughly 30 MB and the
unpacked binary 30 MiB on 2026-08-27.

The two SHA-256 values in the installer were computed by this project over the
files as downloaded. Their publisher supplies no digest for these files. A
mismatch therefore identifies a changed file without saying why it changed,
and the installer refuses it explicitly.

The installer also refuses, each by name and with what to do about it: an OS that is not Linux, an
architecture nothing is published for, an absent `curl` or a fetch that did not complete, a checksum
mismatch, an unpacked binary that will not run here or that has no `openssl`, and a `--base` holding no
`php` or one without `openssl`. `--base` is for a machine that already has a PHP and for
every host the pin does not cover, and the binary it names is asked for `openssl` before the path is handed
back.

`bridge.json` names `php/bridge` as both the command and the prepare step.

## The bridge

`php/bridge` is a wrapper in two forms. `--prepare` installs the pinned build when it is absent and pushes
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
