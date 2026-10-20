# Conformance (Rust, RustCrypto)

The RustCrypto lane. The crypto binding comes from the RustCrypto crates, written in Rust, with no OpenSSL,
`ring` or `aws-lc-rs` anywhere in the resolved set. `v1/bridge/main.rs` answers the contract's seven
operations through `v1/primitives/lib.rs`; the next section says which of them the crates answer and which
this lane.

- base64url is the `base64` crate's `URL_SAFE_NO_PAD` engine. It already refuses padding and non-zero
  trailing bits; the bridge still checks the alphabet, the length and the decode-and-re-encode comparison
  itself, as every lane does, so a later crate release that relaxes a default changes no answer.
- AES-128/256-GCM is `aes-gcm`'s `Aes128Gcm` and `Aes256Gcm` through the `Aead` trait, which produces and
  consumes `ciphertext || tag` as one buffer. The key's width picks the type.
- HKDF-SHA-256 is `hkdf` over `sha2`'s `Sha256`. `info` is a byte slice all the way to the HMAC, so the
  recorded 0x00 and high octets reach the derivation unchanged.
- ECDH over P-256 is `p256::ecdh::diffie_hellman`, whose `raw_secret_bytes` is a fixed 32-octet field
  element, so a leading zero octet stays.
- The P-256 point is `p256::PublicKey::from_sec1_bytes` in and `to_sec1_point(false)` out, each coordinate
  at full width. The import refuses a point off the curve.
- RSA-OAEP is `rsa`'s `Oaep::new::<Sha256>()`, which names one hash for the digest and for MGF1, with no
  label.

`serde_json` reads the batch into a `Value`, and the bridge compares each object's member names with the set
the contract names, so an unnamed member or one spelled in another case is refused. The JWK member handling
is lane code, as in every lane: the bridge reads `kty`, `crv` and the base64url members it needs through the
strict reader and hands octets to the crates' key routines.

## Who answers what

`bridge.json` names the members of this binding and the member that answers each operation, and a run
with `--record` writes the same pairs as `operation=` rows. The member is the code that computes the answer
bytes or the accept/refuse verdict the corpus compares. The rows attribute; they claim no independence
from a library, and each `lane` row names the library call its lane code still rests on.
`rustcrypto` is the RustCrypto crates pinned in `v1/Cargo.lock`, and `lane` is code written in this lane.

- `decode-base64url`: `lane`. The alphabet loop, the length rule and the re-encode comparison in
  `decode_strict_base64url` decide every refusal (`v1/primitives/lib.rs:34-53`). The decode itself is the
  `base64` crate's `URL_SAFE_NO_PAD`, which is not a RustCrypto crate either.
- `hkdf-sha256`: `rustcrypto`.
- `open-aes-gcm`: `rustcrypto`.
- `seal-aes-gcm`: `rustcrypto`.
- `ecdh-p256`: `rustcrypto`.
- `p256-point`: `rustcrypto`. Lane code pads the JWK's `x` and `y` and lays out `0x04 || x || y`
  (`v1/primitives/lib.rs:143-154`); the `p256` crate validates the point and writes the returned canonical
  SEC 1 bytes (`v1/primitives/lib.rs:139-160`). The operation's returned bytes therefore come from the named
  crate member, while the lane prepares the bytes it receives.
- `open-rsa-oaep`: `rustcrypto`.

## Boundary

This directory owns the RustCrypto binding, its bridge implementation, its `bridge.json` operation
declaration, its Cargo manifest and lock, and its build. The runtime directory above owns the pinned
toolchain ([`../README.md`](../README.md)). The [shared contract](../../_shared/contract/v1/bridge.md) owns
request and observation shapes; the [conformance README](../../README.md) owns selection, expected values,
comparison and result folding. Corpus cases, case selection and policy stay out of this lane. This lane
reads no vectors.

## Running it

    ./check                     # the RustCrypto lane's own gate
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane by its path:

    node conformance-primitives/_shared/driver/run.mjs rust/rustcrypto
    node conformance-primitives/_shared/driver/run.mjs rust/rustcrypto --case ecdh/01

`../../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Crates

[`v1/Cargo.toml`](v1/Cargo.toml) names each direct crate by an exact `=` version, and the committed
[`v1/Cargo.lock`](v1/Cargo.lock) is the pin for the whole resolved set: it records every crate's version and
its registry checksum, and no other file repeats a crate hash. The direct crates as the lock holds them:

- `aes-gcm` 0.11.1, features `aes` and `alloc`
- `p256` 0.14.0, features `arithmetic` and `ecdh`
- `hkdf` 0.13.0 and `sha2` 0.11.0
- `rsa` 0.9.10, with `sha2` 0.10.9 for its OAEP hash
- `base64` 0.23.1
- `serde_json` 1.0.151

Default features are off wherever they reach beyond these calls, so the resolved set carries no OS
random-number source. `rsa` 0.9 is the newest stable `rsa` release, and it is built on the digest 0.10
traits, a generation older than `sha2` 0.11, so its OAEP takes the 0.10 `Sha256` type. The manifest names
that release `sha2_010`, and the lock holds both.

Bumping a crate means editing its `=` version in `Cargo.toml`, regenerating the lock with the pinned cargo
and running `./check`; the vendor directory then moves with the lock's digest.

## Prepare and offline behaviour

`bridge.json` names `rust/rustcrypto/build-bridge` as the prepare step and
`rust/rustcrypto/v1/target/release/bridge` as the command. The runner runs the prepare step outside the
request budget, and it does two things:

- `cargo vendor --locked` copies the crates `Cargo.lock` names into `<cache>/vendor/<digest>`, where the
  digest is the first 16 hex digits of the lock's SHA-256. Cargo checks every downloaded crate against the
  lock's checksum ([`cargo vendor`](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)). A
  directory already there for the digest is reused, so this needs the network once per lock.
- `cargo build --frozen --release` builds from that directory through a generated
  `v1/.cargo/config.toml` and refuses both the network and a lock that would have to change
  ([`--frozen`](https://doc.rust-lang.org/cargo/commands/cargo-build.html)).

The prepare step asks the runtime's installer for `--print-base` and `--print-cache` only, so it never
downloads a toolchain; `./check` installs one first. The vendored crates are shared across checkouts,
because a directory named by the lock digest holds the same source wherever it is read. The build output
is not shared: it lands in this checkout's `v1/target/`, which git ignores along with the generated
`v1/.cargo/`, so two checkouts never run each other's binary. On 2026-09-30 the vendored source was 39 MiB
and `<cache>/cargo-home` 49 MiB.

## The package

`v1` is one Cargo package, `conformance-primitives-rustcrypto`, with two targets. `v1/primitives/lib.rs` is
the `primitives` library: the strict base64url reader, HKDF, the AES-GCM carrier, P-256 import, agreement
and encoding, and RSA import with the OAEP call. It reads no request and no refusal code. `v1/bridge/main.rs`
is the `bridge` binary: it reads the batch, calls the library, decides what a failure means for its own
answer and writes one JSON document on stdout. A panic is caught in `main`, reported on stderr and turned
into exit 1 with nothing on stdout.

## What RustCrypto asked of this bridge

- `PublicKey::from_sec1_bytes` reads every SEC 1 form, so a 33-octet compressed peer point imports and
  agrees, where Go's `crypto/ecdh` accepts only the 65-octet form. The contract carries only the
  uncompressed point, and the bridge passes the peer octets to the crate unchanged rather than adding a
  width check the crate does not make.
- `RsaPrivateKey::from_components` validates the key and recomputes the CRT values, so the JWK's `dp`, `dq`
  and `qi` are never read; a wrong `qi` still opens.
- `rsa` 0.9 answers a ciphertext one octet short, one octet long, numerically at or above the modulus, or
  with a flipped octet with one decryption error, which the bridge answers as `unseal_failed`.
- `aes-gcm`'s `decrypt` fails a carrier shorter than the tag the same way as a tag that does not verify, so
  it answers `authentication_failed` without a separate length check.
- `SecretKey::from_bytes` takes exactly 32 octets and refuses zero and a scalar at or above the group order;
  the bridge left-pads a shorter `d`, as the Go lane does, and refuses a wider one.
