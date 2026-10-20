# Conformance (Go, standard library)

The Go lane. The crypto binding comes from the Go standard library: nothing is linked, no OpenSSL takes part, and
`check` says so on its banner where the other lanes name a library. `v1/bridge/bridge.go` answers the
contract's seven operations; the next section says which of them the standard library answers and which
this lane.

- base64url is `encoding/base64`'s `RawURLEncoding`, which admits non-zero unused trailing bits, so the
  bridge decodes, re-encodes and compares against the input.
- AES-128/256-GCM is `crypto/aes` under `crypto/cipher`, which produces and consumes `ciphertext || tag` as
  one buffer. The key's width picks the cipher.
- ECDH over P-256 is `crypto/ecdh`, which agrees at the P-256 field width. The same package checks the
  uncompressed point, which the lane lays out at full coordinate width.
- HKDF-SHA-256 is `crypto/hkdf`, which takes `info` as a Go string; a Go string holds arbitrary octets, so
  the recorded 0x00 and high octets reach the derivation unchanged.
- RSA-OAEP is `crypto/rsa` with SHA-256 for both the digest and MGF1.

`encoding/json` reads the envelope, each request row and each input into maps of raw members, and
`closedMembers` refuses a member the contract does not name (`v1/bridge/bridge.go:604-632`). A struct would
drop members nobody declared and match declared ones without regard to case, so `{"Value":"..."}` would fill
a `value` field. The JWK inputs are the exception: `jwkMember` and `rsaJwkMember` unmarshal them into the
`primitives.JWK` and `primitives.RSAJWK` structs (`v1/bridge/bridge.go:571-594`,
`v1/internal/primitives/primitives.go:61-67`, `155-162`), so a JWK member matches without regard to case and
an undeclared one is dropped.

## Who answers what

`bridge.json` names the members of this binding and the member that answers each operation, and a run
with `--record` writes the same pairs as `operation=` rows. The member is the code that computes the answer
bytes or the accept/refuse verdict the corpus compares. The rows attribute; they claim no independence
from a library, and each `lane` row names the library call its lane code still rests on.
`stdlib` is Go's standard library crypto packages, and `lane` is code written in this lane.

- `decode-base64url`: `lane`. The alphabet loop, the length check and the re-encode comparison in
  `decodeStrictBase64url` decide every refusal; `encoding/base64`'s `RawURLEncoding` only decodes
  (`v1/bridge/bridge.go:696-719`).
- `hkdf-sha256`: `stdlib`.
- `open-aes-gcm`: `stdlib`.
- `seal-aes-gcm`: `stdlib`.
- `ecdh-p256`: `stdlib`.
- `p256-point`: `lane`. The lane pads the JWK's `x` and `y` to 32 octets and writes `0x04 || x || y`
  (`v1/internal/primitives/primitives.go:45-52`, `78-82`). `crypto/ecdh`'s `NewPublicKey` checks that the
  bytes name a point on the curve, and `Bytes` hands back the same bytes (`v1/bridge/bridge.go:522-526`).
  Naming the lane rather than `stdlib` is a reading of that split: the library validates, the lane lays out
  the bytes.
- `open-rsa-oaep`: `stdlib`.

## Boundary

This directory owns the Go standard-library binding, its bridge implementation, its `bridge.json` operation
declaration and its build. The runtime directory above owns the pinned toolchain
([`../README.md`](../README.md)). The [shared contract](../../_shared/contract/v1/bridge.md) owns
request and observation shapes; the [conformance README](../../README.md) owns selection, expected values,
comparison and result folding. Corpus cases, case selection and policy stay out of this lane. This lane
reads no vectors.

## Running it

    ./check                     # the Go lane's own gate
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs go/stdlib
    node conformance-primitives/_shared/driver/run.mjs go/stdlib --case ecdh/01

`../../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## The bridge

`bridge.json` names `go/stdlib/build-bridge` as the prepare step and the built binary as the command.

`go/stdlib/build-bridge` compiles `v1/bridge/bridge` beside its source and prints nothing when the compile
succeeds. The runner runs it outside the request budget, so the budget then covers one already-built
binary answering one batch. It asks the installer for `--print-bin` and `--print-cache`, both queries that
install nothing, so a cold cache stays cold and a run with no toolchain says so rather than pulling 70 MB
inside a conformance run. `GOTOOLCHAIN=local` keeps a `go` line in a `go.mod` from sending the build off to
fetch a different Go than the one the installer verified.

The runner then starts that binary directly, with no wrapper between it and the batch: one JSON document in
on stdin, one out on stdout, every diagnostic on stderr.

## The module

`v1` is one module, `conformance-primitives/go/v1`, holding one `main` package: the bridge. The library calls
it makes live in `v1/internal/primitives`, which it imports directly: JWK-to-key conversion, the AES-GCM
carrier, HKDF and RSA private-key import. That package reads no request and no refusal code, and the bridge
decides what a failure means for its own answer.
