# Conformance (Go)

The Go lane. The crypto binding comes from the Go standard library: nothing is linked, no OpenSSL takes part, and
`check` says so on its banner where the other lanes name a library. `v1/bridge/bridge.go` answers the
contract's seven operations, each one a stock library call.

- base64url is `encoding/base64`'s `RawURLEncoding`, which admits non-zero unused trailing bits, so the
  bridge decodes, re-encodes and compares against the input.
- AES-128/256-GCM is `crypto/aes` under `crypto/cipher`, which produces and consumes `ciphertext || tag` as
  one buffer. The key's width picks the cipher.
- ECDH over P-256 and the uncompressed point are `crypto/ecdh`, which agrees at the P-256 field width and
  writes a point at full coordinate width.
- HKDF-SHA-256 is `crypto/hkdf`, which takes `info` as a Go string; a Go string holds arbitrary octets, so
  the recorded 0x00 and high octets reach the derivation unchanged.
- RSA-OAEP is `crypto/rsa` with SHA-256 for both the digest and MGF1.

`encoding/json` reads the batch into maps of raw members rather than structs: unmarshalling into a struct
drops members nobody declared and matches declared ones without regard to case, so `{"Value":"..."}` would
fill a `value` field and a member the contract does not name would pass unseen.

## Boundary

This directory owns the Go standard-library binding, its bridge implementation, its `bridge.json` operation
declaration and its pinned toolchain and build. The [shared contract](../_shared/contract/v1/bridge.md) owns
request and observation shapes; the [conformance README](../README.md) owns selection, expected values,
comparison and result folding. Corpus cases, case selection and policy stay out of this lane. This lane
reads no vectors.

## Running it

    ./check                     # the Go lane's own gate
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs go
    node conformance-primitives/_shared/driver/run.mjs go --case ecdh/01

`../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Toolchain

Go 1.27.0, pinned to the exact version and kept in step with `v1/go.mod`. Both per-arch SHA-256 values come
from the release table at https://go.dev/dl/, so bumping the pin means changing the version and both
checksums together.

    ./install-toolchain                    # install if absent, print BASE
    ./install-toolchain --base <dir>       # use this toolchain as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the toolchain under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the go binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

Inside the cache dir the toolchain sits at `<cache>/go1.27.0`, `GOCACHE` at `<cache>/build` and `GOPATH` at
`<cache>/gopath`, so build output lands beside the toolchain that produced it and never in the host's home
directory. The download was roughly 70 MB and the unpacked toolchain 240 MiB on 2026-08-27; for the current
number, `du -sh "$(./install-toolchain --print-base)"`.

Nothing goes on `PATH`, here or system-wide, so `go` stays absent from a plain shell on a machine that has
this toolchain. `--print-bin` names the binary, and you run it by that name:

    "$(./install-toolchain --print-bin)" version

That form installs nothing, so run the installer once first, or drop the flag and let the same substitution
install and then print the directory. Either way the installer names the directory on stderr, `installed to
<path>` or `already present at <path>`.

`bridge.json` names `go/build-bridge` as the prepare step and the built binary as the command.

## The bridge

`go/build-bridge` compiles `v1/bridge/bridge` beside its source and prints nothing when the compile
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
