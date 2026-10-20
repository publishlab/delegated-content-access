# Conformance (.NET, base class library)

The .NET lane. The crypto binding comes from the base class library, and the project names no `PackageReference`
at all, so this lane reports what a stock SDK does with the recorded octets. `v1/bridge/Bridge.cs` answers
the contract's seven operations: decode a strict base64url field,
derive octets with HKDF-SHA-256, open and seal an AES-GCM carrier, agree a P-256 ECDH secret, encode a
P-256 public point, and open an RSA-OAEP ciphertext. Five are one base class library call each; the base64url
decode and the point encoding are written in this lane (Who answers what, below).

`System.Buffers.Text`'s `Base64Url` decodes, and it accepts a padded spelling and refuses non-zero trailing
bits, so it applies part of the strict field rule; the bridge checks the alphabet, the length and the
re-encode comparison itself, so the answer stays the same if a runtime update changes how much of the rule `Base64Url` applies.
`AesGcm` runs AES-128-GCM and AES-256-GCM, picking the cipher off the key's width.
`ECDiffieHellman.DeriveRawSecretAgreement` agrees the P-256 secret, `System.Security.Cryptography.HKDF`
derives, and `RSAEncryptionPadding.OaepSHA256` names one hash for both the digest and MGF1.
`System.Text.Json` reads the batch.

## Who answers what

`bridge.json` names the members of this binding and the member that answers each operation, and a run
with `--record` writes the same pairs as `operation=` rows. The member is the code that computes the answer
bytes or the accept/refuse verdict the corpus compares. The rows attribute; they claim no independence
from a library, and each `lane` row names the library call its lane code still rests on.
`bcl` is `System.Security.Cryptography` in the .NET base class library, and `lane` is code written in this
lane.

- `decode-base64url`: `lane`. The alphabet scan, the length rule and the re-encode comparison in
  `DecodeStrictBase64Url` decide every refusal; `Base64Url` only decodes and re-encodes
  (`v1/bridge/Bridge.cs:509-548`).
- `hkdf-sha256`: `bcl`.
- `open-aes-gcm`: `bcl`.
- `seal-aes-gcm`: `bcl`.
- `ecdh-p256`: `bcl`.
- `p256-point`: `lane`. No cryptographic call takes part: `Base64Url.DecodeFromChars` decodes the JWK's `x`
  and `y`, and `PointFromJwk` pads them and writes `0x04 || X || Y` byte by byte, with no on-curve check
  (`v1/Primitives.cs:62-73`).
- `open-rsa-oaep`: `bcl`.

## Boundary

This directory owns the .NET base-class-library binding, its bridge
implementation, the operation list in its `bridge.json` and its build. The
runtime directory above owns the pinned toolchain ([`../README.md`](../README.md)).
The [shared contract](../../_shared/contract/v1/bridge.md) owns
request and observation shapes; the [conformance README](../../README.md) owns
selection, expected values, comparison and result folding. Corpus cases, case
selection, policy and endpoint behavior stay outside this lane. This lane reads
no vectors.

## Running it

    ./check                     # the case corpus through the .NET bridge
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs dotnet/bcl
    node conformance-primitives/_shared/driver/run.mjs dotnet/bcl --case rsa-oaep/01

`../../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## The bridge

`bridge.json` names `dotnet/bcl/v1/bridge/prepare` as the prepare step and `dotnet/bcl/v1/bridge/start` as
the command.

This lane's two forms are two scripts rather than one wrapper taking a flag. `prepare` installs the SDK when
it is absent, publishes the bridge into the lane's cache, and pushes one empty batch through the published
program, so the build and the first JIT sit outside the request budget; a program that cannot start says so
there, where the failure is a build problem rather than a bridge that did not answer. `start` asks the
installer for `--print-bin`, a query that downloads nothing, and runs `dotnet exec` over the published
assembly. It publishes nothing, since a build inside the request would run inside the time the runner measures.

Both scripts source `paths.sh`, so both resolve the same directory: `<cache>/build/bridge-v1/<key>`, where the
key is a digest of the absolute path of `v1/bridge/`. Two worktrees publish to two directories and neither
executes the other's assembly; two runs from one tree share a directory, and `prepare` takes an exclusive
lock over it.

One JSON document arrives on stdin and one leaves on stdout. Neither script may write to stdout, so the two
path queries are captured and every diagnostic goes to stderr, where the runner reprints it beside a
failure.

## The project layout

`v1/bridge/bridge.csproj` is the whole build definition, and it sits in its own directory so the SDK's
default `.cs` glob covers this program alone. It compiles `Bridge.cs` beside it, plus `../Primitives.cs` and
`../Json.cs` named explicitly, since neither file's own directory glob reaches into this one.

`v1/Primitives.cs` holds the library calls the seven operations answer with. Two of them need a line of code
here that other runtimes get for free. `AesGcm` writes the ciphertext and the tag into two separate spans, so
only this lane can express a tag-first mistake, and joining as ciphertext then tag reproduces the bytes
WebCrypto, Go, PHP and the JCA produce. `ECDiffieHellman` needs the second line: `DeriveKeyMaterial` hashes
the agreed point and answers 32 plausible octets nobody else computes, and `DeriveRawSecretAgreement`,
available on net8.0 and later, answers the raw x-coordinate the other four runtimes agree on.

`v1/Json.cs` builds an ordered object model straight on `Utf8JsonReader`, and the JWK import in
`Primitives.cs` takes that model. `Utf8JsonReader` reports every property name in order and takes no position
on duplicates, where the document layer above it reads a repeated member name three different ways:
`JsonDocument.Parse` hands back the last value but enumerates the repeated name twice, `JsonNode.Parse`
throws, and `JsonSerializer.Deserialize` into a dictionary keeps no order. Measured on .NET 10.0.11,
2026-08-27.
