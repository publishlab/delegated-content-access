# Conformance (.NET)

The .NET lane. The crypto binding comes from the base class library, and the project names no `PackageReference`
at all, so this lane reports what a stock SDK does with the recorded octets. `v1/bridge/Bridge.cs` answers
the contract's seven operations, and each one is a single library call: decode a strict base64url field,
derive octets with HKDF-SHA-256, open and seal an AES-GCM carrier, agree a P-256 ECDH secret, encode a
P-256 public point, and open an RSA-OAEP ciphertext.

`System.Buffers.Text`'s `Base64Url` decodes, and it accepts a padded spelling and refuses non-zero trailing
bits, so it applies part of the strict field rule; the bridge checks the alphabet, the length and the
re-encode comparison itself, so the answer stays the same if a runtime update changes how much of the rule `Base64Url` applies.
`AesGcm` runs AES-128-GCM and AES-256-GCM, picking the cipher off the key's width.
`ECDiffieHellman.DeriveRawSecretAgreement` agrees the P-256 secret, `System.Security.Cryptography.HKDF`
derives, and `RSAEncryptionPadding.OaepSHA256` names one hash for both the digest and MGF1.
`System.Text.Json` reads the batch.

## Boundary

This directory owns the .NET base-class-library binding, its bridge
implementation, the operation list in its `bridge.json` and its pinned
toolchain and build. The [shared contract](../_shared/contract/v1/bridge.md) owns
request and observation shapes; the [conformance README](../README.md) owns
selection, expected values, comparison and result folding. Corpus cases, case
selection, policy and endpoint behavior stay outside this lane. This lane reads
no vectors.

## Running it

    ./check                     # the case corpus through the .NET bridge
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs dotnet
    node conformance-primitives/_shared/driver/run.mjs dotnet --case crypto/01

`../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Toolchain

.NET SDK 10.0.400, which reports `10.0.400` and a `.NET 10.0.11` runtime. Read on 2026-08-27, the release
metadata gave the 10.0 channel `"support-phase": "active"`, `"release-type": "lts"` and
`"eol-date": "2028-11-14"`.

    ./install-toolchain                    # install if absent, print BASE
    ./install-toolchain --base <dir>       # use this SDK as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the SDK under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the dotnet binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

The checksums here are SHA-512, where Adoptium and go.dev publish SHA-256, so this installer runs
`sha512sum` and those two run `sha256sum`. Both values come from Microsoft's release metadata, one entry per
file, read on 2026-08-27 over `dotnet-sdk-linux-x64.tar.gz` and `dotnet-sdk-linux-arm64.tar.gz`; the channel
index says which channel is current LTS. Bumping the pin means changing the version and both hashes
together.

Inside the cache dir the SDK sits at `<cache>/sdk-10.0.400`. `DOTNET_ROOT` is never exported and nothing
goes on `PATH`: the CLI pins the runtime root of the apphost it spawns to its own location, so invoking
`<BASE>/dotnet` by absolute path selects which SDK answers. `DOTNET_CLI_HOME` and `NUGET_PACKAGES` are
pointed into the cache as well, since without them the CLI writes into `$HOME` on first use. The download
was 229 MiB and the extracted SDK 614 MiB on 2026-08-27, the heaviest toolchain here. Network is needed once,
for that download; a restore never reaches it, because the project declares no package reference.

`bridge.json` names `dotnet/v1/bridge/prepare` as the prepare step and `dotnet/v1/bridge/start` as the
command.

## The bridge

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
