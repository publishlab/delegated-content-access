# Conformance (.NET runtime)

The .NET runtime, a pinned SDK whose base class library answers the crypto and JSON calls. The one binding
today is [`bcl/`](bcl/README.md), whose project names no `PackageReference`.

## Boundary

This directory owns the .NET SDK pin and `install-toolchain`. A binding owns its project, its bridge, its
operation declaration and its check. The [shared contract](../_shared/contract/v1/bridge.md) owns request and
observation shapes; the [conformance README](../README.md) owns selection, expected values, comparison and
result folding.

## Toolchain

.NET SDK 10.0.400, which reports `10.0.400` and a `.NET 10.0.11` runtime. Read on 2026-08-27, the release
metadata gave the 10.0 channel `"support-phase": "active"`, `"release-type": "lts"` and
`"eol-date": "2028-11-14"`.

`versions` lists one token, `10` (SDK 10.0.400), `default`; the token is the .NET major version.

    ./install-toolchain                    # install the default version if absent, print BASE
    ./install-toolchain --version <token>  # the same for a token `versions` lists; others are refused
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
