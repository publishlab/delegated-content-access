# Conformance (Bun runtime)

The Bun runtime, a pinned Bun release per version token, installed by `install-toolchain` into the cache. The
one binding today is [`boringssl/`](boringssl/README.md), Bun's WebCrypto over the BoringSSL that Bun links. It
runs the shared JavaScript answer source, [`../_source/js/v1/bridge.mjs`](../_source/README.md), the same file
the Node and Deno lanes run.

## Boundary

This directory owns the Bun pins, the `versions` list and `install-toolchain`. A binding owns its bridge
wrapper, its operation declaration and its check. The [shared contract](../_shared/contract/v1/bridge.md) owns
request and observation shapes; the [conformance README](../README.md) owns selection, expected values,
comparison and result folding.

## Versions

`versions` lists `1` (1.4.2) as `default`, so a run with no version input answers the corpus on Bun 1.4.2.
The pin is the `bun-linux-x64.zip` asset of the GitHub release
`https://github.com/oven-sh/bun/releases/tag/bun-v1.4.2`, and its SHA-256 is the line for that asset in the
release's `SHASUMS256.txt`, read on 2026-10-09:
`36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913`. Only the Linux x64 glibc build is pinned,
and the installer refuses any other architecture before it downloads; on such a host, install Bun by hand and
pass `--base`.

Bun ships a `.zip` only. The installer unpacks it with `unzip` when the host has it and with
`python3 -m zipfile -e` otherwise, then sets the exec bit, which neither tool keeps. The zip holds one
directory, `bun-linux-x64/`, with the `bun` binary in it, and that directory becomes the install.

    ./install-toolchain                    # install the first default version if absent, print BASE
    ./install-toolchain --version 1        # the same for the token 1
    ./install-toolchain --base <dir>       # use the bun binary in <dir> as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the install under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the bun binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

Each version sits at `<cache>/bun-v<release>` with the single `bun` binary directly under it. The download
was about 35 MB on 2026-10-09. A `bun` on `PATH` never answers as this lane's bridge.

A pin bump changes the release in `versions` and the checksum in `install-toolchain` together, and it also
rechecks the provider [`boringssl/README.md`](boringssl/README.md) names for each operation.
