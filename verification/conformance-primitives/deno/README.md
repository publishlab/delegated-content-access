# Conformance (Deno runtime)

The Deno runtime, a pinned Deno release per version token, installed by `install-toolchain` into the cache. The
one binding today is [`rustcrypto-awslc/`](rustcrypto-awslc/README.md), Deno's WebCrypto, which Deno builds from
RustCrypto crates and aws-lc-rs. It runs the shared JavaScript answer source,
[`../_source/js/v1/bridge.mjs`](../_source/README.md), the same file the Node lane runs.

## Boundary

This directory owns the Deno pins, the `versions` list and `install-toolchain`. A binding owns its bridge
wrapper, its operation declaration and its check. The [shared contract](../_shared/contract/v1/bridge.md) owns
request and observation shapes; the [conformance README](../README.md) owns selection, expected values,
comparison and result folding.

## Versions

`versions` lists `2` (2.9.7) as `default`, so a run with no version input answers the corpus on Deno 2.9.7.
The pin is the `deno-x86_64-unknown-linux-gnu.zip` asset of the GitHub release
`https://github.com/denoland/deno/releases/tag/v2.9.7`, and its SHA-256 is the value in that asset's own
`deno-x86_64-unknown-linux-gnu.zip.sha256sum`, read on 2026-10-09:
`c6527f24f4b16031d3ae4fa9f658d5f11534c8d84ce7dc8502420280919c3490`. Only Linux x86_64 is pinned, and the
installer refuses any other architecture before it downloads; on such a host, install Deno by hand and pass
`--base`.

Deno ships a `.zip` only. The installer unpacks it with `unzip` when the host has it and with
`python3 -m zipfile -e` otherwise, then sets the exec bit, which neither tool keeps.

    ./install-toolchain                    # install the first default version if absent, print BASE
    ./install-toolchain --version 2        # the same for the token 2
    ./install-toolchain --base <dir>       # use the deno binary in <dir> as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the install under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the deno binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

Each version sits at `<cache>/deno-v<release>` with the single `deno` binary directly under it. The download
was about 40 MB on 2026-10-09. A binding's wrapper points `DENO_DIR` at `<cache>/deno-dir`, so Deno's own
module and code cache stays out of the user's. A `deno` on `PATH` runs the driver when `DCA_JS=deno`, and
never answers as this lane's bridge.

A pin bump changes the release in `versions` and the checksum in `install-toolchain` together, and it also
rechecks the provider each operation names in [`rustcrypto-awslc/README.md`](rustcrypto-awslc/README.md):
Deno has moved WebCrypto operations between providers across releases, and the binding's name can go stale
while the directory keeps it.
