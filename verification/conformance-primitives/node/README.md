# Conformance (Node runtime)

The Node runtime, a pinned Node.js release per version token, installed by `install-toolchain` into the
cache. The one binding today is [`openssl/`](openssl/README.md), WebCrypto over the OpenSSL that Node links.
Its answer source, `../_source/js/v1/bridge.mjs`, sits outside this directory so that every JavaScript lane
can run the same file.

## Boundary

This directory owns the Node pins, the `versions` list and `install-toolchain`. A binding owns its bridge
wrapper, its operation declaration and its check; the JavaScript answer source lives in
[`../_source/js/v1/`](../_source/README.md). The [shared contract](../_shared/contract/v1/bridge.md) owns
request and observation shapes; the [conformance README](../README.md) owns selection, expected values,
comparison and result folding.

## Versions

`versions` lists `24` (24.21.0) and `22` (22.23.3), both `default`, so a run with no version input answers
the corpus on both. Each pin is the `node-v<release>-linux-<arch>.tar.gz` archive from
`https://nodejs.org/dist/v<release>/`, and its SHA-256 is the line for that archive in the release's
`SHASUMS256.txt`, read on 2026-09-30. Linux x64 and arm64 are pinned; x64 is the one this lane has run.
The `.tar.gz` build is pinned rather than `.tar.xz`, because `xz` is not present on every host.

    ./install-toolchain                    # install the first default version if absent, print BASE
    ./install-toolchain --version 22       # the same for Node 22
    ./install-toolchain --base <dir>       # use this Node as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the install under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the node binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

Each version sits at `<cache>/node-v<release>` with `bin/node` under it. The download was about 55 MB per
version on 2026-09-30. The `node` on `PATH` runs the driver, whichever runtime `DCA_JS` names, and never
answers as this lane's bridge.
