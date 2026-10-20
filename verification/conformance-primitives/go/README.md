# Conformance (Go runtime)

The Go runtime. Go's standard library carries the crypto and the JSON the bridge calls, so the one binding
today, [`stdlib/`](stdlib/README.md), links nothing beyond it. This directory owns what a binding builds
with, the pinned toolchain and its installer.

## Boundary

This directory owns the Go toolchain pin and `install-toolchain`. A binding owns its bridge, its module, its
operation declaration and its check. The [shared contract](../_shared/contract/v1/bridge.md) owns request and
observation shapes; the [conformance README](../README.md) owns selection, expected values, comparison and
result folding.

## Toolchain

Go 1.27.0, pinned to the exact version and kept in step with `stdlib/v1/go.mod`. Both per-arch SHA-256 values come
from the release table at https://go.dev/dl/, so bumping the pin means changing the version and both
checksums together.

`versions` lists one token, `1.27` (1.27.0), `default`.

    ./install-toolchain                    # install the default version if absent, print BASE
    ./install-toolchain --version <token>  # the same for a token `versions` lists; others are refused
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
