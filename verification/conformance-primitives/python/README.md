# Conformance (Python runtime)

The CPython runtime. This directory installs only the runtime. CPython ships none of the contract's
primitives, so a binding pins and installs its own library; the one binding today is
[`cryptography/`](cryptography/README.md), which installs the pinned `cryptography` wheels.

## Boundary

This directory owns the CPython pin and `install-toolchain`. A binding owns its library pins, its bridge, its
operation declaration and its check. The
[shared contract](../_shared/contract/v1/bridge.md) owns request and observation shapes; the
[conformance README](../README.md) owns selection, expected values, comparison and result folding.

## Toolchain

CPython 3.14.7, from the `20260825` python-build-standalone release, in its `install_only_stripped` variant.

`versions` lists one token, `3.14` (3.14.7), `default`; the token is the CPython minor version.

    ./install-toolchain                    # install the default version if absent, print BASE
    ./install-toolchain --version <token>  # the same for a token `versions` lists; others are refused
    ./install-toolchain --base <dir>       # use this CPython as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the install under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the interpreter, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

The interpreter is pinned by release tag, version and one SHA-256 per arch. python-build-standalone
publishes one `SHA256SUMS` asset per release, covering every file in it, with no per-asset `.sha256` and no
endpoint that resolves a release name to an asset, so the pin is the filename plus its line in that manifest
and a bump changes the tag, the version and both hashes together, all four read off the one file. The
download goes through the dated release asset URL with `+` percent-encoded as `%2B`; avoid the
`releases/latest/download/...` form, which walks forward to the next dated release and makes the checksums stop
matching.

Inside the cache dir the interpreter sits at `<cache>/cpython-3.14.7+20260825` and bytecode caches at
`<cache>/build/v1`. Nothing goes on `PATH`. On 2026-08-27 the interpreter download was 34 MiB and unpacked
to 106 MiB. That is the cheapest toolchain here by a wide margin.
