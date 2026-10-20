# Conformance (workerd runtime)

The workerd runtime, Cloudflare's open-source Workers runtime, a pinned release per version token, installed by
`install-toolchain` into the cache. The one binding today is [`boringssl/`](boringssl/README.md), workerd's
WebCrypto over the BoringSSL that workerd links. It runs the shared answer module
[`../_source/js/v1/answer.mjs`](../_source/README.md), the same answering code the Node, Deno and Bun lanes run,
from a Worker entry of its own, because a workerd isolate has no stdin and no exit code.

## Boundary

This directory owns the workerd pins, the `versions` list and `install-toolchain`. A binding owns its bridge
launcher, its Worker entry and configuration, its operation declaration and its check. The
[shared contract](../_shared/contract/v1/bridge.md) owns request and observation shapes; the
[conformance README](../README.md) owns selection, expected values, comparison and result folding.

## Versions

`versions` lists `1` (1.20261008.1) as `default`, so a run with no version input answers the corpus on workerd
1.20261008.1, the newest release on 2026-10-09. The pin is the `workerd-linux-64.gz` asset of the GitHub
release `https://github.com/cloudflare/workerd/releases/tag/v1.20261008.1`, and its SHA-256 is the `digest`
the GitHub release API reports for that asset, read on 2026-10-09:
`a7c6dab0b3c2336eff0296edb83e2aa45d412d6e86f2e3b9ff89b380d829a2ae`. That digest is GitHub's own asset metadata,
computed by GitHub over the uploaded file. Cloudflare publishes no checksum file beside the asset, so the pin
trusts GitHub's record of the upload rather than a checksum Cloudflare signed or listed. Only the Linux x86_64
build is pinned, and the installer refuses any other architecture before it downloads; on such a host, install
workerd by hand and pass `--base`.

The asset is a gzip of the bare binary, not an archive. The installer checks the digest of the `.gz`, unpacks
it with `gzip -dc` and sets the exec bit.

    ./install-toolchain                    # install the first default version if absent, print BASE
    ./install-toolchain --version 1        # the same for the token 1
    ./install-toolchain --base <dir>       # use the workerd binary in <dir> as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the install under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the workerd binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

Each version sits at `<cache>/workerd-v<release>` with the single `workerd` binary directly under it. The
download was about 39 MB on 2026-10-09, and the binary unpacks to about 135 MB. The binary reports its release
as a date: `workerd --version` answers `workerd 2026-10-08`, and the lane record carries `2026-10-08`. A
`workerd` on `PATH` never answers as this lane's bridge.

## BoringSSL at this pin

The tag `v1.20261008.1` builds against BoringSSL tag `0.20260929.0`, commit
`427ec40cc8edc545253289232e885708c409e5ea`. The file [`build/deps/gen/deps.MODULE.bazel`][deps] at that tag
overrides the `boringssl` module with the GitHub tarball of `0.20260929.0`, archive SHA-256
`55827fd521a666a60293d06dc0410524d5eff8eb7cda23fdb6e2b1d56a5d4a20`, plus one workerd patch that exposes
`libdecrepit` for Node's `ncrypto`. The tag-to-commit step comes from the GitHub API for `google/boringssl`,
read on 2026-10-09. The binary itself reports no BoringSSL revision, so the lane check cannot print one; this
reading of the build files is the citation.

Workerd releases daily. A pin bump changes the release in `versions` and the digest in `install-toolchain`
together, rereads `deps.MODULE.bazel` at the new tag for the BoringSSL revision, and rechecks the calls
[`boringssl/README.md`](boringssl/README.md) names for each operation.

[deps]: https://github.com/cloudflare/workerd/blob/v1.20261008.1/build/deps/gen/deps.MODULE.bazel
