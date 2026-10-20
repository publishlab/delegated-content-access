# Conformance (Rust runtime)

The Rust runtime. Rust's standard library carries no crypto and no JSON, so every Rust lane is a binding: a
pinned crate stack in its own directory under this one, with its own `bridge.json`, `check`, Cargo manifest
and committed `Cargo.lock`. This directory owns what the bindings share, the pinned toolchain and its
installer. The one binding today is [`rustcrypto/`](rustcrypto/README.md).

## Boundary

This directory owns the Rust toolchain pin and `install-toolchain`. A binding owns its crates, its bridge,
its operation declaration and its check. The [shared contract](../_shared/contract/v1/bridge.md) owns request
and observation shapes; the [conformance README](../README.md) owns selection, expected values, comparison
and result folding.

## Toolchain

Rust 1.98.1, the stable release in
[`channel-rust-stable.toml`](https://static.rust-lang.org/dist/channel-rust-stable.toml) dated 2026-09-03,
reporting `rustc 1.98.1 (48a229cea 2026-09-01)` and `cargo 1.98.1 (797e8a9bc 2026-08-05)`. Both per-arch
SHA-256 values are the ones static.rust-lang.org publishes beside each archive as
`rust-1.98.1-<arch>-unknown-linux-gnu.tar.gz.sha256`, and the channel file carries the same values. Bumping
the pin means changing the version and both checksums together.

`versions` lists one token, `1.98` (1.98.1), `default`.

    ./install-toolchain                    # install the default version if absent, print BASE
    ./install-toolchain --version <token>  # the same for a token `versions` lists; others are refused
    ./install-toolchain --base <dir>       # use this toolchain as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the toolchain under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the cargo binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

The installer downloads the `.tar.gz` archive rather than the `.tar.xz` one, so unpacking needs only `tar`
and `gzip`. Before it checks the downloaded bytes against the pin, it fetches the published `.sha256` file
and refuses to install when that file names another digest. It then runs the archive's own `install.sh` for
three components, `rustc`, `cargo` and `rust-std-<arch>-unknown-linux-gnu`, and leaves out the docs,
clippy, rustfmt and LLVM tools the archive also carries.

Inside the cache dir the toolchain sits at `<cache>/rust-1.98.1`. A binding's build points `CARGO_HOME` at
`<cache>/cargo-home` and vendors its crates under `<cache>/vendor/`, so cargo writes nothing into
`~/.cargo`. On 2026-09-30 the x86_64 download was 364 MiB and the installed toolchain 577 MiB; for the
current number, `du -sh "$(./install-toolchain --print-base)"`.

Nothing goes on `PATH`. `--print-bin` names cargo, and a binding runs it by that name with `RUSTC` naming
the `rustc` beside it, because cargo started by absolute path still looks for `rustc` on `PATH`. rustc finds
its standard library relative to its own binary. It links with the host's `cc`, which the toolchain does not
carry; a host with no C linker cannot build a binding.
