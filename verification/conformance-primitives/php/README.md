# Conformance (PHP runtime)

The PHP runtime, a pinned static `php-cli` build that carries its own OpenSSL in the `openssl` extension.
The one binding today is [`openssl/`](openssl/README.md).

## Boundary

This directory owns the PHP pin and `install-toolchain`. A binding owns its bridge, its operation declaration
and its check. The [shared contract](../_shared/contract/v1/bridge.md) owns request and observation shapes;
the [conformance README](../README.md) owns selection, expected values, comparison and result folding.

## Toolchain

A static `php-cli` built by crazywhalecc/static-php-cli and served from `dl.static-php.dev`, taken from the
`bulk` distribution, which is the one carrying the `openssl` extension. `versions` lists two tokens: `8.4`
(8.4.23), `default`, and `8.3` (8.3.32), `listed`, which runs when a run names it or asks for `all`. 8.3.32
is the newest 8.3 build that distribution carried on 2026-09-30; php.net had released 8.3.35 by then, and
its published SHA-256 covers the source tarball, not this build.
It links nothing on the host and has no glibc floor to miss. Linux x86_64 and aarch64 are pinned; the
x86_64 line is the one this lane has executed, and the aarch64 line stays unproven until an aarch64 run.

    ./install-toolchain                    # install the default version if absent, print BASE
    ./install-toolchain --version <token>  # the same for a token `versions` lists; others are refused
    ./install-toolchain --base <dir>       # use this install as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the install under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the php binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

The tarball holds one file, so each version's install is that one binary, at
`<cache>/php-<release>-cli-linux-<arch>/php`, and 8.4 and 8.3 sit side by side.
This lane compiles nothing, writes no artefact and keeps no bytecode cache. Nothing goes on `PATH`;
`--print-bin` prints the binary's path, and the binary is run from that path. The download was roughly 30 MB and the
unpacked binary 30 MiB on 2026-08-27.

The SHA-256 values in the installer, two per token, were computed by this
project over the files as downloaded; the 8.3.32 pair on 2026-09-30, from two
downloads that matched. Their publisher supplies no digest for these files. A
mismatch therefore identifies a changed file without saying why it changed,
and the installer refuses it explicitly.

The installer also refuses, each by name and with what to do about it: an OS that is not Linux, an
architecture nothing is published for, an absent `curl` or a fetch that did not complete, a checksum
mismatch, an unpacked binary that will not run here or that has no `openssl`, and a `--base` holding no
`php` or one without `openssl`. `--base` is for a machine that already has a PHP and for
every host the pin does not cover, and the binary it names is asked for `openssl` before the path is handed
back.
