# Conformance (JVM runtime)

The JVM runtime, a pinned Eclipse Temurin JDK whose JCA providers answer the crypto calls. This directory
installs only the runtime. The JDK ships no JSON parser, so a binding pins and installs its own; the one
binding today is [`jca-jackson/`](jca-jackson/README.md), which fetches the pinned Jackson jars.

## Boundary

This directory owns the JDK pin and `install-toolchain`. A binding owns its library pins, its bridge, its
operation declaration and its check. The [shared contract](../_shared/contract/v1/bridge.md) owns request and
observation shapes; the [conformance README](../README.md) owns selection, expected values, comparison and
result folding.

## Toolchain

Eclipse Temurin JDK 21 (LTS), pinned to release `jdk-21.0.12.1+1`, which reports itself as 21.0.12.1.

`versions` lists one token, `21` (`jdk-21.0.12.1+1`), `default`; the token is the Java feature release.

    ./install-toolchain                    # install the default version if absent, print BASE
    ./install-toolchain --version <token>  # the same for a token `versions` lists; others are refused
    ./install-toolchain --base <dir>       # use this JDK as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the JDK under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the java binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

Both per-arch SHA-256 values are hardcoded from Adoptium rather than computed locally, read off the assets
endpoint in `package.checksum`, one call per arch; Adoptium publishes the same digest again in a
`.sha256.txt` beside the release asset and the two agree. The download goes through the version-pinned
binary endpoint, with `+` percent-encoded as `%2B`. The `latest/21/ga/...` form resolves to the same asset
today and moves to the next release the day Adoptium ships it, at which point the pinned checksums stop
matching, so the installer uses the pinned form. Both forms redirect to a short-lived signed
asset URL, so `curl -fSL` is required. Bumping the pin means changing the release name and both checksums
together.

Inside the cache dir the JDK sits at `<cache>/jdk-21.0.12.1+1`. `--base` must name a JDK and not a JRE,
since a JRE holds no `bin/javac`, and the installer refuses one on that. `JAVA_HOME` is never exported and
nothing goes on `PATH`; `javac` and `java` are invoked by absolute path and find their own installation from
there. The download was 198 MiB and the extracted JDK 346 MiB on 2026-08-27, roughly 2.5x the Go toolchain
beside it. Network is needed once, for that download, and everything after runs with no egress.
