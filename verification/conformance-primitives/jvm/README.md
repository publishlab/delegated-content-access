# Conformance (JVM)

The JVM lane. The crypto calls go through the JCA, so this lane reports what a Temurin JDK's own providers do
with the octets it is handed. `v1/Bridge.java` answers the contract's seven library-call operations.
`java.util.Base64`'s URL decoder rejects `+`, `/` and whitespace and checks nothing else, so
the bridge adds the alphabet test and the decode-and-re-encode comparison around it.
AES-128/256-GCM is `Cipher("AES/GCM/NoPadding")` under `GCMParameterSpec(128, nonce)`, which produces and
consumes `ciphertext || tag` in one buffer with no splitting, and the key's width picks the cipher. ECDH-P256
is `KeyAgreement("ECDH")` over keys built through `KeyFactory("EC")` from a JWK's raw coordinates and from a
peer's 65-octet point. RSA-OAEP is `Cipher("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")` with an explicit
`OAEPParameterSpec`. HKDF is hand rolled over `Mac("HmacSHA256")`.

The JDK ships no JSON parser, so the lane pins one and `install-toolchain` puts it in the cache beside the
JDK: jackson-databind, jackson-core and jackson-annotations, each jar checked against a pinned SHA-256 before
it is used, all three under Apache-2.0. `v1/Json.java` beside the bridge is an object model over that
library. Jackson parses the batch, and the accessors there hand the bridge Java values, so no operation in
`v1/Bridge.java` touches a Jackson type.

## Boundary

This directory owns the JCA binding, its bridge implementation, its
`bridge.json` operation declaration and its pinned toolchain/build. The
[shared contract](../_shared/contract/v1/bridge.md) owns request and observation
shapes; the [conformance README](../README.md) owns selection, expected values,
comparison and result folding. Cases and case selection stay outside this lane.

`v1/Json.java` carries no parser of its own. It names the members the bridge
reads and converts what Jackson returns; reading JSON bytes belongs to the
pinned library. The answer document is still written by hand, in
`v1/Bridge.java`, because Jackson's generator spells non-ASCII and lone
surrogates differently and this lane keeps the bytes it has produced since it
landed.

## Running it

    ./check                     # the case corpus through v1/Bridge.java
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs jvm
    node conformance-primitives/_shared/driver/run.mjs jvm --case ecdh/01

`../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Toolchain

Eclipse Temurin JDK 21 (LTS), pinned to release `jdk-21.0.12.1+1`, which reports itself as 21.0.12.1.

    ./install-toolchain                    # install if absent, print BASE
    ./install-toolchain --base <dir>       # use this JDK as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the JDK under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the java binary, install nothing
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --print-classpath  # print the JSON library classpath, install nothing
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

The same installer fetches the JSON library from Maven Central into `<cache>/jars`: jackson-databind 2.22.2,
jackson-core 2.22.2 and jackson-annotations 2.22, the versions jackson-bom 2.22.2 puts together. Each jar is
checked against a SHA-256 read off the `.sha256` Maven Central serves beside it, and a jar whose digest does
not match is thrown away rather than installed. Bumping the pin means changing a version and its digest
together in `install-toolchain`. The jars add 2.3 MB to the cache and the file names carry their versions, so
a bump writes new files. `--print-classpath` answers with the three paths joined by `:` whether or not they
have been fetched.

`bridge.json` names `jvm/bridge` as both the command and the prepare step.

## The bridge

`jvm/bridge` is a wrapper in two forms. `--prepare` installs the JDK and the jars when they are absent,
compiles `v1/Bridge.java` and `v1/Json.java` against the jars under `-Xlint:all`, and pushes one empty batch
through the result, so javac and the first JVM start sit outside the request budget. The bare form asks the
installer for `--print-base` and `--print-classpath`, queries that download nothing, and execs `java -cp
<build>:<jars> Bridge`. A run that reaches it with no JDK, or with a jar missing, says so and exits nonzero
rather than fetching while a batch waits on stdin.

Preparing and answering are two processes of one run, so the class files go to a directory both of them
compute: `<cache>/build/bridge-v1/<key>`, where the key is a digest of the absolute path of `v1/`. Two
checkouts and two worktrees therefore never share one directory. Preparation recompiles from the sources it
finds, so the class files never go stale. One cache dir is shared across containers and across
concurrent runs, so a compile takes the build lock exclusively and an answering JVM holds it shared until it
exits: the lock's file descriptor is opened before `exec java` and survives the exec.

One JSON document arrives on stdin and one leaves on stdout. Nothing in the wrapper may write to stdout, so
every line it prints goes to stderr, where the runner reprints it beside a failure.

## JDK behavior this bridge accounts for

Observed on Temurin 21.0.12.1, by running the corpus inputs rather than by reading the specification. The
first two were re-checked 2026-08-30; the rest were recorded 2026-08-27.

`Base64.getUrlDecoder()` decodes `3q2-7w`, `3q2-7w==` and `3q2-7x` to the same `deadbeef`, so padding and
non-zero trailing bits both pass it. A GCM carrier shorter than the tag throws `AEADBadTagException`, at 0, 5
and 15 bytes alike; that counts as a tag that did not verify, so the result is `authentication_failed`, never a crash.

The transform string alone leaves the JDK defaulting MGF1 to SHA-1 (JDK-8058549), where WebCrypto and Go
both use SHA-256, so the `OAEPParameterSpec` is passed on decrypt as well as encrypt. An implementation that
seals and opens with the default interoperates only with itself.

JDK 21 has no `javax.crypto.KDF` and no HKDF service in any bundled provider, so `v1/Bridge.java` writes RFC
5869 out over `Mac`, expanding one block per counter for as many octets as a request asks for. An absent salt
widens to 32 zero bytes there, because `SecretKeySpec` throws outright on a zero-length key while RFC 5869
and WebCrypto both read an empty salt as HashLen zeros.

Every EC coordinate goes through `new BigInteger(1, bytes)`. Without the `1` any coordinate whose top bit is
set becomes negative. `generateSecret()` returns the full 32-byte field width with its leading zero bytes in
place, so the bridge answers what it returns; the width check around it adds leading zeros for a provider
that trims them. An off-curve peer point imports cleanly here and `doPhase` declines it, so a clean import
leaves the peer key unvalidated.
