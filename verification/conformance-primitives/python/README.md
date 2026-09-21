# Conformance (Python)

The CPython lane. This lane's crypto binding comes from the `cryptography` package, since CPython ships none of these
primitives itself, so this is the one lane whose toolchain is two pins rather than one. `v1/bridge.py`
answers the contract's seven operations, each one stock library call: decode a strict base64url field,
derive octets with HKDF-SHA-256, open and seal an AES-GCM carrier, agree a P-256 ECDH secret, encode a P-256
public point, and open an RSA-OAEP ciphertext.

base64url comes from `v1/primitives/codec.py`, written out because `base64.urlsafe_b64decode` is the widest decoder
of the runtimes here and no standard-library setting narrows it: an alphabet test, a decode, and a re-encode
compared against the input. AES-128/256-GCM comes from `cryptography`'s `AESGCM`, which produces and consumes
`ciphertext || tag` as one buffer; ECDH-P256, HKDF-SHA256 and RSA-OAEP are that same library's `ec`, `HKDF`
and `padding.OAEP`, reached through `v1/primitives/crypto.py`. The JWK import lives in `v1/primitives/jwk.py`,
written out because the library ships no JWK reader anywhere. `json.loads` reads the batch.

## Boundary

This directory owns the CPython and `cryptography` binding, its bridge implementation, the operation list in
its `bridge.json` and its pinned toolchain. The [shared contract](../_shared/contract/v1/bridge.md) owns
request and observation shapes; the [conformance README](../README.md) owns selection, expected values,
comparison and result folding. Cases, policy and endpoint behavior do not belong in this lane.

## Running it

    ./check                     # the case corpus, through v1/bridge.py
    ./check --record <file>     # also write this run's lane record, for _shared/aggregate-results

To narrow a failure, run the driver from `verification/` and name this lane:

    node conformance-primitives/_shared/driver/run.mjs python --case ecdh/01

`../README.md` carries the selectors, the exit codes and what a narrowing run claims.

## Toolchain

CPython 3.14.7, from the `20260825` python-build-standalone release, in its `install_only_stripped` variant.
The bridge was verified against it with `cryptography` 50.0.1.

    ./install-toolchain                    # install if absent, print BASE
    ./install-toolchain --base <dir>       # use this CPython as is, download nothing
    ./install-toolchain --cache-root <dir> # put or find the install under this root
    ./install-toolchain --print-base       # print where BASE is or would be, install nothing
    ./install-toolchain --print-bin        # print the interpreter, install nothing
    ./install-toolchain --print-site       # print the package dir, install nothing; empty under --base
    ./install-toolchain --print-cache      # print the cache dir, install nothing
    ./install-toolchain --force            # re-download over an existing install

The interpreter is pinned by release tag, version and one SHA-256 per arch. python-build-standalone
publishes one `SHA256SUMS` asset per release, covering every file in it, with no per-asset `.sha256` and no
endpoint that resolves a release name to an asset, so the pin is the filename plus its line in that manifest
and a bump changes the tag, the version and both hashes together, all four read off the one file. The
download goes through the dated release asset URL with `+` percent-encoded as `%2B`; avoid the
`releases/latest/download/...` form, which walks forward to the next dated release and makes the checksums stop
matching.

The wheels are pinned in `requirements-cp314-linux.txt`, one `--hash` line per wheel, and installed through
pip rather than `curl`, because the wheel URLs on `files.pythonhosted.org` carry an opaque
content-addressed path segment and there is no URL to construct from a version number. One file covers both
architectures: pip's hash-checking mode takes several `--hash` lines per requirement and installs a file
matching any one of them, and pip picks which wheel to ask for by the host tags. This lane has run on x86_64,
and the lines the requirements file marks unexecuted stay unproven until an
aarch64 run.

`--require-hashes` pins the file and pip still picks which file to ask for, so two properties of that choice
are refused first, by name, rather than surfacing as a hash mismatch that reads like a supply-chain alarm.
One is glibc: `cryptography` publishes `manylinux_2_17`, `_2_28` and `_2_34` builds of one version and pip
picks by the host's glibc, and the pinned hash is the `_2_34` one, so an older host or musl is told to use
`--base`. The other is the CPython minor version: `cffi` ships no abi3 wheel, so its hash is welded to one
interpreter, and a tag mismatch means the installer's own version, abi tag and requirements file have moved
apart, which it reports by naming the two values that disagree. `--no-deps` on `cryptography` alone installs a
package that will not import at all: the Rust rewrite did not remove the cffi dependency.

Inside the cache dir the interpreter sits at `<cache>/cpython-3.14.7+20260825`, the wheels at
`<cache>/wheelhouse-cp314-<arch>`, the installed packages at `<cache>/site-cp314-<arch>`, and bytecode
caches at `<cache>/build/v1`. The wheelhouse and package dir carry the abi tag and the arch because a cp314
cffi build is unimportable under any other minor version, and they belong to the pinned interpreter alone: a
`--base` interpreter reads its own packages, `--print-site` answers nothing, and the installer checks that
it imports `cryptography` before it accepts the flag. Nothing goes on `PATH`. On 2026-08-27 the interpreter
download was 34 MiB and unpacked to 106 MiB, the wheelhouse was 4.8 MiB and is kept rather than deleted
because it is what makes an offline install work, and the installed packages were 17 MiB. That is the
cheapest toolchain here by a wide margin.

`bridge.json` names `python/install-toolchain` as the prepare step and `python/v1/bridge` as the command.

## The bridge

`python/v1/bridge` is a wrapper with one form, because the preparation this lane needs is the install and
the installer is already the prepare step `bridge.json` names. The wrapper resolves the interpreter through
`--print-bin` and asks the installer nothing but print queries, so by the time it runs the interpreter is
either there or the run already stopped. `python3` on `PATH` is not that interpreter, and a bridge started
through the system one would report a missing AES library rather than an observation.

It exports `PYTHONPATH` as the site dir the installer names, and unsets it when the answer is empty, since
forcing this lane's pin-keyed site dir onto a `--base` interpreter makes a cp314 extension module
fail to load. `PYTHONPYCACHEPREFIX` points at the cache, so a checkout never carries `__pycache__/`.
`PYTHONNOUSERSITE` and `-s` keep `~/.local` off `sys.path`, so a stray `cryptography` there cannot be what
answered. `v1/` itself stays off `PYTHONPATH`: `import primitives` resolves because Python puts a
directly-run script's own directory on `sys.path`, and nothing wider is added.

`exec` replaces the wrapper with the interpreter, so the batch flows between the driver and `bridge.py` with
nothing in between to buffer or reorder it. One JSON document arrives on stdin and one leaves on stdout;
every diagnostic goes to stderr, and no traceback ever reaches the operator in place of a named line.

## What `cryptography` asked of this bridge

An `HKDF` object is single use: `derive()` twice on one raises `AlreadyFinalized`, where the JVM helper and
.NET's `HKDF.DeriveKey` are stateless calls, so every derivation builds its own object. `AESGCM` accepts any
nonce from 8 to 128 bytes, so the 12-byte rule is the caller's; the tag width is not, since the library
refuses a truncated tag itself and `AESGCM` has no tag-length argument. `AESGCM` also picks AES-128 or
AES-256 off the key it is handed, which matches the rule the contract states. `EllipticCurvePrivateNumbers`
refuses a scalar with no public point and refuses one paired with someone else's, so a recorded EC key needs
`x` and `y` beside `d`. `EllipticCurvePublicKey.from_encoded_point` reads the 65-octet peer point and refuses
one off the curve at import. `exchange(ECDH())` answers the raw agreed x-coordinate with no KDF over it. An
RSA private key is rebuilt from base64url integers through `RSAPrivateNumbers`, with the CRT members
recomputed rather than read from the JWK.

Other lanes go wrong at two points this library handles correctly: `padding.OAEP`
takes the digest and the MGF1 hash as two required arguments and defaults neither, so the JDK's silent SHA-1
mask has no analogue to fall into, and `AESGCM.encrypt` returns one ciphertext-then-tag buffer.

`base64.urlsafe_b64decode` calls `b64decode` after translating to the standard alphabet, and every hole follows
from that one line: it raises on the unpadded spelling the contract carries, it accepts `+` and `/`, it
discards every character outside the alphabet before the length check, it consumes excess `=` and keeps
decoding past it, and it accepts non-zero unused trailing bits. `b64decode(..., altchars, validate=True)`
fixes the junk, the whitespace and the data after padding, and still accepts `+`, `/` and trailing bits,
because `altchars` translates before it validates. So it does not check canonicality either, and no other
lane needs the alphabet test in `v1/primitives/codec.py`.
