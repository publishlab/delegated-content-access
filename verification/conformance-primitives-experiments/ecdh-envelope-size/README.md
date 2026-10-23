# ECDH envelope size

Three publisher-to-issuer ECDH envelope shapes, sealed and opened in six runtimes from one frozen fixture.
The question is whether independent runtimes produce and open the same bytes once the nonce is derived
instead of carried, and once the ephemeral point travels compressed. If the runtimes agree here, the shapes are
implementable on stock crypto libraries. The experiment selects none of them:
[spec--sealed-key-envelopes.md](../../../docs/spec--sealed-key-envelopes.md) defines the current 97-octet
ordinary envelope with an implicit zero nonce and no HKDF. The frozen 109-octet control and both HKDF
transcripts below remain experimental; matching the current envelope's width does not select its construction.

## Profiles

| Profile | Decoded | base64url | Envelope fields |
| --- | ---: | ---: | --- |
| `control-109` | 109 | 146 | 65-byte uncompressed point, 12-byte nonce, 16-byte ciphertext, 16-byte tag |
| `hkdf-97` | 97 | 130 | 65-byte uncompressed point, 16-byte ciphertext, 16-byte tag |
| `hkdf-compressed-65` | 65 | 87 | 33-byte compressed point, 16-byte ciphertext, 16-byte tag |

## Transcript

All three agree a 32-byte fixed-width P-256 ECDH x-coordinate and encrypt one 16-byte DCA key under
AES-256-GCM with the complete BIND string as additional data. The BIND string is one canonical content
coordinate, `dca-bind-v1|c|<renderId>|bodytext`.

`control-109` records the former BIND spelling and carried-nonce
ECDH/AES-GCM carrier: the agreed x-coordinate is the AES-256-GCM key and the
fixture supplies the nonce. Current envelopes use `dca-bind-key-envelope`;
these experimental bytes remain frozen.

The two HKDF profiles replace both with derived material:

```text
key   = HKDF-SHA256(shared, empty salt, "dca-envelope-size-experiment-v1|key|"   || BIND, 32 bytes)
nonce = HKDF-SHA256(shared, empty salt, "dca-envelope-size-experiment-v1|nonce|" || BIND, 12 bytes)
```

Separate labels keep the nonce and the AES key from being two readings of one output. Deriving the nonce
removes 12 bytes from the wire and makes the nonce a function of the ephemeral key and the
coordinate rather than an independent random value. `hkdf-compressed-65` serializes the ephemeral public
value as the SEC 1 compressed point, prefix `0x02` or `0x03` followed by the 32-byte x-coordinate.

Sealing compresses by copying the x-coordinate out of the uncompressed export. Opening goes the other way
through the runtime's own import: a raw-point entry where the library has one, and otherwise a
`SubjectPublicKeyInfo` around the point handed to the library's public-key reader. Where the library refuses
the compressed form (go, jvm, dotnet), the lane's decoder recovers y from x per SEC 1 section 2.3.4 and hands
`04 || x || y` to that same import, so the library still checks the point is on the curve. A runtime whose
library also refuses the uncompressed point records the profile as unsupported rather than passing.

## Inputs, probes and expectations

`_shared/fixture.json` holds every input and the recorded answer. Its `inputs` section carries one fixed
issuer P-256 keypair, one fixed ephemeral keypair, a second ephemeral keypair for the reuse probe, the
16-byte DCA key, the BIND string and a second one at another `contentName`, the control nonce and two
off-curve points. Private keys are PKCS#8, public points are raw. Because the ephemeral keypair is fixed, a seal
repeats, so each runtime is asked for the same bytes.

`inputs` stays frozen, and `node/probe.mjs --record` writes the `expected` block beside it from one run of
the Node probe: per profile the envelope in hex and base64url, the derived key and nonce, the opened DCA key,
the decoded and base64url widths, the carried point width and the three negative answers, and beside the
profiles the three derived pairs of the ephemeral-reuse probe. Recording refuses a run in which a profile
went unanswered, and it rewrites nothing under `inputs`, so re-recording on a runtime that agrees reproduces
the same bytes.

Every probe reads `inputs` only and writes observations as JSON on stdout. Each seals a profile, opens what
it sealed, then reopens it under the other BIND, with one ciphertext byte flipped, with the point replaced
by an off-curve one, and with the point replaced by a compressed x whose `x^3 - 3x + b` has no square root
mod p. They import nothing from `js/` and hold no expected value.

Only `_shared/compare.mjs` compares. It holds each runtime against the recorded block field
by field, and then holds the answering runtimes against each other on those same fields; agreement there means
they would open each other's envelopes; no probe is handed another runtime's output. The base64url widths are
recomputed from the decoded lengths rather than read as a second literal. A runtime whose library refuses
even the uncompressed point reports `unsupported` and the refusal its library gave; the comparison prints
that line and counts it against nothing. A lane with a decoder answers the compressed profile like any other,
so a wrong decoder is a disagreement, not an absence.

## Lanes and toolchains

| Lane | Probe | Crypto library |
| --- | --- | --- |
| node | `node/probe.mjs` | WebCrypto over the runtime's OpenSSL |
| php | `php/probe.php` | ext-openssl and `hash_hkdf` |
| python | `python/probe.py` behind `python/probe` | `cryptography` |
| go | `go/probe.go` behind `go/probe` | `crypto/ecdh`, `crypto/hkdf`, `crypto/cipher` |
| jvm | `jvm/Probe.java` behind `jvm/probe` | JCE, with HKDF built from `Mac` HmacSHA256 |
| dotnet | `dotnet/Probe.cs` behind `dotnet/probe` | `System.Security.Cryptography` |

The JDK ships no JSON parser, so `jvm/Json.java` reads the fixture and writes the observation object. The
other five lanes use their own standard library's parser.

Node and PHP run off `PATH`. The other four launchers call the public lane's own installer by relative path,
`../../../conformance-primitives/<lane>/install-toolchain`, with no flags on the first call so a cold
cache installs. Each installer reads its own location rather than the working directory, so it answers from
here without being copied or sourced, and the pin, the checksum, the download and the cache directory stay in
that one script. The cache is the same `$DCA_CACHE`, `$XDG_CACHE_HOME/dca` or `~/.cache/dca/<lane>` the public
lanes fill, so a machine that has run a public lane has already paid for the download. Build output goes to
`<lane cache>/build/ecdh-envelope-size/<key>`, keyed by the absolute path of these sources, so the checkout
carries none and two checkouts never read back each other's binary. The first run of a lane needs network;
after that a run needs none.

## Running it

From this directory:

```sh
sh check                       # every probe, then the comparison
DCA_PHP=php8.4 sh check        # name the PHP binary; php8.3 and then php are tried otherwise
node node/probe.mjs --record   # rewrite the expected block from this Node run
```

Exit 0 every runtime agreed, 1 a runtime answered wrongly, 2 a runtime did not answer. The observation JSON
is written to a run directory outside the repository and the check prints its path. No repository gate runs
this check: an experiment runs from its own focused command.

## Results

2026-09-17, run finished 00:09 UTC. `check` exited 0. The first run, 2026-09-16 23:30 UTC,
had go, jvm and dotnet at `unsupported` on `hkdf-compressed-65`; their decoders came after it.

| Runtime | Version | Crypto library | `control-109` | `hkdf-97` | `hkdf-compressed-65` |
| --- | --- | --- | --- | --- | --- |
| node | v22.22.2 | OpenSSL 3.5.5 | matches recorded | matches recorded | matches recorded |
| php | 8.3.33 | OpenSSL 3.0.20 | matches recorded | matches recorded | matches recorded |
| python | 3.14.7 | cryptography 50.0.1 | matches recorded | matches recorded | matches recorded |
| go | go1.27.0 | Go standard library | matches recorded | matches recorded | matches recorded, decoder |
| jvm | 21.0.12.1 | SunEC 21 | matches recorded | matches recorded | matches recorded, decoder |
| dotnet | 10.0.11 | .NET on Debian 12 | matches recorded | matches recorded | matches recorded, decoder |

Every runtime sealed the recorded bytes for all three profiles, recovered the 16-byte key, and released no
key under another BIND, a flipped ciphertext byte, an off-curve point or the non-residue compressed point.
All six produced the same 65 bytes as each other and as the recording.

Compressed-point import, and what each lane does where the library refuses it:

| Runtime | Entry | What happened |
| --- | --- | --- |
| node | `importKey('raw', ...)` | imports the 33-byte point directly |
| php | `openssl_pkey_get_public` on a `SubjectPublicKeyInfo` | openssl decompresses it |
| python | `EllipticCurvePublicKey.from_encoded_point` | imports the 33-byte point directly |
| go | `crypto/ecdh`, `crypto/x509` | refuses (`invalid public key`); `decompress.go` decodes first |
| jvm | `KeyFactory("EC")`, `X509EncodedKeySpec` | refuses (`Invalid EC key`); `Decompress.java` decodes first |
| dotnet | `ImportSubjectPublicKeyInfo` | refuses (`not a valid public or private key`); `Decompress.cs` decodes first |

Three of six libraries read the uncompressed form only, through either entry. PHP has no raw-point entry, so
its probe wraps the point in a `SubjectPublicKeyInfo` and openssl decompresses it there; the JVM and .NET
readers take that same shell and refuse the compressed point inside it. So the 65-byte profile costs a
decompression step written by the implementer on half the runtimes tested here, which is a cost the two
uncompressed profiles do not carry. The three decoders in this experiment pay it: each follows the sketch
in [Decoding sketch](#decoding-sketch) line for line over the language's big-integer type, rejects at the
`y^2 == rhs` check when x has no point, and ends in the library import. Flipping one byte of a decoder's
output made `check` exit 1 on that lane's compressed profile in each of the three.

That step is short on P-256 because p is 3 mod 4. The reader takes x and the prefix byte (`02` even y, `03`
odd y), computes `y = (x^3 - 3x + b)^((p+1)/4) mod p`, replaces y with `p - y` when the parity differs, and
hands `04 || x || y` to the same import that refused the compressed form; that import still checks the
point is on the curve. Go keeps `elliptic.UnmarshalCompressed`, marked deprecated and still shipped, so its
helper is two lines into `ecdh.P256().NewPublicKey`. The JVM builds an `ECPoint` and `ECPublicKeySpec` with
`BigInteger.modPow`, and .NET fills `ECParameters.Q` with `BigInteger.ModPow`, each about fifteen lines.
The encoding is [SEC 1 v2.0](https://www.secg.org/sec1-v2.pdf) section 2.3.3 and the decoding section
2.3.4 (Certicom, 2009);
[FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) appendix D.1.4 (NIST, 2023) spells
out the same decompression.

An envelope-open vector alone does not catch every wrong decompressor. The prefix chooses one of the two
points `P` and `-P` with the same x-coordinate. ECDH outputs the x-coordinate of the shared point, and
`d(-P) = -(dP)`, whose x-coordinate is unchanged. A helper that ignores or reverses the prefix parity can
therefore derive the same AES key and still pass the GCM tag under this experiment's transcript. The adapter
proof must compare the exact recovered `04 || x || y` bytes before key agreement, including both prefix
parities, and must refuse a malformed prefix, an out-of-range x-coordinate, a value with no square root and
any point the library rejects.

These experimental HKDF transcripts do not include the transmitted point encoding in the derivation context.
Including the 33 carried octets in the domain-separated HKDF context would make a prefix change produce a
different key; leaving them out permits the two encodings above to open the same envelope. That is an
encoding-malleability decision, not evidence that the content key can be recovered without an issuer key.

The ephemeral-reuse probe reports the derived pair for the same ephemeral under the same BIND twice, the same
ephemeral under another BIND, and a fresh ephemeral under the original BIND. Every runtime returned an
identical key and nonce for the repeat, and a different key and nonce for the other two. Under these
profiles the nonce is fixed by the ephemeral key and the coordinate, so
reusing an ephemeral keypair at one coordinate reuses the AES-GCM key and nonce pair. The control's
independently sampled nonce does not have that property. The probe records the relationship and does not
make ephemeral reuse a supported mode.

## Decoding sketch

This non-normative SEC 1 P-256 decoding sketch describes the adapter used by
this experiment. The [compact-ECDH profile](../../../docs/spec-profile--compact-ecdh.md#43-compressed-carrier)
defines its own opening requirements; the frozen transcripts above do not
implement that profile.

SEC 1 defines point decoding. This sketch does not replace the standard or
the current profile's additional opening requirements.

```text
decodeCompressedP256(encoded):
    require length(encoded) == 33
    require encoded[0] is 0x02 or 0x03

    x = OS2IP(encoded[1..32])
    require x < p

    rhs = (x^3 - 3*x + b) mod p
    y = rhs^((p + 1) / 4) mod p
    require y^2 mod p == rhs

    if parity(y) != (encoded[0] & 1):
        y = p - y

    require y < p
    require parity(y) == (encoded[0] & 1)

    point = 0x04 || I2OSP(x, 32) || I2OSP(y, 32)
    return libraryImportAndValidate(point)
```

Here `p` and `b` are the P-256 field prime and curve coefficient, `OS2IP` and
`I2OSP` use unsigned big-endian integers, and `parity(y)` is the least
significant bit of `y`. The final library import remains part of the required
validation boundary.

## Runtimes not built here

The layout has one subdirectory per runtime, and six exist. Bun, Deno and workerd remain unbuilt. A
port reads `inputs`, writes the same observation shape and changes no recorded byte; the fixture and
`_shared/compare.mjs` stay where they are.
