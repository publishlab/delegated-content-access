# Proposal: compact ECDH P-256 envelope

Status: Proposal
Target: [spec--sealed-key-envelopes.md Section 4](spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope);
[spec--profiles.md](spec--profiles.md) for the optional profile

This document has no protocol authority. If the editors accept it, they move
its text into the targets; if they decline it, they remove this file.

## Introduction

The current `ecdh-p256` envelope is 109 octets: a 65-octet uncompressed ephemeral
P-256 public key, a fresh 12-octet AES-GCM nonce, and a 32-octet encrypted
payload plus tag. The publisher uses the 32-octet shared x-coordinate directly
as the AES-256-GCM key; the current spec explicitly forbids a KDF. This proposal replaces it with a
distinct 97-octet required construction that derives key and nonce with HKDF
and omits the transmitted nonce. It also proposes an optional 65-octet profile
that compresses the ephemeral point. The current spec includes neither form.
A dated six-runtime experiment proves that both widths interoperate under its
recorded transcript; the proposal still needs selection and its final
byte-exact specification transcript.

## Motivation

JSON wire size: the 97-octet decoded envelope drops 16 base64url characters
per envelope. The 65-octet decoded envelope drops another 43 by compressing the
public key; it is a separate optional profile because compressed-key import is
not native in every supported runtime. Node, PHP and Python import it through
their crypto libraries. Go, the JVM and .NET need a SEC 1 decompression adapter
before the same libraries import and validate the uncompressed public key.

The component columns are decoded octets. The JSON columns count ASCII
characters in the unpadded base64url string carried on the wire.

| Form                           | One-time public key | Nonce | Payload | Tag | JSON chars | JSON chars saved |
|--------------------------------|--------------------:|------:|--------:|----:|-----------:|-----------------:|
| Current `ecdh-p256`            |                  65 |    12 |      16 |  16 |        146 |                - |
| Proposed derived nonce         |                  65 |     0 |      16 |  16 |        130 |        16 (-11%) |
| Proposed compressed public key |                  33 |     0 |      16 |  16 |         87 |        59 (-40%) |

The one-time public key is the public half of a fresh key pair the publisher
creates for one envelope. The issuer combines it with its own private key to
calculate the secret needed to open that envelope. The publisher's one-time
private key and the calculated secret never appear in the JSON.

The base64url count is the number of ASCII characters inside the JSON string
value. It excludes the surrounding quotes, member name, and JSON punctuation.
Canonical base64url needs no JSON escaping, so each listed character contributes
one UTF-8 byte to the encoded envelope value. Reductions are relative to the
current envelope and percentages are rounded to whole numbers.

The first proposed form derives instead of transmitting the 12-octet nonce.
The compressed form also shortens the publisher's one-time public key from its
uncompressed encoding to its SEC 1 compressed encoding. That compression
removes another 43 characters from every JSON envelope value.

The [worked data-format example](design--data-format--example.md#fixed-binary-widths-in-the-example)
is the baseline: it shows the current envelope width in its surrounding JSON.
The proposed forms change only the envelope bytes represented by that string;
they add no JSON member.

Construction: the authors deliberately chose the raw shared x-coordinate.
Its lack of a KDF is not by itself a defect. Before replacing it, the new form
must fix and test the complete HKDF transcript, key separation, nonce behavior
and cross-runtime interoperability. Deriving the nonce does not make reuse of
an ephemeral key or shared secret safe; the final transcript must address that
case.

## Specification

## 1. Change
Lands in: [spec--sealed-key-envelopes.md Section 4](spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope); [spec--profiles.md](spec--profiles.md) for the optional profile

This document names each envelope by its decoded length: 109 (current
`ecdh-p256`), 97 and 65. As unpadded base64url in the JSON carrier these are
146, 130 and 87 characters.

The current spec requires implementations to support `ecdh-p256` and makes
`rsa-oaep` optional. The issuer's registered opening key selects the envelope;
the envelope carries neither an algorithm name nor its width. A KDF-based form
therefore needs its own algorithm or profile identifier. Before adoption, the
spec must also say how it coexists with current 109-octet envelopes, which form
is required or optional, and which decoded length each identifier accepts.

Both proposed forms derive the AES-GCM key and nonce from the ECDH shared
secret and omit the transmitted nonce. The 65-octet form also compresses the
ephemeral point. An issuer MUST NOT choose a form by inspecting its length.

This proposal makes the 97-octet form the required replacement and the
65-octet compressed-point form an optional profile. Neither is part of the
current spec.

## 2. Envelopes
Lands in: [spec--sealed-key-envelopes.md Section 4](spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope)

Proposed required form, uncompressed point, 97 octets:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 65 octets | Ephemeral P-256 public key, uncompressed |
| 65 | 32 octets | Encrypted payload (16) and GCM tag (16) |

Proposed optional form, compressed point, 65 octets:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 33 octets | Ephemeral P-256 public key, SEC 1 compressed |
| 33 | 32 octets | Encrypted payload (16) and GCM tag (16) |

The payload width is the 16 octets Section 2 fixes for every kind.

## 3. Derivation
Lands in: [spec--sealed-key-envelopes.md Section 4](spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope)

The publisher still generates a fresh ephemeral P-256 key pair for every
envelope and encodes the shared x-coordinate as 32 big-endian octets, retaining
leading zero octets. It then derives the key and nonce as follows:

```text
key   = HKDF-SHA256(shared, salt, key-info,   L = 32)
nonce = HKDF-SHA256(shared, salt, nonce-info, L = 12)
```

Still open: the exact salt, the domain-separated `key-info` and `nonce-info`
octets, whether either includes BIND and the exact transmitted ephemeral-point
encoding, and what happens if a shared secret is repeated. The spec must fix
these choices together as one transcript. BIND remains the GCM
`additionalData`; HKDF input does not silently replace it.

The point encoding needs an explicit decision because changing a compressed
point's `02` or `03` prefix selects `P` or `-P`, while ECDH outputs the
x-coordinate of the shared point. Both signs therefore produce the same shared
x-coordinate. Without the carried point octets in the authenticated
transcript, a prefix change can leave the derived key and valid GCM tag
unchanged. Including the exact carried encoding in the domain-separated HKDF
context would remove that encoding malleability.

## 4. Opening
Lands in: [spec--sealed-key-envelopes.md Section 6](spec--sealed-key-envelopes.md#6-opening-and-failure)

An issuer MUST open the 97-octet form only for the registered algorithm or
profile that names it. It MUST open the compressed form only for an issuer key
registered for that profile, and a publisher MUST NOT send that form otherwise.
The existing `ecdh-p256` identifier continues to require 109 octets unless the
spec changes it.

The issuer MUST refuse any decoded length other than the one fixed by the
registered algorithm or profile. It imports the point through its cryptographic
library and fails the open if import, point validation or key agreement fails.
It then derives the key and nonce from Section 3, rebuilds BIND and uses BIND
to authenticate the ciphertext. A different BIND or payload width MUST fail.
The compressed profile accepts exactly a SEC 1 33-octet P-256 encoding with
prefix `02` or `03`. An implementation may import it directly or recover the
matching uncompressed `04 || x || y` point before import. The recovery must
apply the prefix parity, refuse an out-of-range x-coordinate or a curve equation
with no square root, and still use the cryptographic library's public-key and
point validation before key agreement.

The following is a non-normative decoding sketch. SEC 1 and the rejection
requirements above define behavior; this sketch does not replace either one.

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

## 5. Evidence
Lands in: [spec--sealed-key-envelopes.md Section 8](spec--sealed-key-envelopes.md#8-versioning-and-conformance)

Experiment: [ecdh-envelope-size](../verification/conformance-primitives-experiments/ecdh-envelope-size/README.md)

A dated experiment recorded fixed expected bytes and exercised Node, PHP,
Python, Go, the JVM and .NET. On 2026-09-17 all six lanes produced and
opened the same 109-, 97-, and 65-octet envelopes. Node, PHP and Python imported
the compressed point through their crypto libraries. Go, the JVM and .NET
first recovered the uncompressed SEC 1 point, then handed it to the same
library import and validation boundary used by the uncompressed profiles.

Every lane refused another BIND, a flipped ciphertext octet, an off-curve
point, and a compressed x-coordinate whose curve equation has no square root.
Changing one octet of each of the three decompressor outputs made that lane
fail rather than silently agree. This proves that both proposed widths are
implementable under the recorded transcript on the six named runtime versions.
It does not select a profile or settle the final HKDF transcript.

Before adoption, each runtime must seal and open the same fixed bytes. Tests
must cover the final transcript, changed BIND, wrong length, malformed or wrong
point encoding, authentication failure, payload width and publisher-to-issuer
interoperability. The compressed profile must additionally test the exact
recovered uncompressed point for both prefix parities, invalid prefixes,
out-of-range x-coordinates, values with no square root, point validation and a
changed transmitted prefix. Migration tests must retain the current 109-octet
form.

## 6. Results

| Profile | Node | PHP | Python | Go | JVM | .NET |
| --- | --- | --- | --- | --- | --- | --- |
| Current 109 octets | Match | Match | Match | Match | Match | Match |
| Proposed 97 octets | Match | Match | Match | Match | Match | Match |
| Optional compressed 65 octets | Match | Match | Match | Match, adapter | Match, adapter | Match, adapter |

The dated size and cross-runtime proof is complete for the recorded transcript.
Selection remains open until the HKDF transcript and exact point-encoding
authentication decision land. Promotion evidence must then run that selected
transcript, compare exact recovered points for both prefix parities, retain the
negative cases above, and cover the selected migration behavior.
