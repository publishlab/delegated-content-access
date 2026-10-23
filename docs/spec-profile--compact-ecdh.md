# Compact ECDH envelope profile

Status: Public Working Draft

## Abstract

This optional profile defines compact publisher-to-issuer envelopes using one
fixed RFC 9180 HPKE suite and compressed P-256 public-point transport. It saves
32 octets for a 16-octet key compared with the ordinary ECDH envelope. Its
generic 32-octet payload capacity does not define composition with content
groups; that composition remains undefined and MUST be refused. A publisher
selects it per issuer block with `"envelope": "compact-ecdh"`, using the same
issuer public key and key identifier. The baseline envelope remains available.

## 1. Introduction

`dca-profile-compact-ecdh` composes `dca-profile-baseline` with the compact-ECDH
extension defined here. Support is optional. A role claiming this profile MUST
implement its applicable duties; deployment configuration determines whether a
publisher emits compact envelopes and an issuer accepts them for a keypair.
Support does not require every issuer block to use the extension.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

### 1.1. Rationale (informative)

HPKE supplies an established key schedule, published vectors and interoperable
implementations. A port can implement this fixed suite using its platform's
ECDH, HKDF/HMAC and AES-GCM primitives without depending on an HPKE library.
An exact implementation can later be replaced by a compatible library while
preserving the cryptographic bytes.

Compressed transport shortens the public point by 32 octets. For an ordinary
16-octet key that takes the envelope from 97 to 65 octets. A generic 32-octet
payload occupies 81 octets, compared with 113 in an uncompressed envelope.
This size arithmetic does not define a content-group composition. Neither
uncompressed envelope carries a nonce, so the saving is the point alone.
Derivation and compressed transport are selected
together. This profile offers no derivation-only mode. Compression is a DCA
carrier transformation around standard HPKE; HPKE's internal serialization and
key schedule remain exactly those specified in RFC 9180.

## 2. Roles and selection

The publisher receives an issuer public key and `keyId` through the existing
trusted provisioning arrangement. The issuer retains the matching private key.
The public key MUST be P-256 for compact use. Configuration MUST establish that
the publisher, client relay and issuer support this selected path before the
publisher relies on it. DCA defines no runtime capability negotiation here.

The publisher MAY enable compact sealing independently for each issuer. The
issuer MUST permit compact use for the selected keypair through trusted
configuration. The unsigned wire selector cannot enable an unsupported or
unpermitted procedure, select an unregistered key, or grant reader access.
Core verification and authorization ordering continues to apply.

Trusted configuration lists the procedures each keypair may open under. A
keypair without a list opens under its ordinary procedure only, the one its
registration names. A list of the ordinary procedure and `compact-ecdh` permits
both. A list of `compact-ecdh` alone permits compact only, so a request that
omits the selector opens nothing for that keypair. An issuer never takes the
first or only listed procedure as a default, and refuses at configuration a list
that is malformed, repeats a procedure, names an unsupported procedure or names
one the key type cannot use.

The publisher and issuer MAY use the same keypair and `keyId` for ordinary and
compact envelopes. Format selection does not require key rotation. `keyId`
identifies the issuer keypair within its publisher registration; `envelope`
selects the procedure used with that keypair.

This extension changes publisher-to-issuer envelopes only. It does not change
item encryption, period-key content-key seals, returned capability kinds or
issuer-to-client response protection.

## 3. Wire selector and client relay

### 3.1. Publisher delivery

The optional member `envelope` on an `issuerData` record has one defined value:

| Representation | Meaning |
| --- | --- |
| Member omitted | Use the key's ordinary procedure, if configuration permits it for that key |
| `"compact-ecdh"` | Use the compact construction defined here |

The publisher MUST omit the member when selecting the ordinary procedure. An
explicit default string, `null`, an empty string or another value is not defined
by this profile. A compact-aware consumer MUST refuse a present malformed or
unsupported value rather than process it as omission. Support for another value
requires another specified procedure and trusted configuration.

The selector applies to the issuer block's `sealed.contentKeys`,
`sealed.periodKeys` and, when the chain-key profile is selected,
`sealed.chainKeys`. A block MUST NOT mix compact and ordinary envelopes in these
collections. Another issuer block in the same delivery MAY use a different procedure.
An extension-defined sealed field participates only when its owning mechanism
provides the payload width and binding required by Section 4.2. A publisher MUST
NOT emit a compact-selected block containing a sealed field whose composition
with this selector is undefined.

```json
{
  "issuerData": [
    {
      "issuerName": "exampleIssuer",
      "keyId": "issuer-key-A",
      "envelope": "compact-ecdh",
      "sealed": {
        "contentKeys": [
          { "contentName": "bodytext", "key": "<compact seal: 65 bytes>" }
        ]
      }
    },
    {
      "issuerName": "otherIssuer",
      "keyId": "issuer-key-B",
      "sealed": {
        "contentKeys": [
          { "contentName": "bodytext", "key": "<ordinary ECDH seal: 97 bytes>" }
        ]
      }
    }
  ]
}
```

Decoded widths in examples are illustrative; actual values use the canonical
binary-string encoding defined by the data format.

### 3.2. Unlock request

For a selected issuer, the client MUST copy its `envelope` member to the unlock
request's top-level `envelope` member. If absent, it MUST leave that request
member absent. It MUST associate the selector with the same captured issuer
block as `keyId` and the relayed sealed values, including narrowed requests.
The client MUST NOT infer or rewrite a selector from a blob's length.

```json
{
  "version": "1",
  "issuerName": "exampleIssuer",
  "keyId": "issuer-key-A",
  "envelope": "compact-ecdh",
  "resourceJWT": "<signed resource metadata>",
  "sealed": {
    "contentKeys": [
      { "contentName": "bodytext", "key": "<compact seal: 65 bytes>" }
    ]
  }
}
```

The issuer admits the selector within the verified publisher registration and
its trusted procedure configuration. It MUST NOT try another procedure after a
failed open. A mismatched, removed or inserted selector cannot be rescued by
length-based dispatch or fallback. No selector is added to the unlock response:
the selected response mechanism independently protects returned capabilities.

A client claiming this profile needs selector relay and admission support, but
no HPKE or point-decompression implementation. An older client that discards the
selector does not satisfy these relay duties, even if it forwards sealed strings.

## 4. Fixed construction

### 4.1. HPKE suite and context

Publishers and issuers MUST use the complete RFC 9180 construction with:

| Parameter | Selection | Identifier |
| --- | --- | --- |
| Mode | Base | `0x00` |
| KEM | DHKEM(P-256, HKDF-SHA256) | `0x0010` |
| KDF | HKDF-SHA256 | `0x0001` |
| AEAD | AES-256-GCM | `0x0002` |

`info` MUST be exactly the UTF-8 bytes of `dca-derivation-compact-ecdh`, with
no quotes, terminator, whitespace or length prefix added by DCA. RFC 9180's
own labeled framing, suite identifiers and literals apply unchanged.
PSK inputs are empty as required by Base mode; no authenticated-sender mode is
selected. The issuer public key is the recipient key.

Each envelope MUST use a fresh HPKE sender context and exactly one `Seal` at
sequence number zero. A publisher MUST generate a fresh ephemeral P-256 keypair
using its cryptographic implementation for every envelope and MUST NOT reuse it
across seals. The sealing API SHOULD generate that keypair internally. The issuer
creates a fresh receiver context and performs exactly one `Open` at sequence zero.
Neither a nonce nor a sequence number is carried in the DCA envelope.

The full DHKEM extraction and HPKE key schedule MUST be used. The raw ECDH
x-coordinate is not the HPKE shared secret and MUST NOT be substituted for it.
Implementations MUST preserve fixed-width leading zero octets and use RFC 9180's
standard uncompressed P-256 serialization inside DHKEM, including both public
keys in its KEM context. An implementation need not compute unused exporter
output, but MUST produce the same encryption key and nonce as the full suite.

### 4.2. Payload and binding

For `contentKeys`, `periodKeys` and `chainKeys`, the plaintext is exactly the
16-octet key and the HPKE AAD is exactly the corresponding BIND octets defined
by the sealed-envelope and selected key-profile specifications. No extra BIND
prefix or suffix is added. `info` is fixed; BIND enters HPKE as AAD, not `info`.

A composing mechanism that seals a different payload, such as a 32-octet window
seed, MUST define its exact expected width and binding bytes. Those bytes become
the plaintext and AAD respectively without another encoding layer. The caller
supplies the expected width from that mechanism, not from the received envelope.
This profile permits 16- and 32-octet payload contracts only. Supporting a
32-octet payload does not make a seed an ordinary delivered key or authorize
returning seeds to clients. The composing profile's custody rules still apply.

### 4.3. Compressed carrier

RFC 9180 produces `enc` as a 65-octet uncompressed P-256 point:
`04 || X || Y`, with 32-octet unsigned big-endian coordinates. The publisher
MUST compress it to `prefix || X`, where `prefix` is `02` for even Y and `03`
for odd Y. Compression takes place after HPKE context creation; HPKE itself
uses the standard uncompressed `enc`.

The binary envelope is:

```text
compressedEnc (33 octets) || ciphertext (payload width + 16-octet GCM tag)
```

For a 16-octet key it is 65 octets, encoded as 87 unpadded base64url characters.
For a 32-octet payload it is 81 octets, encoded as 108 characters. The selector's
JSON overhead is per issuer block and is additional to these string widths.

An issuer MUST check the exact expected envelope width and prefix before
opening. It MUST recover the unique uncompressed point with the indicated
parity, rejecting x outside the P-256 field, a curve equation without a square
root, invalid parity/encoding, the point at infinity and any point rejected by
its cryptographic implementation. Native compressed import MAY perform recovery;
otherwise a SEC 1 decoder MAY recover the point before library validation.

The issuer MUST supply the recovered, exact 65-octet `enc` to RFC 9180
`SetupBaseR`. It MUST NOT pass the 33-octet encoding into HPKE's KEM context or
change HPKE serialization rules to accept it. HPKE library replacement retains
this DCA transport adapter around the library.

## 5. Failure and coexistence

Wrong selector, disallowed procedure, incompatible public-key type, malformed
encoding, wrong payload width, invalid point, failed key agreement or failed
HPKE authentication MUST result in no released plaintext. Decoded plaintext
MUST match the expected payload width. Failures use the ordinary envelope-open
failure and endpoint disclosure rules; they do not trigger algorithm fallback.

An issuer MAY accept ordinary and compact envelopes with the same private key
and keyId. Old deliveries without `envelope` continue using the ordinary
procedure, which the issuer MUST keep permitting while it serves them. The publisher
can stop creating compact deliveries by disabling that
issuer's compact selection and omitting `envelope` on subsequent ordinary
blocks. This does not change already cached deliveries.

Procedure retirement and key rotation are distinct configuration actions. An
issuer that must continue serving cached compact deliveries MUST retain compact
acceptance and the necessary private key. The default interpretation of an
existing registration MUST NOT be silently changed to reinterpret cached blobs.
Invalidating a CDN cache does not establish that every saved copy disappeared.

## 6. Security considerations

The DCA security model applies. Public ciphertext and selectors confer no
entitlement. Publisher verification, authorization, publisher-scoped key lookup
and BIND reconstruction retain their existing order and duties. The issuer
public key is public; anyone can form an encryption to it, so successful opening
alone does not establish publisher authorship.

The same private key used by both procedures is the same entrustment domain.
The selector is not an isolation boundary between issuers, publishers or aliases.
Trusted configuration restricts procedure use; the transcript and authentication
reject incompatible ciphertexts. Unknown selectors MUST NOT broaden acceptance.

Changing the sign of a P-256 point leaves the ECDH shared x-coordinate unchanged.
Correct decompression and the full HPKE KEM context are therefore both required:
checking ECDH agreement alone cannot establish exact decoding. Test both point
parities and the complete authentication outcome of a changed prefix.

Repeating an ephemeral keypair and derivation context repeats key and nonce.
Encrypting different plaintexts in that condition violates GCM's nonce uniqueness
requirement. Fresh ephemeral keys are a publisher duty for every seal. Replaying
an already produced envelope is not a fresh encryption and does not violate it.
This profile provides neither forward secrecy after issuer-key compromise nor
revocation of keys already delivered to readers.

## 7. Conformance and compatibility

A publisher claim covers selection, fresh sealing, fixed suite, payload/BIND
composition and compressed output. An issuer claim covers configuration-gated
selection, exact decoding, fixed-suite opening, failure behavior and coexistence.
A client claim covers faithful selector relay and delivery/request association.
A complete deployment requires all applicable duties; cryptographic library
support alone does not establish deployment compatibility.

Evidence SHOULD include published HPKE vectors and independent implementation
interoperability for the fixed suite, plus DCA-specific fixed vectors for `info`,
BIND and compressed transport. Tests SHOULD compare DHKEM and key-schedule
intermediates as well as final plaintext; include leading zeros, both parities,
invalid points, selector mutation, same-key coexistence, copied coordinates,
16/32-octet payloads and cached-delivery transitions. Historical size-experiment
vectors using another key schedule do not establish conformance to this profile.

The suite, `info`, selector and internal serialization are fixed compatibility
contracts. An incompatible change requires a distinct contract identifier under
the profile rules. This document defines an optional extension; it does not claim
that a particular reference implementation has completed its conformance tests.

## 8. Normative references

- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html), especially Sections 4, 5 and 7.
- [SEC 1, version 2.0](https://www.secg.org/sec1-v2.pdf), Sections 2.3.3 and 2.3.4.
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html): BCP 14 requirement words.
- [DCA core protocol](spec--core-protocol.md).
- [DCA profiles](spec--profiles.md).
- [DCA data format](spec--data-format.md).
- [DCA sealed-key envelopes](spec--sealed-key-envelopes.md).
- [DCA period-key profile](spec-profile--period-keys.md).
- [DCA chain-key profile](spec-profile--chain-keys.md).
- [DCA security model](spec--security-model.md).
