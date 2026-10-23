# DCA publisher-to-issuer sealed-key envelopes

Status: Public Working Draft

## Abstract

This document specifies the public-key envelopes used to carry DCA key
material from a publisher to an issuer. It defines ECDH P-256 and RSA-OAEP
envelopes and the BIND construction that commits each payload to its DCA
coordinate.

<a id="1-scope"></a>
## 1. Introduction

A publisher seals key material for one issuer and places the resulting envelope
in a render. The client relays that envelope in an unlock request. This document
defines the publisher-to-issuer envelope formats and their coordinate binding,
called BIND.

It does not define envelope placement in DCA messages, issuer authorization,
content ciphertext, chain-key derivation or issuer-to-client delivery.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Envelope model

An envelope carries exactly one 16-octet `c` content key, `p` period key
or `pc` positioned chain key. Every delivered key of every kind MUST be exactly
16 octets, before sealing and after opening, in direct and client-bound
delivery; this width is fixed for DCA v1 and is not selected by issuer, family,
render or observed length. A publisher, issuer or client MUST NOT select a
second width, infer another payload size, or select a DCA version, profile,
key kind or width from an observed length; no width negotiation exists in DCA v1.
It MUST NOT retry another width or emit duplicate width-specific wrap sets. A
different delivered-key width requires a new suite or specification version,
not another v1 profile. The default seal algorithm is selected by the issuer public-key registration;
no algorithm or width identifier is carried inside the binary envelope. The
optional [compact ECDH profile](spec-profile--compact-ecdh.md) adds an explicit
procedure selector beside the sealed collections while retaining the same keypair.

The current algorithms are:

- `ecdh-p256`: ephemeral P-256 ECDH followed by AES-256-GCM; and
- `rsa-oaep`: RSA-OAEP with SHA-256 and a 2048-bit-or-larger key.

### 2.1 Issuer opening-key provisioning

The issuer generates a fresh keypair for each opening-key generation from a
cryptographically secure random source and MUST dedicate it to the DCA envelope
construction: it MUST NOT expose the private key through another protocol's
decryption, key-agreement, signing or raw-key operation. The issuer retains the
private key and gives only the public key to each publisher authorized to seal
for that opening-key namespace.

The manual interchange form is PEM text with label `PUBLIC KEY`. Its decoded
value is an X.509 `SubjectPublicKeyInfo` structure:

- `ecdh-p256` carries an EC public key on `secp256r1` (also named P-256 or
  `prime256v1`); and
- `rsa-oaep` carries an RSA public key.

The issuer gives each authorized publisher the public key with its `issuerName`,
new `keyId` and envelope algorithm name over a trusted, authenticated channel;
DCA v1 defines no provisioning message or transport. The publisher MUST
authenticate these values, because key substitution would redirect newly sealed
material; the public key itself needs no confidentiality. Unlock endpoints reach
clients through trusted client integration
([core Section 9](spec--core-protocol.md#9-delegation-completeness)), not through
publisher sealing configuration.

The envelope algorithm name is the provisioning token `ecdh-p256` or
`rsa-oaep` from Section 2, compared as exact lowercase ASCII. It is
configuration exchanged with the key, not a DCA message member. The optional
`envelope` selector defined by the compact ECDH profile selects that profile
without replacing this registered default or the key identifier. The client-bound methods `ECDH-P256` and `RSA-OAEP`
([profiles Section 7](spec--profiles.md#7-client-bound-custody-profiles)) name
different constructions and do not select a publisher-to-issuer envelope.

Before use, the publisher MUST parse the `SubjectPublicKeyInfo`, confirm that
its key type and parameters match the named algorithm, and reject a malformed
or mismatched key. The issuer MUST confirm that the retained private key matches
the delivered public key. It MUST NOT send the private key to the publisher.

During rotation, the issuer creates a new keypair and `keyId`, delivers the new
public record, and retains the old private key while cached renders still name
it. Provisioning, activation, overlap, and retirement are control-plane actions;
they are not fields in an envelope.

The envelope travels as a canonical binary string
([data-format Section 2.2](spec--data-format.md#22-binary-strings)): the
producer MUST emit it and the issuer MUST admit it under those rules. This
document defines the decoded octets.

## 3. BIND

BIND commits the sealed payload to the coordinate at which the issuer opens it.
The client can rename, remove, copy and replay message fields, so the issuer
rebuilds BIND from trusted sources (Section 3.3).

### 3.1 Binding forms

`dca-bind-key-envelope` defines three forms:

```text
content: dca-bind-key-envelope | c  | renderId | contentName
period:  dca-bind-key-envelope | p  | renderId | accessGroup | t
chain:   dca-bind-key-envelope | pc | renderId | accessGroup | suppliedT
                            | chainsPerDay | periodMinutes
```

Spaces above are layout only. The `pc` form belongs to
`dca-profile-chain-keys`; [spec-profile--chain-keys.md](spec-profile--chain-keys.md) defines
its geometry and `suppliedT` validity.

The kind field separates keys with different authority:

- `c` identifies an item `contentKey` envelope;
- `p` identifies a `periodKey` envelope; and
- `pc` identifies a positioned chain key.

An envelope of one kind MUST NOT open as another kind.

### 3.2 Canonical encoding

Fields are concatenated in their listed order with one `|` octet (`0x7c`)
between each pair. There is no leading or trailing delimiter, whitespace,
escaping, padding or length prefix.

Every field is encoded as US-ASCII octets. String fields use their validated
wire spelling; geometry-number fields use the canonical decimal spelling of
their admitted integer values, as specified below.
Every variable field MUST exclude `|`. A producer MUST refuse a value that
cannot be represented by exactly one form.

Field requirements are:

- `dca-bind-key-envelope`, `c`, `p` and `pc` are the literal strings shown above.
- `renderId` is the canonical 22-character unpadded base64url encoding of
  exactly 16 octets. Generation and freshness are defined by
  [spec--core-protocol.md](spec--core-protocol.md#41-producer-form).
- `contentName` and `accessGroup` use the identifier grammar in
  [spec--data-format.md](spec--data-format.md#21-identifiers).
- `t` is the period label carried by the enclosing format, and `suppliedT` is
  the period label of the sealed chain key's supplied position. BIND treats
  both as opaque ASCII fields after the delimiter check.
- `chainsPerDay` and `periodMinutes` use the canonical decimal spelling of
  their admitted positive integer values, with no leading zero, sign,
  fraction, exponent or whitespace. JSON spellings `2`, `2.0` and `2e0`
  therefore produce the same BIND field `2`. The pair MUST be complete and
  valid for `suppliedT` under the chain-key specification.

### 3.3 Trusted field sources

The publisher builds BIND from the coordinate at which it places the envelope.
The issuer MUST rebuild the same form from the `renderId` in the verified
publisher assertion, the key kind of the request section that carried the
envelope, and the envelope's own coordinate: `contentName`; `accessGroup` and
`t`; or `accessGroup`, `suppliedT` and the geometry the request resolved for
that family. For a relayed envelope that is the coordinate at which the
request presented it
([core Section 6.1](spec--core-protocol.md#61-presented-coordinates)). The
issuer MUST NOT build BIND from any other coordinate, such as a policy-selected
result coordinate, and MUST NOT accept a client-supplied or alternate BIND
value. [Core Section 6.3](spec--core-protocol.md#63-opening-key-scope-and-bind)
specifies the permission condition for opening.

The optional [compact ECDH profile](spec-profile--compact-ecdh.md) defines an
alternative procedure selected by `envelope` in the issuer block and relayed
unlock request. For that profile, selection follows its rules with the same
registered keypair and keyId; omission retains the procedures defined here.
The compact profile owns its HPKE derivation, compressed carrier and payload
widths. It does not alter the `ecdh-p256` construction below.

## 4. ECDH P-256 envelope

The binary envelope is:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 65 octets | Fresh ephemeral P-256 public key, uncompressed |
| 65 | 32 octets | Encrypted 16-octet payload and 16-octet GCM tag |

For each envelope, the publisher MUST generate a fresh ephemeral P-256 keypair
using its cryptographic implementation and MUST NOT reuse an ephemeral keypair
across envelopes. It performs ECDH with the issuer public key. The shared
x-coordinate MUST be encoded as an unsigned big-endian integer at the P-256
field width: exactly 32 octets, retaining or adding leading zero octets as
needed. The publisher and issuer use those 32 octets directly as the
AES-256-GCM key. A producer or issuer implementing this algorithm MUST NOT
apply a KDF.

The AES-GCM nonce MUST be twelve zero octets. It is implicit and MUST NOT
be carried in the envelope. The publisher encrypts the payload with that nonce
and the complete BIND octets as AES-GCM `additionalData`. The fresh ephemeral
keypair requirement applies to every envelope, including different values at
the same coordinate: reusing a pair with the same recipient repeats the AES key
and nonce. Different BIND values do not make that reuse safe.

The decoded envelope MUST be exactly 97 octets (130 unpadded base64url
characters). The issuer MUST refuse any other decoded length before it opens
the envelope; no carried-nonce format
fallback is permitted. The first octet of the
65-octet public-point field MUST be `0x04`; the issuer MUST refuse any other
value before importing the point, even if its cryptographic implementation
accepts that encoding. It MUST import the received
public point as an uncompressed P-256 point through its cryptographic
implementation and fail opening if import, point validation or key agreement
fails. It then rebuilds BIND and authenticates the GCM ciphertext with it. The
issuer MUST fail opening on a BIND difference.

## 5. RSA-OAEP envelope

The binary envelope is one RSA ciphertext exactly as wide as the issuer
modulus. The modulus MUST be at least 2048 bits. RSA-OAEP uses SHA-256 for its
digest, MGF1 with SHA-256 and an empty label.

The OAEP plaintext is:

```text
BIND || key
```

`key` is exactly 16 octets, as Section 2 fixes for every kind. The producer and
the issuer split the plaintext at that stated width,
never at the recovered length: after decryption the issuer treats the final
`key` octets as the key and all preceding octets as BIND. The plaintext length
MUST be exactly `len(expected BIND) + len(key)`, and recovered BIND MUST equal
expected BIND in full. A prefix comparison is invalid.

For RSA-OAEP with SHA-256 and a modulus of `k` octets, the maximum plaintext is
`k - 66` octets: 190 octets at the 2048-bit minimum. Under the v1 field bounds
(identifiers of at most 64 characters under
[data-format Section 2.1](spec--data-format.md#21-identifiers), the
11-character period label of
[period-keys](spec-profile--period-keys.md#base-period-key-requirements), the
22-character `renderId`, and geometry values that divide 1440 under the
[chain-key window rules](spec-profile--chain-keys.md#windows)), the longest BIND is the
`pc` form at no more than 134 octets, so `BIND || key` is at most 150 octets
and every form fits the minimum modulus.

A profile that permits a wider BIND field has to show that its maximum
plaintext satisfies the OAEP bound, with a larger issuer modulus or smaller
field bounds. A producer MUST reject a coordinate that exceeds the applicable
bound before attempting RSA-OAEP encryption.

## 6. Opening and failure

An issuer opens an envelope only with the private key selected inside the
verified publisher registration and the `keyId` resolution of
[core Section 6.3](spec--core-protocol.md#63-opening-key-scope-and-bind).

The issuer MUST NOT release key material after a malformed field, unsupported
form, invalid envelope encoding, BIND mismatch, authentication failure or
recovered payload of the wrong length. At the issuer-facing boundary each of
these, including an RSA-OAEP padding failure, is one generic opening failure:
the issuer MUST answer the same way whichever fired and MUST NOT name the field,
stage or cause; it need not distinguish relabeling from corruption, a wrong
private key or publisher key rollover. Issuer provisioning faults keep their own
typed answer. An implementation MAY keep distinct internal diagnostics behind
that boundary. Whether one failed envelope rejects a whole request or is
reported beside successful items is defined by the enclosing unlock protocol.

Where a runtime offers a constant-time comparison, an issuer SHOULD compare
recovered BIND against expected BIND with it, over the whole value Section 5
requires. An issuer SHOULD decode RSA-OAEP through its runtime's own OAEP
implementation rather than assembling the EME-OAEP steps itself.

## 7. Security considerations

Successful opening establishes that the recovered payload is cryptographically
bound to the expected BIND value under the selected issuer opening key. It does
not authenticate the producer: possession of the issuer public key is
sufficient to construct an envelope. Publisher attribution and authorization
are not properties of the envelope. The enclosing DCA protocol separately
authenticates render evidence and applies issuer policy.

BIND prevents a client from presenting an unchanged envelope while successfully:

- moving an item content key to another `contentName`;
- moving a period key to another `accessGroup` or `t`;
- substituting content-key, period-key and chain-key envelopes for one
  another;
- moving an envelope to another render; or
- relabeling a chain key to another group, position or geometry.

BIND does **not**:

- authorize the coordinate or replace issuer policy;
- isolate `issuerName` or `keyId` aliases sharing one opening private key,
  which are one entrustment domain
  ([core Section 2.1](spec--core-protocol.md#21-publisher));
- make a delivered period key or chain key render-specific;
- narrow the inherent window-start-through-cutoff reach of a chain key;
- revoke key material already delivered to a client;
- bind shared client-side `contentData` to its page location;
- authenticate publisher identity by itself; or
- protect issuer-to-client delivery.

Publisher separation relies on verified publisher registration and
registration-scoped opening keys. Mutually untrusted publishers MUST NOT share
an opening keyset merely because their `renderId` values should differ.

## 8. Versioning and conformance

`dca-bind-key-envelope` is a specification constant that identifies this
binding grammar, not the surrounding JSON format, and is not a negotiable wire
field. Changing a form's field set, order, encoding or security meaning requires
a new BIND grammar identifier; editorial clarification or an explicitly
specified compatible extension does not. Existing forms remain byte-for-byte
unchanged when a new form or envelope algorithm is introduced.

An implementation SHOULD cover each envelope algorithm and BIND form it
implements with conformance evidence, including changes to each bound field,
cross-kind substitution, cross-render presentation, delimiter injection,
non-canonical `renderId`, incomplete chain geometry, decoded ECDH length, a
payload or envelope of a non-canonical width and RSA prefix confusion.

## 9. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [DCA core protocol](spec--core-protocol.md)
- [DCA data format](spec--data-format.md)
- [DCA period-key capabilities](spec-profile--period-keys.md)
- [DCA chain keys: construction and delegation](spec-profile--chain-keys.md)
- [DCA conformance profiles](spec--profiles.md)

## 10. Informative References

- [DCA data-format example](design--data-format--example.md)
