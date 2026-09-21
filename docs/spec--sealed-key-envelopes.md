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
content ciphertext, period-chain derivation or issuer-to-client delivery.

This document defines the envelope-algorithm and BIND requirements.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Envelope model

An envelope carries exactly one 16-octet `c` content key, `p` exact leaf
or `pc` positioned chain state. This semantic payload width is fixed for DCA
v1; it is not selected by issuer, family, render or observed length.
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements) and
[spec--period-key-chains.md](spec--period-key-chains.md#canonical-construction)
define the period capabilities. The seal algorithm is selected by the issuer
opening key; no algorithm or width identifier is carried in the envelope.

The current algorithms are:

- `ecdh-p256`: ephemeral P-256 ECDH followed by AES-256-GCM; and
- `rsa-oaep`: RSA-OAEP with SHA-256 and a 2048-bit-or-larger key.

### 2.1 Issuer opening-key provisioning

The issuer generates a fresh keypair for each opening-key generation. It uses
a cryptographically secure random source. It SHOULD dedicate the keypair to
DCA. The issuer retains the private key and gives only the public key to each
publisher authorized to seal for that opening-key namespace.

The manual interchange form is PEM text with label `PUBLIC KEY`. Its decoded
value is an X.509 `SubjectPublicKeyInfo` structure:

- `ecdh-p256` carries an EC public key on `secp256r1` (also named P-256 or
  `prime256v1`); and
- `rsa-oaep` carries an RSA public key whose modulus is at least 2048 bits.

The issuer sends the following configuration values together through a trusted,
authenticated channel:

- `issuerName`;
- a new `keyId` for this key generation;
- the envelope algorithm name;
- the complete PEM public-key text; and
- the unlock endpoint or endpoints that serve this issuer.

The channel may be an operator copying text, secure messaging, configuration
management, or an authenticated management API. DCA v1 defines no provisioning
message or transport. Public-key confidentiality is unnecessary, but the
publisher MUST authenticate the received values because key substitution would
redirect newly sealed material.

Before use, the publisher MUST parse the `SubjectPublicKeyInfo`, confirm that
its key type and parameters match the named algorithm, and reject a malformed
or mismatched key. The issuer MUST confirm that the retained private key matches
the delivered public key. It MUST NOT send the private key to the publisher.

During rotation, the issuer creates a new keypair and `keyId`, delivers the new
public record, and retains the old private key while cached renders still name
it. Provisioning, activation, overlap, and retirement are control-plane actions;
they are not fields in an envelope.

A producer MUST spell the complete envelope as a canonical binary string under
[spec--data-format.md](spec--data-format.md#22-binary-strings). An issuer MUST
admit it under the same rules. The enclosing format defines its member placement
and wire spelling. This document defines the decoded envelope octets and their
interpretation.

## 3. BIND

BIND commits the sealed payload to the coordinate at which the issuer opens it.
The client can rename, remove, copy and replay message fields. The issuer
therefore reconstructs BIND from verified render evidence and the coordinate it
is processing. It MUST NOT accept a client-supplied BIND string.

### 3.1 Binding forms

`dca-bind-v1` defines three forms:

```text
content: dca-bind-v1 | c  | renderId | contentName
period:  dca-bind-v1 | p  | renderId | accessGroup | t
chain:   dca-bind-v1 | pc | renderId | accessGroup | suppliedT
                            | chainsPerDay | periodMinutes
```

Spaces above are layout only. The chain form belongs to the
`dca-period-chain-v1` capabilities. Their
geometry, chain-state width and `suppliedT` validity are
defined by [spec--period-key-chains.md](spec--period-key-chains.md).

The kind field separates keys with different authority:

- `c` identifies a direct `contentKey` envelope;
- `p` identifies an exact `periodKey` envelope; and
- `pc` identifies positioned period-chain state.

An envelope of one kind MUST NOT open as another kind.

### 3.2 Canonical encoding

Fields are concatenated in their listed order with one `|` octet (`0x7c`)
between each pair. There is no leading or trailing delimiter, whitespace,
escaping, padding or length prefix.

Every field is encoded as the US-ASCII octets of its validated wire spelling.
Every variable field MUST exclude `|`. A producer MUST refuse a value that
cannot be represented by exactly one form.

Field requirements are:

- `dca-bind-v1`, `c`, `p` and `pc` are the literal strings shown above.
- `renderId` is the canonical 22-character unpadded base64url encoding of
  exactly 16 octets. The issuer obtains it from the verified `resourceJWT`.
  Generation and freshness are defined by
  [spec--core-protocol.md](spec--core-protocol.md#41-producer-form).
- `contentName` and `accessGroup` use the identifier grammar in
  [spec--data-format.md](spec--data-format.md#21-identifiers).
- `t` is the exact-period label carried by the enclosing format. BIND treats it
  as an opaque ASCII field after the delimiter check.
- `suppliedT` names the sealed chain-state position and follows the
  period-chain coordinate grammar. This document and an implementation API use
  that name for the position. An implementation's selection or listing
  contract may carry the same label as `t`. Wire member names and the BIND
  octets do not change.
- `chainsPerDay` and `periodMinutes` are positive decimal integers with no
  leading zero, sign or whitespace. The pair MUST be complete and valid for
  `suppliedT` under the period-chain specification.

For example, the octets for a direct key at `bodytext` are:

```text
dca-bind-v1|c|<renderId>|bodytext
```

`<renderId>` is illustrative notation, not part of the encoding.

### 3.3 Trusted field sources

The publisher builds BIND from the coordinate at which it places the envelope.

The issuer rebuilds the same form from:

- `renderId` in the verified publisher assertion;
- the key kind selected by the parsed request member; and
- the content, period or chain coordinate being processed.

The coordinate used for BIND MUST be the coordinate used for the applicable
access decision. The issuer MUST NOT accept an alternate BIND value beside the
envelope.

## 4. ECDH P-256 envelope

The binary envelope is:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 65 octets | Fresh ephemeral P-256 public key, uncompressed |
| 65 | 12 octets | Fresh AES-GCM nonce |
| 77 | payload width + 16 octets | Encrypted payload and 16-octet GCM tag |

The payload width is the 16 octets Section 2 fixes for every kind, so the
decoded envelope is exactly 109 octets.

The publisher generates a fresh ephemeral P-256 key pair for each envelope and
performs ECDH with the issuer public key. The shared x-coordinate MUST be
encoded as an unsigned big-endian integer at the P-256 field width: exactly 32
octets, retaining or adding leading zero octets as needed. The publisher and
issuer use those 32 octets directly as the AES-256-GCM key. A producer or
issuer implementing this algorithm MUST NOT apply a KDF. A KDF-based
construction requires a distinct, explicitly identified interoperable
algorithm or profile. A local or unsignalled setting MUST NOT change this
transcript.

The publisher encrypts the payload with the fresh nonce and the complete BIND
octets as AES-GCM `additionalData`.

The decoded envelope MUST be exactly 109 octets. The issuer MUST refuse any
other decoded length before it opens the envelope. It MUST import the received
public point as an uncompressed P-256
point through its cryptographic implementation and fail opening if import,
point validation or key agreement fails. It then rebuilds BIND and
authenticates the GCM ciphertext with it. The issuer MUST fail opening on a BIND
difference or a recovered payload of a width other than the one fixed for DCA v1.

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

The publisher puts BIND in the OAEP plaintext, not the OAEP label, so the same
format can be implemented by platforms whose OAEP APIs do not expose labels.

For RSA-OAEP with SHA-256 and a modulus of `k` octets, the maximum plaintext is
`k - 66` octets. At the 2048-bit minimum, `k` is 256 and the maximum is 190
octets. Under the v1 field bounds, the base direct `c` BIND is at most 101
octets and `BIND || key` is at most 117 octets. The base exact-period `p` BIND
is at most 113 octets and `BIND || key` is at most 129 octets. Both therefore
fit the minimum modulus.

Those maxima come from the field widths Section 3 fixes and the documents it
cites. `dca-bind-v1` is 11
octets, the kind field is 1 octet for `c` and `p` and 2 for `pc`, `renderId` is
22 characters, and one `|` sits at every field boundary. `contentName` and
`accessGroup` reach 64 characters under the identifier grammar of
[spec--data-format.md](spec--data-format.md#21-identifiers). An exact `t`
reaches 11 characters under the `YYMMDDTHHMM` form of
[spec--period-keys.md](spec--period-keys.md#base-exact-period-requirements).
`chainsPerDay` divides 1440 and `periodMinutes` divides `1440 / chainsPerDay`
([spec--period-key-chains.md](spec--period-key-chains.md#windows)), so each
geometry field is at most 4 digits. The three forms add up as:

- `c`: 11 + 1 + 22 + 64 field octets and 3 delimiters, so 101 octets;
- `p`: 11 + 1 + 22 + 64 + 11 field octets and 4 delimiters, so 113 octets; and
- `pc`: 11 + 2 + 22 + 64 + 11 + 4 + 4 field octets and 6 delimiters, so 124
  octets.

The `c` and `p` sums are attainable. The `pc` sum bounds the form: the product
of the two geometry fields is at most 1440, so their spellings carry at most 5
digits together and the longest chain BIND is 121 octets.

The `pc` BIND is at most 124 octets under the conservative field-wise bound
in [spec--period-key-chains.md](spec--period-key-chains.md#chain-envelope-bind),
giving at most 140 octets with its 16-octet state. Every kind stays inside the
190-octet maximum.

A profile that permits a wider BIND field has to show that its maximum plaintext
satisfies the OAEP bound, and needs either a larger issuer modulus or smaller
field bounds. A different delivered-key width requires a new suite/specification
version, not another v1 profile. A producer MUST reject a coordinate that exceeds
the applicable bound before attempting RSA-OAEP encryption.

## 6. Opening and failure

An issuer opens an envelope only with the private key selected inside the
verified publisher registration and the envelope's `keyId` processing rules.

The issuer MUST NOT release key material after a malformed field, unsupported
form, invalid envelope encoding, BIND mismatch, authentication failure or
recovered payload of the wrong length.

A BIND mismatch is an opening failure. The issuer need not distinguish
relabeling from corruption, a wrong private key or publisher key rollover.
Whether one failed envelope rejects a whole request or is reported beside
successful items is defined by the enclosing unlock protocol.

At the issuer-facing boundary every caller-shaped decode, algorithm,
authentication, BIND and payload-width failure exposes one generic opening
failure. Issuer provisioning faults keep their own typed answer. The issuer MUST
answer the same way whichever of them fired, and MUST NOT name the field, the
stage or the cause that failed. An implementation MAY keep distinct internal
diagnostics behind that boundary.

Where a runtime offers a constant-time comparison, an issuer SHOULD compare
recovered BIND against expected BIND with it, over the whole value Section 5
requires. This document claims no portable timing guarantee, because the
comparison runs on a runtime whose instruction timing an implementation does
not control. A constant-time call, where available, reduces what timing still
reveals.

The same concern applies one step earlier, at RSA-OAEP decoding. An issuer SHOULD
decode through its runtime's own OAEP implementation rather than assembling the
EME-OAEP steps itself, and MUST answer a padding failure, a width failure and a
BIND difference with the one generic failure above. An answer that separates
them lets a caller distinguish padding failures, which is the query a padding
oracle attack needs.

## 7. Security considerations

Successful opening establishes that the recovered payload is cryptographically
bound to the expected BIND value under the selected issuer opening key. It does
not authenticate the producer: possession of the issuer public key is
sufficient to construct an envelope. Publisher attribution and authorization
are not properties of the envelope. The enclosing DCA protocol separately
authenticates render evidence and applies issuer policy.

BIND prevents a client from presenting an unchanged envelope while successfully:

- moving a direct key to another `contentName`;
- moving an exact period key to another `accessGroup` or `t`;
- substituting direct, exact and chain envelopes for one another;
- moving an envelope to another render; or
- relabeling chain state to another group, position or geometry.

BIND does **not**:

- authorize the coordinate or replace issuer policy;
- make a delivered exact or chain capability render-specific;
- narrow the inherent window-start-through-cutoff reach of chain state;
- revoke key material already delivered to a client;
- bind shared client-side `contentData` to its page location;
- authenticate publisher identity by itself; or
- protect issuer-to-client delivery.

Publisher separation relies on verified publisher registration and
registration-scoped opening keys. Mutually untrusted publishers MUST NOT share
an opening keyset merely because their `renderId` values should differ.

An issuer SHOULD dedicate an opening keypair to the DCA envelope construction.
Key reuse does not change the DCA wire protocol. If an issuer reuses the
private key, it MUST NOT expose an operation under that key that accepts a DCA
envelope and releases or derives its payload without the BIND, decoded-length,
whole-plaintext, and failure rules in Sections 3 through 6. Otherwise, the
other protocol becomes an opening oracle outside DCA's checks. An issuer that
dedicates a keypair to DCA envelopes avoids that cross-protocol dependency.

`renderId` binds this publisher-sealed envelope, not the authority of the key
inside it. A publisher may seal the same reusable exact key into several
renders. A delivered key remains usable with every matching content wrap its
authority opens.

## 8. Versioning and conformance

`dca-bind-v1` versions the binding grammar, not the surrounding JSON format. It
is a specification constant, not a negotiable wire field.

Changing a form's field set, order, encoding or security meaning requires a new
BIND grammar identifier. Existing forms remain byte-for-byte unchanged when a
new form or envelope algorithm is introduced.

An implementation SHOULD cover each envelope algorithm and BIND form it
implements with conformance evidence, including changes to each bound field,
cross-kind substitution, cross-render presentation, delimiter injection,
non-canonical `renderId`, incomplete chain geometry, decoded ECDH length, a
payload or envelope of a non-canonical width and RSA prefix confusion.

Vectors and reference implementations are informative evidence. The formats
and requirements in this document define conformance.

## 9. Normative References

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [DCA core protocol](spec--core-protocol.md)
- [DCA data format](spec--data-format.md)
- [DCA exact period-key capabilities](spec--period-keys.md)
- [DCA period-chain construction and delegation](spec--period-key-chains.md)
- [DCA conformance profiles](spec--profiles.md)

## 10. Informative References

- [DCA data-format example](design--data-format--example.md)
