# Compact ECDH envelopes

Status: reference extension for the optional profile `dca-profile-compact-ecdh`;
implementation evidence, no protocol authority

The [compact-ECDH profile](../../../docs/spec-profile--compact-ecdh.md) holds the contract. A
publisher seals a 16- or 32-octet payload to the issuer's P-256 key with RFC 9180 HPKE in Base mode,
suite `0x0010`/`0x0001`/`0x0002`, `info` `dca-derivation-compact-ecdh` and the BIND octets as AAD. The
wire carries the ephemeral point compressed: `02|03 || X || ciphertext`, 65 octets for a key and 81
for a generic 32-octet payload. The 16-octet key saves 32 octets against the ordinary
97-octet envelope. The generic payload capacity does not define composition with content groups;
that composition remains undefined and must be refused.

Base imports nothing from here. Base carries the generic parts: an issuer config `envelope`
member the Sealer passes to the key sealing and writes into the issuer block, the client's relay
of that member, and the issuer engine's `envelopeProcedures`, which run only when a request names
the procedure and its key entry lists it in `envelopes`.

## Setup

- Publisher: compose `compactEcdhPublisherContribution()` (it owns the key sealing seam) and give
  the issuer `envelope: "compact-ecdh"` beside its `ecdh-p256` key. Other issuers stay ordinary.
- Issuer: pass `compactEcdhIssuerContribution()` to `createIssuerCore`, and give the key entry its
  `publicKey` and the allowlist `envelopes: ["ecdh-p256", "compact-ecdh"]`. The same key pair and
  keyId then keep opening cached ordinary deliveries. `["compact-ecdh"]` alone permits compact
  only: a request without `envelope` opens nothing. The engine refuses a malformed, repeated or
  unknown entry as an issuer fault where it reads the entry. It refuses an entry of another
  algorithm that permits `compact-ecdh` the same way, because the contribution declares ECDH P-256
  keys. The opener still refuses a key pair off ECDH P-256, such as a P-384 key labelled `ecdh-p256`.
- Client: nothing to compose; the base client relays `envelope`.

## Modules

Only the publisher and the issuer use these, so they sit in the pairwise slice
`core-shared--publisher-issuer/`; the client relays `envelope` without reading it.

- `core-shared--publisher-issuer/hpke.js`: the fixed suite on WebCrypto ECDH, HMAC-SHA256 and AES-GCM, with no HPKE
  library. Single-shot `seal` and `open` at sequence zero, full DHKEM ExtractAndExpand and key
  schedule. `seal` generates its ephemeral key pair itself. `open` takes the recipient's key pair,
  because the KEM context holds the recipient's public key and WebCrypto cannot derive it from a
  non-extractable private key.
- `core-shared--publisher-issuer/p256Point.js`: SEC 1 compression and decompression with BigInt field arithmetic.
  Decompression refuses a wrong length, a prefix other than 02 or 03, x at or above p, and an x
  without a point; WebCrypto's import of the recovered point is the final check.
- `core-shared--publisher-issuer/envelope.js`: `seal(payload, issuerPublicKey, aad)` returns the blob as bytes;
  `open(blob, issuerKeyPair, aad, width)` checks the exact width and the prefix before any key
  agreement, and every failure throws `unseal_failed` with one message.
- `core-publisher/keySealing.js`: the publisher contribution. Seals with `envelope.js` under the
  core BIND octets when the Sealer passes `envelope: "compact-ecdh"`, and hands every other seal
  to the core key sealing.
- `core-issuer/procedure.js`: the issuer contribution and the `compact-ecdh` envelope procedure
  the base engine runs.
- `core-shared--publisher-issuer/selector.js`: the `"compact-ecdh"` literal and `readEnvelopeSelector`, which reads
  an issuer block or unlock request as `omitted`, `compact` or `refuse`.
- `core-shared--publisher-issuer/testing/deterministicHpke.js`: RFC 9180 DeriveKeyPair and sealing under a given
  ephemeral key pair, returning dh, shared_secret, key and base_nonce. Tests and the vector recorder
  use it; no production module imports it.

What the extension copied: the private `webCryptoBytes` helper of
`core-shared/cryptoProvider.js`, because base exports no HMAC or raw ECDH output.

## Evidence

- `test/vectors/rfc9180-suite-0010-0001-0002.json`: the one Base-mode entry for this suite from Go
  1.27.0's `crypto/hpke` test data, with its provenance. That source records keys, `enc` and an
  accumulated hash over 1000 seals rather than per-message intermediates; the test reproduces `enc`
  and the hash.
- `test/vectors/dca-compact-ecdh.json`: DCA cases from `tools/record-dca-vectors.mjs`, with both Y
  parities per payload width, an ECDH x-coordinate with a leading zero octet, and every
  intermediate. `goChecked` names the checks a second implementation made, one name per check; `goSealed` holds
  envelopes it sealed, which the test opens.
- Refusal and freshness tests in `test/envelope.test.js` and `test/p256-point.test.js`.
- `test/exchange.test.js`: publisher, client relay and issuer together: a mixed delivery, one key
  pair serving cached ordinary and compact deliveries, period keys, a missing permission,
  removed, inserted, changed and copied selectors, and RSA or misregistered keys.

Run from `js/`:

```sh
pnpm run test:reference:extension:compact-ecdh
```

## Composition and migration boundaries

An omitted selector always selects the ordinary procedure before the key entry's
permission is checked; it never guesses a permitted alternative. Unknown selectors
and disallowed procedures fail without a fallback. The base engine owns this
permission check and whole-key retirement for primary and auxiliary envelopes.
A registered opener may be a function or an `{ open, keyAlgorithms }` declaration;
the engine checks the latter's declared key algorithm before invoking it.

The same issuer key pair and keyId can serve both constructions while both are
permitted. Removing compact permission can reject cached compact deliveries even
while ordinary deliveries still work; whole-key retirement refuses both. Clients
relay the opaque selector and preserve omitted versus present values.

The publisher refuses compact envelopes combined with the current content-group
seed format in one issuer block. An ordinary seed issuer may coexist with a
separate compact issuer. Support for a 32-octet compact payload does not select a
seed format or adopt that composition. The profile requires construction-compatible
bytes, not an HPKE library; other ports may use their existing primitives.
