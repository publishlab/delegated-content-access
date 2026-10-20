# Client-bound transport extension

Status: implemented optional extension

This extension wraps issuer-delivered keys for one client's non-extractable
keypair. A deployment selects it through one of two profile identifiers,
`dca-profile-client-bound-ecdh-p256` or `dca-profile-client-bound-rsa-oaep`
(`docs/spec--profiles.md`, section 7). Base source has only injection seams and
imports nothing from this directory.

## Source placement

| Responsibility | Location |
| --- | --- |
| Client capability and private-key closure | `core-client/` |
| Method mechanics shared by client and issuer | `core-shared--client-issuer/` |
| Issuer sealing and wrapping | `core-issuer/` |
| Issuer response transport adapter | `../../adapter-issuer/KeyDelivery.js` |
| Cross-role ECDH-P256 and RSA-OAEP method entries | `ecdhP256.js`, `rsaOaep.js` |
| Tests owned only by this extension | `test/` |

ECDH-P256 and RSA-OAEP are methods inside this extension. They are not separate
extensions. The extension entry modules combine each method's role-specific
parts without changing the source ownership beneath them. Each entry also
reexports issuer sealing, so a client-only source copy takes the client and
client-issuer slices instead of either cross-role entry.

The host injects a client profile through
`clientBoundKeyCapability(keyPair, profile)`. On the issuer, the shipped
`adapter-issuer/KeyDelivery.js` accepts the matching profile as
`new KeyDelivery({ profile, random })`: the host calls `preflight` before key
opening and `prepare` on the final response under the returned view. The demo
`IssuerServer({ clientBoundProfile })` is one composition of that adapter, not
the integration seam. Neither side chooses a default method. Each method
exports `RANDOM_REQUIRED` so the issuer host can reject an incomplete
deployment at construction. ECDH-P256 needs injected nonce randomness;
RSA-OAEP does not.

`keyPair` is `{ privateKey, publicKey }`: `privateKey` is the selected method's
non-extractable private `CryptoKey`, and `publicKey` is its already exported
public JWK, not the public `CryptoKey`. Export only the public half when the
host creates the pair; the synchronous request builder relays that JWK.
Selecting this transport does not enable period-key relay. A period-key host
also selects client `relayPeriodKeys` and issuer `periodKeyInput`, as described
in the [role composition guide](../../README.md#how-profile-selection-reaches-role-code).
Keep endpoint selection in trusted issuer routes and cache namespaces tied to
the host's authority/client context; the public offer and page data do not
choose that context. [PORTING.md](../../PORTING.md) owns the storage/reset duties.

A response without `transport` uses direct delivery. A present `transport`
names its selected method with `method`; there is no `mode` member. The client
requires that method to match its offer and rejects missing, unknown or
mismatched methods without trying direct delivery. Other transport members
are ignored under the common JSON rules.

Every wrapped key entry is bound to its key kind (`docs/spec--response-binding.md`,
section 6). `core-shared--client-issuer/keyKind.js` builds the one kind
context: UTF-8 `dca-bind-client-bound-key-kind`, one zero octet, then UTF-8
`contentKey`, `periodKey` or `chainKey`. ECDH-P256 passes it as AES-GCM
additional data under the one response transport key; RSA-OAEP passes it as
the OAEP label. Both methods take the kind as an explicit parameter:
`wrap(keyBytes, keyKind)` on the issuer sealer and
`open(value, usages, keyKind)` on the client opener. `KeyDelivery` names the
kind of the result section it writes, and the client resolver names the kind
of the admitted section it reads. Neither side has a default or infers the
kind from the key width, the usages or the ciphertext; a missing or unknown
kind is `bad_config`. A key entry moved into another section fails its tag or
padding check as `unwrap_failed`, one malformed key entry, and the opener does not
retry it under another kind or an empty context.

A selected extension may compose further kinds for response sections it adds
beside `keys`. Trusted composition settles them once with
`settleKindDescriptors(input)`, which both method entries export:

- Each new kind name maps to `{ width: 16, open: "raw" }` or
  `{ width: 16, open: "aesHandle" }`. A base kind name, another width or an
  extra member is `bad_config`.
- The result is a frozen set. A transport takes a composed kind only from a set
  `settleKindDescriptors` returned, never from a plain object.
- The host hands the same set to
  `clientBoundKeyCapability(keyPair, profile, { composedKinds })` and to
  `new KeyDelivery({ random, profile, composedSections, composedKinds })`.
  `KeyDelivery` wraps every `composedSections` entry under its declared kind.
- `createIssuerCore` returns the sections its contributions declare as
  `responseSections`; the host passes `core.responseSections` as
  `composedSections`. The demo `IssuerServer` takes the pair as its
  `responseSections` and `composedKinds` config members.
- In client-bound mode `prepare` refuses with `bad_config`, before it wraps
  anything, a top-level body member other than `keys`, `errors`,
  `notDelivered` and `periodGeometry` that no declared section starts at. An
  undeclared section would otherwise leave raw under a body marked
  client-bound. Direct mode is unchanged.
- A composed kind binds through the same context. `contentGroupPeriodKey` gives
  `dca-bind-client-bound-key-kind`, a zero octet, then `contentGroupPeriodKey`.
- When the set holds a `raw` kind, the capability asks the method's
  `assertCanOpenRawKeys` at setup, so an RSA-OAEP key without `decrypt` usage
  is refused there, not on the first answer.

The content-groups extension composes `contentGroupChainKey` and
`contentGroupPeriodKey`, both `raw`; its
[README](../content-groups/README.md) shows the host setup. Without a
composed set, the capability and both sealers bind only the three base kinds.

Run this extension's gate with:

    npm run test:reference:extension:client-bound-transport

Tests that compose this extension with another optional extension belong in
`test-extensions/`, not here. The recorded wire fixtures remain under
`verification/vectors/v1/profiles/dca-profile-client-bound-*`; `test-vectors/client-bound-vectors.test.js`
owns their replay.
