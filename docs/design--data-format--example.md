# Delegated Content Access (DCA) - Data Format

Status: Informative Draft

## Scope

This document first follows one item through the baseline key exchange using
the optional [HTML carrier profile](spec-profile--html-carrier.md),
unlock request, direct HTTPS response and plaintext opening. It then shows an
HTML delivery with optional period and chain-key alternatives, followed by a
separate content-group exchange. The authoritative
contract is
[spec--data-format.md](spec--data-format.md), composed with the focused
specifications indexed by [spec---overview.md](spec---overview.md).

Objects describe fixed fields; arrays hold collections of typed records. The
examples show identity fields first for readability, but member order has no
meaning and does not imply uniqueness. A key coordinate may use several
fields and may have several candidate values. The collection's rules in
[data format Section 2.3](spec--data-format.md#23-collections-of-named-records)
define how repetitions are processed.

Strings standing in for records, such as `"<omitted; same record format as above>"`,
indicate omitted example material, not valid wire records. `[]` means a genuinely
empty collection.

## Minimal key exchange — HTML delivery

This is a **shape example, not a test vector**. Angle-bracket strings stand for
values that the publisher or issuer generates; they are deliberately not valid
base64url, ciphertext or a signed JWT. The same placeholder denotes the same
value across messages. In an actual exchange, the publisher first signs the
resource assertion with its registered ES256 signing key. It then generates a
fresh independent 16-octet content key used once and encrypts the UTF-8
plaintext `Hello, subscriber.` with AES-128-GCM under the content AAD built from
its `renderId` and the item name `bodytext`, using twelve zero nonce octets,
and seals the content key to
the selected issuer using its registered `ecdh-p256` opening public key. The issuer has that registration and its own opening private key;
its HTTPS endpoint has an authenticated server identity, a known agreement to
return direct keys, and a configured caller-authentication and entitlement
policy. These trusted arrangements are prerequisites, not fields the client
can establish by presenting this JSON.

### Publisher → client: dca-sealed-content (encrypted content)

The following JSON is the separate `dca-sealed-content` script body.

```html
<script type="application/json" class="dca-sealed-content">
```
```json
[
  { "contentName": "bodytext", "content": "<AES-GCM-ciphertext-and-16-octet-tag: base64url>" }
]
```

### Publisher → client: dca-data (metadata only)

The following JSON is the HTML page's `dca-data` script body.
`contentData` describes `bodytext`; its encrypted content is delivered in the
separate `dca-sealed-content` block above.

```html
<script type="application/json" class="dca-data">
```
```json
{
  "version": "1",
  "resourceJWT": "<publisher-signed-compact-ES256-JWS>",
  "contentData": [
    {
      "contentName": "bodytext",
      "contentType": "text/plain"
    }
  ],
  "issuerData": [
    {
      "issuerName": "news-issuer",
      "keyId": "opening-2026",
      "sealed": {
        "contentKeys": [
          { "contentName": "bodytext", "key": "<contentKey-bodytext--sealed-to--issuer-pubkey>" }
        ]
      }
    }
  ]
}
```

### Decoded resourceJWT payload

The decoded payload of that signed `resourceJWT` has this shape. Its protected
header contains `alg: "ES256"`, `typ: "JWT"` and a `kid` that resolves to the
publisher's active signing-key registration. The issuer verifies the compact
JWS before using these claims; merely decoding it is insufficient.
The publisher supplies resource metadata in `data` for the issuer's access and
metering decisions. These example field names are publisher-defined; DCA does
not prescribe their vocabulary or policy meaning.

```json
{
  "renderId": "<fresh-16-octet-render-id: base64url>",
  "origin": "https://publisher.example",
  "issuedAt": "2026-10-11T00:00:00Z",
  "resourceId": "article-123",
  "data": {
    "section": "politics",
    "tags": ["elections", "analysis"],
    "fields.paywallGroup": "premium"
  }
}
```

### Client → issuer: unlock request

With no cached content key, the client copies the selected issuer's fields
into the following body and sends it as one `POST` to
`https://issuer.example/unlock` with `Content-Type: application/json` over
authenticated HTTPS. A browser
deployment that relies on page-origin admission also selects the browser-origin
profile, supplies the browser-observed `Origin`, and follows its CORS rules.
Caller credentials, if the deployment requires them, are supplied through its
separately selected authentication mechanism.

```json
{
  "version": "1",
  "issuerName": "news-issuer",
  "resourceJWT": "<publisher-signed-compact-ES256-JWS>",
  "keyId": "opening-2026",
  "sealed": {
    "contentKeys": [
      { "contentName": "bodytext", "key": "<contentKey-bodytext--sealed-to--issuer-pubkey>" }
    ]
  }
}
```

### Issuer → client: unlock response

After verifying the publisher assertion, authenticating the caller and granting
`bodytext` under its policy, the issuer opens the envelope at that authorized
render and item coordinate. Its direct response is HTTP `200`,
`Content-Type: application/json`, `Cache-Control: no-store`, with this body:

```json
{
  "keys": {
    "contentKeys": [
      { "contentName": "bodytext", "key": "<same-16-octet-content-key: base64url>" }
    ]
  }
}
```

The client admits this as the response to that exact request and confirms that
`bodytext` was presented. It decodes the returned key, then opens the
`content` of the `bodytext` record in `dca-sealed-content` with twelve zero nonce octets. Its AES-GCM additional
data is `LP(renderId) || LP("bodytext")`, using the admitted render ID from
`resourceJWT`
([content protection Section 3.2](spec--content-protection.md#32-content-aad)).
Successful authentication
yields the UTF-8 plaintext `Hello, subscriber.` The illustrative placeholders
cannot be decrypted; a real producer must generate and encode all the stated
cryptographic values. See [core request and result](spec--core-protocol.md#5-baseline-unlock-request),
[content encryption](spec--content-protection.md#3-base-protected-item-transcript),
and [direct response admission](spec--response-binding.md#5-direct-representation)
for the controlling rules.

The remaining sections illustrate a larger HTML delivery with period-key and
chain-key alternatives. Those mechanisms require their selected optional
profiles; they are not needed for the baseline exchange above.

## Period keys + chains — HTML delivery

### Publisher → client: dca-sealed-content (encrypted content)

Ciphertext can be many kilobytes. It stays separate from `dca-data` so the
client reads the small metadata first, and so ciphertext delivery can be
deferred. In HTML the publisher puts it in an inert JSON script as records
that name each content item.

<!-- Keep the HTML opening tag and JSON body in separate code blocks for syntax
highlighting. The closing script tag is intentionally omitted. -->

```html
<script type="application/json" class="dca-sealed-content">
```
```json
[
    { "contentName": "bodytext", "content": "k7Hs9dF2mNqR4xPw..." },
    { "contentName": "premiumtext", "content": "Ym3pTvKsL8nWjEcQ..." },
    { "contentName": "locked-data", "content": "xR5fAhNt0gPkBwU7..." }
]
```

In JSON object delivery the same collection is the `sealedContent` member
([object delivery](spec--data-format.md#6-object-delivery)); under the HTML
carrier the client reads it from the `dca-sealed-content` element
([markup delivery](spec--data-format.md#3-markup-delivery)).

### Publisher → client: dca-data (metadata only)

The following JSON is delivered in the HTML page's `dca-data` script element.
A delivery using only ordinary period keys omits `periodGeometry`, as does a content-key-only baseline delivery.
A delivery selecting chain processing, including retained-chain opening without
fresh chain supply, carries one complete pair shared by every chain-bearing
group. There is no protocol default.

```html
<script type="application/json" class="dca-data">
```
```json
{
    "version": "1",

    "resourceJWT": "<ES256-JWT(payload=resource)>",

    "contentData": [
        {
            "contentName": "bodytext",
            "contentType": "text/html",
            "keys": [
                { "accessGroup": "premium", "period": "251023T1400", "key": "<ckey-bodytext--wrapped--1400>" },
                { "accessGroup": "premium", "period": "251023T1415", "key": "<ckey-bodytext--wrapped--1415>" }
            ]
        },
        {
            "contentName": "premiumtext",
            "contentType": "text/html",
            "keys": [
                { "accessGroup": "premium", "period": "251023T1400", "key": "<ckey-premiumtext--wrapped--1400>" },
                { "accessGroup": "premium", "period": "251023T1415", "key": "<ckey-premiumtext--wrapped--1415>" }
            ]
        },
        {
            "contentName": "locked-data",
            "contentType": "application/json",
            "keys": [
                { "accessGroup": "locked-data", "period": "251023T1400", "key": "<ckey-locked-data--wrapped--1400>" },
                { "accessGroup": "locked-data", "period": "251023T1415", "key": "<ckey-locked-data--wrapped--1415>" }
            ]
        }
    ],


    "issuerData": [
        {
            "issuerName": "<issuerNameA>",
            "...": "Same structure as for issuerNameB, different sealed keys"
        },
        {
            "issuerName": "<issuerNameB>",
            "sealed": {
                "contentKeys": [
                    { "contentName": "bodytext", "key": "<contentKey-bodytext--sealed-to--issuer-pubkey>" },
                    { "contentName": "premiumtext", "key": "<contentKey-premiumtext--sealed-to--issuer-pubkey>" },
                    { "contentName": "locked-data", "key": "<contentKey-locked-data--sealed-to--issuer-pubkey>" }
                ],
                "periodKeys": [
                    { "accessGroup": "premium", "period": "251023T1400", "key": "<pkey-premium-1400--sealed-to--issuer-pubkey>" },
                    { "accessGroup": "premium", "period": "251023T1415", "key": "<pkey-premium-1415--sealed-to--issuer-pubkey>" },
                    { "accessGroup": "locked-data", "period": "251023T1400", "key": "<pkey-locked-data-1400--sealed-to--issuer-pubkey>" },
                    { "accessGroup": "locked-data", "period": "251023T1415", "key": "<pkey-locked-data-1415--sealed-to--issuer-pubkey>" }
                ],
                "chainKeys": [
                    { "accessGroup": "premium", "cutoff": "251023T2345", "key": "<chainKey-2345--sealed-to--issuer-pubkey>" },
                    { "accessGroup": "premium", "cutoff": "251024T1145", "key": "<chainKey-1145--sealed-to--issuer-pubkey>" },
                    { "accessGroup": "locked-data", "cutoff": "251023T2345", "key": "<chainKey-2345--sealed-to--issuer-pubkey>" },
                    { "accessGroup": "locked-data", "cutoff": "251024T1145", "key": "<chainKey-1145--sealed-to--issuer-pubkey>" }
                ]
            },
            "keyId": "2025-10"
        }
    ],

    "periodGeometry": { "periodMinutes": 15, "chainsPerDay": 2 }

}
```

### Fixed binary widths in the example

Binary strings use canonical unpadded base64url. These fixed-width fields
therefore have fixed encoded lengths:

| Field | Decoded width | Base64url length |
| --- | ---: | ---: |
| Content key encrypted with a period key, plus its authentication tag | 32 octets | 43 characters |
| Sealed key using current `ecdh-p256` | 97 octets | 130 characters |
| Sealed key using RSA-2048 | 256 octets | 342 characters |

Ordinary `ecdh-p256` envelopes use an implicit twelve-zero-octet nonce and a
fresh ephemeral keypair per seal. Their 97 octets contain the 65-octet public
point and the 32-octet ciphertext/tag; the former 109-octet layout is refused
without fallback. BIND remains reconstructed by the issuer.

Content encryption uses an implicit twelve-zero-octet nonce; the delivery
does not carry an item nonce. A period-key wrap entry carries no nonce either:
publisher and client derive it from the render ID and the entry's coordinate
([content protection Section 4.1](spec--content-protection.md#41-wrap-nonce)).

The RSA envelope always matches the issuer key's modulus width, so a larger
modulus produces a longer value. Item ciphertext is also variable: it contains
the encrypted content followed by a 16-octet authentication tag. A raw
`contentKey`, `periodKey`, or chain key is 16 octets, but the
publisher places its sealed envelope in `issuerData`, not its 22-character raw
base64url spelling.

### Client → issuer: unlock request

The client selects `issuerNameB` and relays its sealed keys with the resource
JWT and shared geometry.

```json
{
    "version": "1",
    "issuerName": "<issuerNameB>",
    "resourceJWT": "<ES256-JWT(payload=resource)>",
    "keyId": "2025-10",
    "sealed": {
        "contentKeys": [
            { "contentName": "bodytext", "key": "<contentKey-bodytext--sealed-to--issuer-pubkey>" },
            { "contentName": "premiumtext", "key": "<contentKey-premiumtext--sealed-to--issuer-pubkey>" },
            { "contentName": "locked-data", "key": "<contentKey-locked-data--sealed-to--issuer-pubkey>" }
        ],
        "periodKeys": [
            { "accessGroup": "premium", "period": "251023T1400", "key": "<pkey-premium-1400--sealed-to--issuer-pubkey>" },
            { "accessGroup": "premium", "period": "251023T1415", "key": "<pkey-premium-1415--sealed-to--issuer-pubkey>" },
            { "accessGroup": "locked-data", "period": "251023T1400", "key": "<pkey-locked-data-1400--sealed-to--issuer-pubkey>" },
            { "accessGroup": "locked-data", "period": "251023T1415", "key": "<pkey-locked-data-1415--sealed-to--issuer-pubkey>" }
        ],
        "chainKeys": [
            { "accessGroup": "premium", "cutoff": "251023T2345", "key": "<chainKey-2345--sealed-to--issuer-pubkey>" },
            { "accessGroup": "premium", "cutoff": "251024T1145", "key": "<chainKey-1145--sealed-to--issuer-pubkey>" },
            { "accessGroup": "locked-data", "cutoff": "251023T2345", "key": "<chainKey-2345--sealed-to--issuer-pubkey>" },
            { "accessGroup": "locked-data", "cutoff": "251024T1145", "key": "<chainKey-1145--sealed-to--issuer-pubkey>" }
        ]
    },
    "periodGeometry": { "periodMinutes": 15, "chainsPerDay": 2 }
}
```

### Issuer → client: unlock response

This direct response illustrates all three ordinary key kinds. The issuer
grants `bodytext` and `premium` access through 18:00; it returns no
`locked-data` keys. Returned keys are unsealed.

```json
{
    "keys": {
        "contentKeys": [
            { "contentName": "bodytext", "key": "<contentKey-bodytext>" }
        ],
        "periodKeys": [
            { "accessGroup": "premium", "period": "251023T1400", "key": "<pkey-premium-1400>" }
        ],
        "chainKeys": [
            { "accessGroup": "premium", "cutoff": "251023T1800", "key": "<chainKey-premium-1800>" }
        ]
    }
}
```

## Content groups — HTML delivery (Proposal)

The optional [content groups profile](spec-profile--content-groups.md) supplies
its own period keys and chain keys under `contentGroupKeys`. Ordinary
access-group keys remain under `keys`. Here the client requests reusable
`politics` access for `bodytext` and `headline`, and one content key for
`shoppingAd` through its `shopping` connector.

This separate example uses hourly periods, two windows a day, render period
15:00 UTC and one supplied window beginning at 12:00 UTC on 14 October 2026.
The issuer grants a `bodytext` chain through 18:00, a `headline` period key at
15:00, and the `shoppingAd` content key. The response illustrates all three
output kinds; the issuer chooses them under its authorization policy.

These objects follow the profile's production vector. JWT and sealed seeds
are shortened consistently for readability, and ordinary key records are
abbreviated below. The displayed connector and returned-key values retain
the vector's bytes. They are shape examples, not runnable vectors.

### Publisher → client: dca-data (metadata only)

Encrypted content is delivered separately in `dca-sealed-content`, using the
same HTML carrier shown above.

Ordinary key records are omitted here; their formats are shown in the preceding
examples. The placeholders below abbreviate the example, not the wire format.

```html
<script type="application/json" class="dca-data">
```
```json
{
    "version": "1",
    "resourceJWT": "<publisher-signed resource JWT>",

    "contentData": [
        {
            "contentName": "bodytext",
            "contentType": "text/plain",
            "connectors": [
                { "group": "politics", "connector": "cJzy9BAORNe7WOicm5bW9w" },
                { "group": "sports", "connector": "Okl5vn3NeLvXrOKNPvavtg" }
            ]
        },
        {
            "contentName": "headline",
            "contentType": "text/plain",
            "connectors": [
                { "group": "politics", "connector": "OAYiZWTBOh4vZlYIeZfCaA" }
            ]
        },
        {
            "contentName": "shoppingAd",
            "contentType": "text/plain",
            "connectors": [
                { "group": "shopping", "connector": "MOKIZiqdUlGNzqTXNMXhaA" }
            ]
        }
    ],

    "issuerData": [
        {
            "issuerName": "issuerA",
            "keyId": "a1",
            "sealed": {
                "contentKeys": ["<omitted; same record format as above>"],
                "periodKeys": ["<omitted; same record format as above>"],
                "chainKeys": ["<omitted; same record format as above>"],
                "contentWindowSeeds": [
                    { "contentName": "bodytext", "windowStart": "261014T1200", "key": "<bodytext-window-seed--sealed-to--issuer-pubkey>" },
                    { "contentName": "headline", "windowStart": "261014T1200", "key": "<headline-window-seed--sealed-to--issuer-pubkey>" },
                    { "contentName": "shoppingAd", "windowStart": "261014T1200", "key": "<shoppingAd-window-seed--sealed-to--issuer-pubkey>" }
                ]
            }
        }
    ],

    "periodGeometry": { "periodMinutes": 60, "chainsPerDay": 2 },
    "renderPeriod": "261014T1500"
}
```

### Client → issuer: unlock request

The client relays the sealed seeds and names the access it needs:

- `requestedContentGroups` asks for reusable group access for each named
  content item. Here it asks for `politics` access to `bodytext` and `headline`.
- `requestedContentKeys` asks for an individual item's content key through
  one of its connectors. Here it supplies the `shopping` connector for
  `shoppingAd`, rather than asking for reusable shopping-group access.

These are requests, not grants. The issuer applies its authorization policy
and chooses the permitted key outputs shown in the response below. Both fields
predate the named-record reorganization; their collections now use arrays
instead of maps keyed by content name.

```json
{
    "version": "1",
    "issuerName": "issuerA",
    "resourceJWT": "<publisher-signed resource JWT>",
    "keyId": "a1",
    "sealed": {
        "contentKeys": ["<omitted; same record format as above>"],
        "contentWindowSeeds": [
            { "contentName": "bodytext", "windowStart": "261014T1200", "key": "<bodytext-window-seed--sealed-to--issuer-pubkey>" },
            { "contentName": "headline", "windowStart": "261014T1200", "key": "<headline-window-seed--sealed-to--issuer-pubkey>" },
            { "contentName": "shoppingAd", "windowStart": "261014T1200", "key": "<shoppingAd-window-seed--sealed-to--issuer-pubkey>" }
        ]
    },
    "renderPeriod": "261014T1500",
    "periodGeometry": { "chainsPerDay": 2, "periodMinutes": 60 },
    "requestedContentGroups": [
        { "contentName": "bodytext", "groups": ["politics"] },
        { "contentName": "headline", "groups": ["politics"] }
    ],
    "requestedContentKeys": [
        { "contentName": "shoppingAd", "group": "shopping", "connector": "MOKIZiqdUlGNzqTXNMXhaA" }
    ]
}
```

### Issuer → client: unlock response

```json
{
    "keys": { "contentKeys": ["<omitted; same record format as above>"] },
    "contentGroupKeys": {
        "chainKeys": [
            { "contentName": "bodytext", "group": "politics", "cutoff": "261014T1800", "key": "y-W5pEt7JcGJXpTV_JNbug" }
        ],
        "periodKeys": [
            { "contentName": "headline", "group": "politics", "period": "261014T1500", "key": "f5_xFO8-no-F7IpVyrkI1g" }
        ],
        "contentKeys": [{ "contentName": "shoppingAd", "key": "wMHCw8TFxsfIycrLzM3Ozw" }]
    }
}
```

Each reusable-key record names its **content name, group and cutoff or
period**. A content-key record needs only the **content name**. The chain cutoff
and period labels both fall within the supplied 12:00 window; the client
derives their positions from the geometry captured in its request. It opens
`bodytext` and `headline` using their connectors in `contentData`; only the
content-key alternative relays a connector to the issuer. No seed is returned.

## Notes

### Access groups
The publisher and issuer agree on access groups such as `premium` and
`locked-data`. The publisher must assign items to those groups and seal their
content keys accordingly before delivery. The issuer then decides which readers
receive the supplied group keys; it cannot change which items those keys open.
For narrower access, it can return an individual item's content key instead.

[Content groups](spec-profile--content-groups.md) reduce the wire cost of
supplying many groups, making finer-grained grouping practical and leaving
more combinations to issuer policy.

### Chain keys
`periodGeometry` is the shared period-authoring context; its `chainsPerDay`
member and `chainKeys` select the chain-key extension as
defined in [Extension carrier and client
relay](spec-profile--chain-keys.md#12-extension-carrier-and-client-relay).
They are not part of the content-key-only baseline. `periodGeometry` describes
both the period grid (`periodMinutes`) and its grouping into independently
rooted chain windows (`chainsPerDay`). The period keys derived from a chain
use that same grid; this is not a separate geometry for unrelated period keys.
A period-key-only issuer or client receives usable keys at named coordinates
and needs no chain geometry to open them or their matching content-key wraps.
The name identifies the construction context that needs these two parameters,
not a different kind of period key.

The publisher or its key service needs the complete construction pair even
when it emits only the derived period keys. Both parameters enter Leaf as
well as Root and Step, so changing the number of independently rooted windows
can change period-key bytes at the same label. That publisher configuration
need does not impose chain processing on period-key-only recipients. Period-only
authoring omits wire `periodGeometry`; its publisher configures `periodMinutes`
locally. The selected chain delivery above carries both geometry members.

`periodGeometry` carries the shared geometry: the publisher gives both
`premium` and `locked-data` two independent UTC half-day chains with
15-minute periods, whose terminal labels are `251023T2345` and
`251024T1145`. Each ordinary item wrap still names its own period, including
a deliberately authored next-period alternative.

Geometry validation is defined by
[chain-keys Section 12](spec-profile--chain-keys.md#12-extension-carrier-and-client-relay).
`chainKeys` stays inside `sealed`; the relaying client
copies that known collection with its sibling `periodGeometry` context. The publisher
keeps the `periodKeys` sibling visible so a page reader can inspect
coexisting supply. Each shown chain value is the 16-octet chain key at the
labeled position, sealed under the extended `dca-bind-key-envelope|pc` grammar; "root" is
only its recipient-relative role. Labels of chain-bearing families are always
eleven characters.
