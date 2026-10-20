# Delegated Content Access (DCA) - Data Format

Status: Informative Draft

## Scope

This document first follows one item through the baseline JSON delivery,
unlock request, direct HTTPS response and plaintext opening. It then shows an
optional HTML delivery with period and chain-key alternatives. The authoritative
contract is
[spec--data-format.md](spec--data-format.md), composed with the focused
specifications indexed by [spec---overview.md](spec---overview.md).

## Minimal baseline exchange: one item

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

The publisher delivers one UTF-8 JSON document. Here `contentData.bodytext`
names the item, while `sealedContent.bodytext` holds its ciphertext and tag.
The item has no period-key wrap, transform, chain geometry or HTML carrier.

```json
{
  "version": "1",
  "resourceJWT": "<publisher-signed-compact-ES256-JWS>",
  "contentData": {
    "bodytext": {
      "contentType": "text/plain"
    }
  },
  "issuerData": {
    "news-issuer": {
      "keyId": "opening-2026",
      "sealed": {
        "contentKeys": {
          "bodytext": "<content-key-envelope-for-news-issuer: base64url>"
        }
      }
    }
  },
  "sealedContent": {
    "bodytext": "<AES-GCM-ciphertext-and-16-octet-tag: base64url>"
  }
}
```

The decoded payload of that signed `resourceJWT` has this shape. Its protected
header contains `alg: "ES256"`, `typ: "JWT"` and a `kid` that resolves to the
publisher's active signing-key registration. The issuer verifies the compact
JWS before using these claims; merely decoding it is insufficient.

```json
{
  "renderId": "<fresh-16-octet-render-id: base64url>",
  "origin": "https://publisher.example",
  "issuedAt": "2026-10-11T00:00:00Z",
  "resourceId": "article-123",
  "data": {}
}
```

With no cached content key, the client copies the selected issuer's fields
into the following body and sends it as one `POST` to
`https://issuer.example/unlock` with `Content-Type: application/json` over
authenticated HTTPS. This example assumes a non-browser caller. A browser
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
    "contentKeys": {
      "bodytext": "<content-key-envelope-for-news-issuer: base64url>"
    }
  }
}
```

After verifying the publisher assertion, authenticating the caller and granting
`bodytext` under its policy, the issuer opens the envelope at that authorized
render and item coordinate. Its direct response is HTTP `200`,
`Content-Type: application/json`, `Cache-Control: no-store`, with this body:

```json
{
  "keys": {
    "contentKeys": {
      "bodytext": "<same-16-octet-content-key: base64url>"
    }
  }
}
```

The client admits this as the response to that exact request and confirms that
`bodytext` was presented. It decodes the returned key, then opens
`sealedContent.bodytext` with twelve zero nonce octets. Its AES-GCM additional
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

## Sealed content

Ciphertext can be many kilobytes. It stays separate from `dca-data` so the
client reads the small metadata first, and so ciphertext delivery can be
deferred. In HTML the publisher puts it in an inert JSON script keyed by
content name.

<!-- Keep the HTML opening tag and JSON body in separate code blocks for syntax
highlighting. The closing script tag is intentionally omitted. -->

```html
<script type="application/json" class="dca-sealed-content">
```
```json
{
    "bodytext": "k7Hs9dF2mNqR4xPw...",
    "premiumtext": "Ym3pTvKsL8nWjEcQ...",
    "locked-data": "xR5fAhNt0gPkBwU7..."
}
```

In the baseline JSON delivery the same map is the `sealedContent` member
([object delivery](spec--data-format.md#6-object-delivery)); under the HTML
carrier the client reads it from the `dca-sealed-content` element
([markup delivery](spec--data-format.md#3-markup-delivery)).

## dca-data (JSON)

Below is an illustrative `dca-data` script. A delivery using only ordinary
period keys omits `periodGeometry`, as does a content-key-only baseline delivery.
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

    "contentData": {
        "bodytext": {
            "contentType": "text/html",
            "keys": {
                "premium": [
                    { "t": "251023T1400", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-bodytext--sealed-with--periodKey-premium-1400>" },
                    { "t": "251023T1415", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-bodytext--sealed-with--periodKey-premium-1415>" }
                ]
            }
        },
        "premiumtext": {
            "contentType": "text/html",
            "keys": {
                "premium": [
                    { "t": "251023T1400", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-premiumtext--sealed-with--periodKey-premium-1400>" },
                    { "t": "251023T1415", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-premiumtext--sealed-with--periodKey-premium-1415>" }
                ]
            }
        },
        "locked-data": {
            "contentType": "application/json",
            "keys": {
                "locked-data": [
                    { "t": "251023T1400", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-locked-data--sealed-with--periodKey-locked-data-1400>" },
                    { "t": "251023T1415", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-locked-data--sealed-with--periodKey-locked-data-1415>" }
                ]
            }
        }
    },


    "issuerData": {
        "<issuerNameA>": {
            "...": "Same structure as below, different sealed keys"
        },
        "<issuerNameB>": {
            "sealed": {
                "contentKeys": {
                    "bodytext": "<contentKey-bodytext--sealed-with--issuer-pubkey>",
                    "premiumtext": "<contentKey-premiumtext--sealed-with--issuer-pubkey>",
                    "locked-data": "<contentKey-locked-data--sealed-with--issuer-pubkey>"
                },
                "periodKeys": {
                    "premium": {
                        "251023T1400": "<periodKey-premium-1400--sealed-with--issuer-pubkey>",
                        "251023T1415": "<periodKey-premium-1415--sealed-with--issuer-pubkey>"
                    },
                    "locked-data": {
                        "251023T1400": "<periodKey-locked-data-1400--sealed-with--issuer-pubkey>",
                        "251023T1415": "<periodKey-locked-data-1415--sealed-with--issuer-pubkey>"
                    }
                },
                "chainKeys": {
                    "premium": {
                        "251023T2345": "<chainKey-at-251023T2345--sealed-with--issuer-pubkey>",
                        "251024T1145": "<chainKey-at-251024T1145--sealed-with--issuer-pubkey>"
                    },
                    "locked-data": {
                        "251023T2345": "<chainKey-at-251023T2345--sealed-with--issuer-pubkey>",
                        "251024T1145": "<chainKey-at-251024T1145--sealed-with--issuer-pubkey>"
                    }
                }
            },
            "keyId": "2025-10"
        }
    },

    "periodGeometry": { "periodMinutes": 15, "chainsPerDay": 2 }

}
```

### Fixed binary widths in the example

Binary strings use canonical unpadded base64url. These fixed-width fields
therefore have fixed encoded lengths:

| Field | Decoded width | Base64url length |
| --- | ---: | ---: |
| Nonce for encrypting a content key with a period key | 12 octets | 16 characters |
| Content key encrypted with a period key, plus its authentication tag | 32 octets | 43 characters |
| Sealed key using current `ecdh-p256` | 109 octets | 146 characters |
| Sealed key using RSA-2048 | 256 octets | 342 characters |

Content encryption uses an implicit twelve-zero-octet nonce; the delivery
does not carry an item nonce.

The RSA envelope always matches the issuer key's modulus width, so a larger
modulus produces a longer value. Item ciphertext is also variable: it contains
the encrypted content followed by a 16-octet authentication tag. A raw
`contentKey`, `periodKey`, or chain key is 16 octets, but the
publisher places its sealed envelope in `issuerData`, not its 22-character raw
base64url spelling.

### Decoded `resourceJWT` object
Example of the decoded `resourceJWT` object:
```json
{
    "renderId": "<renderId>",
    "origin": "https://www.news-site.example",
    "issuedAt": "2025-10-23T14:00:00Z",
    "resourceId": "123456",
    "data": {
        "date.published": "2025-10-20T10:30:00Z",
        "section": "politics",
        "tags": [
            "breaking",
            "elections",
            "analysis"
        ],
        "fields.extractedCustomField1": "customValue"
    }
}
```

## Notes

### Access groups
`premium` and `locked-data` are publisher-scoped logical names from one
access-group vocabulary shared by `<issuerNameA>` and `<issuerNameB>`. The
publisher may seal either group for both issuers, one issuer, or neither; each
issuer is provisioned zero or more groups. Reusing a name never gives it an
issuer-specific meaning: the matching period key opens the same content-side
wraps regardless of which issuer delivered it.


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
locally. The selected chain delivery below carries both geometry members.

`periodGeometry` carries the shared geometry: the publisher gives both
`premium` and `locked-data` two independent UTC half-day chains with
15-minute periods, whose terminal labels are `251023T2345` and
`251024T1145`. Each ordinary item wrap still names its own period, including
a deliberately authored next-period alternative.

Geometry validation is defined by
[chain-keys Section 12](spec-profile--chain-keys.md#12-extension-carrier-and-client-relay).
`chainKeys` stays inside `sealed`; the relaying client
copies that known map with its sibling `periodGeometry` context. The publisher
keeps the `periodKeys` sibling visible so a page reader can inspect
coexisting supply. Each shown chain value is the 16-octet chain key at the
labeled position, sealed under the extended `dca-bind-key-envelope|pc` grammar; "root" is
only its recipient-relative role. Labels of chain-bearing families are always
eleven characters.
