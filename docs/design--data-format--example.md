# Delegated Content Access (DCA) - Data Format

Status: Informative Draft

## Scope

This document shows an example of the wire format on an HTML page: the markup
publishers produce and clients consume. The authoritative contract is
[spec--data-format.md](spec--data-format.md), composed with the focused
specifications indexed by [spec---overview.md](spec---overview.md).

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

## dca-data (JSON)

Below is an illustrative `dca-data` script. The `periodChain` object is optional for
issuers and clients.

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
            "nonce": "<base64url(randomBytes(12))>",
            "aad": "<aad>",
            "keys": {
                "premium": [
                    { "t": "251023T1400", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-bodytext--sealed-with--periodKey-premium-1400>" },
                    { "t": "251023T1415", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-bodytext--sealed-with--periodKey-premium-1415>" }
                ]
            }
        },
        "premiumtext": {
            "contentType": "text/html",
            "nonce": "<base64url(randomBytes(12))>",
            "aad": "<aad>",
            "keys": {
                "premium": [
                    { "t": "251023T1400", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-premiumtext--sealed-with--periodKey-premium-1400>" },
                    { "t": "251023T1415", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-premiumtext--sealed-with--periodKey-premium-1415>" }
                ]
            }
        },
        "locked-data": {
            "contentType": "application/json",
            "nonce": "<base64url(randomBytes(12))>",
            "aad": "<aad>",
            "keys": {
                "locked-data": [
                    { "t": "251023T1400", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-locked-data--sealed-with--periodKey-locked-data-1400>" },
                    { "t": "251023T1405", "nonce": "<base64url(randomBytes(12))>", "key": "<contentKey-locked-data--sealed-with--periodKey-locked-data-1405>" }
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
                        "251023T1405": "<periodKey-locked-data-1405--sealed-with--issuer-pubkey>"
                    }
                },
                "periodChainKeys": {
                    "premium": {
                        "251023T2345": "<period-chain-state-at-251023T2345--sealed-with--issuer-pubkey>",
                        "251024T1145": "<period-chain-state-at-251024T1145--sealed-with--issuer-pubkey>"
                    },
                    "locked-data": {
                        "251023T1755": "<period-chain-state-at-251023T1755--sealed-with--issuer-pubkey>",
                        "251023T2355": "<period-chain-state-at-251023T2355--sealed-with--issuer-pubkey>"
                    }
                }
            },
            "unlockUrl": "https://api.example.com/unlock",
            "keyId": "2025-10"
        }
    },

    "periodChain": {
        "chainsPerDay": 2,
        "periodMinutes": 15,
        "accessGroups": {
            "locked-data": {
                "chainsPerDay": 4,
                "periodMinutes": 5
            }
        }
    }

}
```

### Fixed binary widths in the example

Binary strings use canonical unpadded base64url. These fixed-width fields
therefore have fixed encoded lengths:

| Field | Decoded width | Base64url length |
| --- | ---: | ---: |
| Nonce for content encryption | 12 octets | 16 characters |
| Nonce for encrypting a content key with a period key | 12 octets | 16 characters |
| Content key encrypted with a period key, plus its authentication tag | 32 octets | 43 characters |
| Sealed key using current `ecdh-p256` | 109 octets | 146 characters |
| Sealed key using RSA-2048 | 256 octets | 342 characters |

The RSA envelope always matches the issuer key's modulus width, so a larger
modulus produces a longer value. Item ciphertext is also variable: it contains
the encrypted content followed by a 16-octet authentication tag. A raw
`contentKey`, exact `periodKey`, or period-chain state is 16 octets, but the
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


### Period chain keys
`periodChain` and `periodChainKeys` are the period-chain extension's members as
frozen in [Extension carrier and client
relay](spec--period-key-chains.md#12-extension-carrier-and-client-relay).
They are not part of the accepted base format. `periodChain` carries
the document-wide geometry: the publisher gives `premium` two independent UTC
half-day chains with 15-minute periods, whose terminal labels are
`251023T2345` and `251024T1145`. The publisher overrides `locked-data` to four
six-hour chains per day with five-minute periods, whose shown current and next
terminals are `251023T1755` and `251023T2355`.

If the document-wide `chainsPerDay` and `periodMinutes` members are absent,
`accessGroups` must contain a complete pair for every access group appearing in
any issuer's `periodChainKeys`. A family entry replaces both document values;
partial inheritance is invalid. All issuers for one access group use its same
resolved geometry. `periodChainKeys` stays inside `sealed`; the relaying client
copies that known map with its sibling `periodChain` context. The publisher
keeps the exact `periodKeys` sibling visible so a page reader can inspect
coexisting supply. Each shown chain value is the 16-octet chain state at the
labeled position, sealed under the extended `dca-bind-v1|pc` grammar; "root" is
only its recipient-relative role. Labels of chain-bearing families are always
eleven characters.


## JSON API variant

For API responses (headless CMS, mobile apps, SPAs), the HTML split is
unnecessary. All data fits in a single JSON object. Sealed content moves into a
`sealedContent` field keyed by `contentName`; its values are base64url
ciphertext. Place it at the end so metadata comes first and large blobs last:

```json
{
    "version": "1",
    "resource": "{ ... }",
    "resourceJWT": "...",
    "contentData": "{ ... }",
    "issuerData": "{ ... }",
    "sealedContent": {
        "bodytext": "k7Hs9dF2mNqR4xPw...",
        "premiumtext": "Ym3pTvKsL8nWjEcQ...",
        "locked-data": "xR5fAhNt0gPkBwU7..."
    }
}
```

Note: `"{ ... }"` values are placeholders for the full objects shown in the
dca-data example above.

Only the extraction changes: for markup the client reads two elements by class
name; for JSON API the object is parsed directly and its `sealedContent` member
is the same map. The two carriers are specified by
[markup delivery](spec--data-format.md#3-markup-delivery) and
[object delivery](spec--data-format.md#6-object-delivery).
