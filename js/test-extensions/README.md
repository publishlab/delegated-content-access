# Selected-extension composition tests

This directory holds shared interactions between optional extensions with no
clear primary feature owner. An extension-owned test may import sibling
implementations and remain with its primary feature.

## Where a test goes

| What the test proves                                      | Put it in                        |
| --------------------------------------------------------- | -------------------------------- |
| Base source and barrels load with every extension removed | `test-base/`                     |
| A portable implementation contract                        | `test-contract/`                 |
| One optional extension                                    | `extensions/<name>/test/`        |
| Shared interaction with no primary extension owner        | `test-extensions/`               |
| One complete scenario for a named protocol profile        | `test-profiles/`                 |
| A JavaScript reference implementation behavior            | `test/`                          |
| An extracted reference target                             | `test-reference/<target>/`       |
| A deliberately different or failing implementation        | `experiments/<experiment>/test/` |

Place each test by ownership. If removing one extension should remove the
test, it belongs to that extension. If the test remains meaningful only while
several named extensions are selected and has no primary owner, it belongs
here. Owned tests, helpers and bench scenarios may import siblings directly.
Required sibling sources must be installed for those lanes; missing support is
an explicit prerequisite failure. Runtime dependencies remain role-constrained,
cycle-free and separate from development-only imports.

For example, `client-bound-chain-keys.test.js` belongs here because it proves
the client-bound transport and chain-keys extensions work together. An ECDH
seal/open test belongs under `extensions/client-bound-transport/test/`.

`support/` holds composition code a test here needs and no shipped role owns,
for instance an issuer that selects two extensions at once. The composition
run collects only the `*.test.js` files here, and nothing under `support/`
ships.

`publisher-composition.test.js` combines chain supply and content-key seal
omission against the pre-composition record in
`fixtures/publisher-composition--chain-omission.json`. The related core and
single-extension suites replay seven further records captured from unchanged
publisher source. Tests compare JWT signing-input bytes and verify
the signature, and compare issuer-envelope/ciphertext and remaining delivery
bytes with the records. Randomized ECDSA signature bytes are not required to
match. No fixture is regenerated during this replay. The current fixed-nonce
transcript also omits item `nonce` members and changes ciphertext bytes and
tags and shifts later seeded draws. The derived period-wrap nonce drops each
wrap entry's `nonce` member and shifts the seeded envelope draws that followed
the removed wrap draws. Replay evidence follows the current generated records. From the repository root, regenerate all eight through
`node js/test-lib/fixtures/record-publisher-composition.js`, or append
`--check` to verify the recorded bytes without writing.

The `derived-content-aad--*.test.js` files hold the adoption evidence for that
AAD where it needs sibling extensions. `--exchanges` opens JSON and HTML
deliveries through item keys, period keys and the chain-keys extension over
direct and client-bound transport. Its two content-groups cells run over direct
transport through `createPublisher`, `createIssuerCore` and
`createDeliveryClient` composed from `contentGroupsProfile`; its header lists
the combinations it does not cover.
`--resource-id-pipe` publishes and opens a resourceId holding `|` through the
ordinary and content-groups paths and matches it to a recipient grant's
`sub`. `--wire-size` measures one delivery with and without the carried member.
The independent transcript comes from
`../test-reference/support/contentAadOctets.js`, which shares no code with
`core-shared--client-publisher/contentAad.js`.

`../extensions/content-groups/test/production-roles.test.js` and
`../extensions/content-groups/test/ordinary-routing.test.js` hold the
content-groups access and binding checks that need the stock Root/Step/Leaf
derivation from chain-keys. They run `createPublisher`, `createIssuerCore` and
`createDeliveryClient` composed from `contentGroupsProfile` over direct
transport. The first covers named connector maps, seed-envelope binding,
request and answer bounds, chain reach inside one window, rival retained
secrets and the transcript octets; a test that replaced an assertion of the
retired root `contentGroups` array says which. The second puts ordinary item
routes beside content-group routes on one page. Its retired-opening-key case runs over direct transport and
over client-bound ECDH-P256: the answer carries the base `key_retired` entry beside the scoped
`contentGroupKeys.errors` record, the error leaves unwrapped, and the client reports both and files no key.
The owned `../extensions/content-groups/test/_lib/world.js`
builds the roles both use; shared composition tests reuse that fixture. The extension README retains explicitly historical measurements from the retired generator.

`content-groups-composition.test.js` selects the content-groups extension with
the chain-keys derivation and chain-key cache, and with both client-bound
methods. A real `createPublisher` page, serialized as JSON or as the HTML
carrier, reaches the composed delivery client. The client asks a real
`createIssuerCore` endpoint and opens plaintext through plain `open()`. The
file covers item, period and chain grants, candidate item recovery beside an ordinary item,
reuse across articles of one content name and window, and denials checked by
real decryption attempts. It also covers request and response substitutions,
shared storage with reload, eviction and a bogus rival chain, and reset during
a delayed answer, storage write, unwrap or derivation. Under ECDH-P256 and
RSA-OAEP it opens chain-, period- and item-key items beside the ordinary item,
checks that every content-group key leaves the issuer wrapped, and refuses
swapped kinds, 32-byte keys, and a direct answer or an unwrapped content-group
section as a downgrade. The independent vectors live in
[`../test-profiles/dca-profile-content-groups.test.js`](../test-profiles/dca-profile-content-groups.test.js).

Three later blocks in `content-groups-composition.test.js` put content groups beside another mechanism:

- "compression beside content groups": `CompressingSealer` writes the same connectors and seeds as
  `Sealer` for a grouped item, and seals an item that only its content groups route.
- "compact ECDH beside content groups": seeds for an ordinary issuer publish beside a compact-selected block that
  carries none, and seeds for the compact issuer refuse `bad_config`.
- "one base issuer engine composing chain keys with content groups": the host builds one `createIssuerCore`
  with `requireChainRepresentation(chainKeyCapabilitySource(...))` as `periodCapabilitySource`, `chain-keys` in
  `selectedExtensions` with its encoder, and the content-groups contribution. Under period-key and chain-key
  representation a full grant opens the chain-family item, the connector item and the item-key item, and each
  denial closes only its own route. One case pins each host duty. An unlock without a captured instant answers
  500, with or without a chain grant. When the request relays the chain family as period keys and the policy
  grants it, the answer is 500 without `requireChainRepresentation` and 200 with it.
  The block also covers a content-group-only request, Origin checked before policy and opening-key work,
  client-bound wrapping, and swapped seed and chain blobs. It never exercises the stock `chainKeyIssuerEngine`
  wrapper.

`composition-boundaries.test.js` opens one gzip HTML delivery through ordinary
item keys, stock chain keys and content-group chains in one composed browser
client. The direct case checks authored content type and plaintext, independent
denials, retained opening of a later render without a new request, and reset
followed by a denied successor. A client-bound ECDH variant checks the opening
boundary and absence of raw keys in delivery. The client nests the stock chain
builder through the content-group builder's `innerBuilder`; the issuer uses the
hand-composed base-engine recipe in the content-groups README. The DOM is a
Node string harness, not a deployed browser. The client-bound variant calls the
core and KeyDelivery directly and does not prove browser Origin or signing-key
admission. This is optional composition evidence, not a default deployment or a
complete conformance claim.

`compact-ecdh-chain-keys.test.js` selects the compact-ECDH extension with the
chain-keys supply. A Sealer composed with the compact publisher contribution
seals chain keys for a compact-selected issuer; each `sealed.chainKeys` value
is a 65-octet compact envelope that `openCompactEcdh` opens to a 16-octet key
under the chain-key BIND octets as AAD, and the ordinary ECDH opener refuses
it. The recorded DCA vectors and the Go, Python and PHP checks of them live
with the [extension](../extensions/compact-ecdh/README.md) and cover item and
period bindings, not the chain-key binding.

`recipient-grant-compact-ecdh.test.js` selects the recipient-grant issuer with
the compact-ECDH issuer contribution. One key entry permits
`["ecdh-p256", "compact-ecdh"]`; an ordinary and a compact-selected render to
that key each answer 200 to a grant holder, and the client opens the granted
item and receives no key for an ungranted one. The extension's own tests check
that a contribution other than an envelope procedure is refused.

`npm run test:reference:compositions` runs this directory. `npm test` reaches these
files through its own glob over the package, but no named single-extension command
runs them.

This README owns the test-purpose description for the files directly under
this directory; they need no per-test README. When a new combination lands,
record here the selected protocol profiles or implementation extensions, the
boundary the tests exercise and any applicable recorded or independent
evidence. Passing this JavaScript composition lane remains implementation
evidence and does not by itself establish a protocol-conformance claim.

[`../test-profiles/README.md`](../test-profiles/README.md) indexes meaningful
profile combinations that live here. Keep the executable test here when it
requires sibling implementation extensions; do not copy it into the profile
directory merely to make that index self-contained.
