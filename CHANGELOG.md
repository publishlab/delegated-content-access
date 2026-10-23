# DCA compatibility changelog

Status: Informative Draft

This log records changes an early implementer must handle to keep content-key,
period-key and chain-key opening working. A content key is abbreviated ckey;
a period key is abbreviated pkey. Entries group compatibility changes rather
than list individual commits. The [specifications](docs/spec---overview.md) define the protocol.

## Start here

- **New implementation:** start with the [specification overview](docs/spec---overview.md#start-here)
  and its one-item baseline example. This changelog explains changes; it is not
  the implementation contract. The [roadmap](roadmap--draft-period.md) describes
  possible next work, not extra requirements for the current draft.
- **Existing implementation:** identify the exact publication or source revision
  you used and the optional profiles you selected. Start with the impact table
  below, then read the relevant entries. A JavaScript API change does not by
  itself require an independent implementation to adopt that API.

## v1.0.0-alpha.3 - 2026-10-23

Changes since [v1.0.0-alpha.2, publication commit 14cd688](https://github.com/publishlab/delegated-content-access/commit/14cd688db74086cd718139e8cbda1efd0f05f37b),
published on 20 October 2026.

### Publisher compression target policy

The optional `CompressingSealer` now checks complete ordered encoding sequences
on raw and prepared input. Its default target accepts unencoded content and one
gzip layer. A baseline-only target selects `[[]]` and uses `identity` for raw
input; additional prepared sequences require explicit configuration and matching
client decoders. The generic Sealer and wire format are unchanged.

Custom gzip encoders receive disposable input bytes, so output validation and
retries retain the originally captured content.

### Breaking: collections are arrays of named records

Every collection of content items, issuers, keys, connectors, sealed material,
request selections and reports is now a JSON array. Each record names its
identity and coordinates as fields instead of using dynamic object keys. Fixed
sections such as `keys`, `sealed`, `contentGroupKeys` and `periodGeometry` stay
objects, and ordinary `keys` stay separate from `contentGroupKeys`. The
[data-format example](docs/design--data-format--example.md#period-keys--chains--html-delivery)
shows a complete exchange.

- Delivery: `contentData` holds `{contentName, ...}` items, `issuerData` holds
  `{issuerName, ...}` blocks and `sealedContent` or `dca-sealed-content` holds
  `{contentName, content}`.
- Item wraps: `keys` holds `{accessGroup, period, key}`; the former `t` is now
  `period`. Content-group `connectors` hold `{group, connector}`.
- Sealed and returned keys: `contentKeys` hold `{contentName, key}`,
  `periodKeys` hold `{accessGroup, period, key}` and `chainKeys` hold
  `{accessGroup, cutoff, key}`. Content-group period and chain records use
  `contentName` and `group` instead of `accessGroup`; their content-key records
  use only `contentName` and `key`. Seeds are `{contentName, windowStart, key}`.
  A client-bound protected value sits unchanged under `key`.
- Reports and selections: `errors` holds `{coordinate, error, message?}`,
  `notDelivered` holds `{accessGroup, reason, message?}`, and
  `requestedPeriodKeys`, `requestedContentGroups`, `requestedContentKeys`,
  `requestedChainCutoffs` and `boundCandidates` become records.
- Required empty collections are `[]`, so `keys.contentKeys` and request
  `sealed.contentKeys` may be empty arrays. Optional collections keep their
  omission rules and are not sent empty.

Repeated records now have stated meanings. A repeated descriptor or status
record, such as an item, issuer block, sealed-content record, error or report,
resolves to the last whole record with no merging. Repeated key material and
connectors at one coordinate are candidate alternatives that count toward
existing limits. Repeated request selections take the union of groups or
periods and the lowest chain cutoff, and repeated item routes stay
alternatives. This is separate from duplicate JSON member names, whose rule is
unchanged. This representation change leaves labels, BIND, AAD, nonces and
derivations unchanged; array position enters none of them. The separate
cryptographic changes below still apply.

**Incompatibility:** there is no dual parser, toggle, version change or
profile identifier. A reader of the former object maps cannot read the new
arrays, and a new reader refuses the old maps. Republish retained deliveries
and update every publisher, issuer, client and relay together. Signed response
transcripts and whole-message vectors change shape; cryptographic inputs and
outputs at each coordinate do not.

**Who updates:** every role. Optional profiles stay optional; a baseline-only
peer still needs the new baseline representation.

Authority: [data format](docs/spec--data-format.md#23-collections-of-named-records),
[core protocol](docs/spec--core-protocol.md#7-baseline-issuer-core-result),
[period keys](docs/spec-profile--period-keys.md#56-family-reports-notdelivered),
[chain keys](docs/spec-profile--chain-keys.md#124-requested-article-periods) and the
[content groups proposal](docs/spec-profile--content-groups.md#unlock-request).

### Breaking: ordinary ECDH envelope omits its nonce

Ordinary `ecdh-p256` envelopes now contain a 65-octet uncompressed ephemeral
P-256 public point followed by 32 octets of encrypted key and GCM tag:
**97 decoded octets / 130 unpadded base64url characters**, formerly 109 / 146.
The AES-GCM nonce is twelve implicit zero octets. Each seal requires a fresh
ephemeral keypair, including seals at the same coordinate; changing BIND cannot
make agreement reuse safe. The raw 32-octet shared x-coordinate remains the
AES-256-GCM key, without a KDF, and the issuer reconstructs the same BIND.

**Incompatibility:** publishers and issuers must update together. The ordinary
opener requires exactly 97 octets and refuses the former carried-nonce layout;
there is no selector, old-format fallback or automatic retry. Republish retained
deliveries for the new opener, or serve them through a separately maintained
old implementation. Clients relay the sealed value as before.

RSA-OAEP, compact-ECDH HPKE and issuer-response nonces retain their separate
procedures; content-group seed envelopes follow in the next entry. This adoption
is an ordinary-envelope change, not adoption of the paused nonce-free response
experiment.

Authority: [sealed-key envelopes Section 4](docs/spec--sealed-key-envelopes.md#4-ecdh-p-256-envelope).

### Breaking: content-group seed envelope omits its nonce

Optional content-groups `ecdh-p256-content-name-seed` envelopes now contain the
65-octet uncompressed ephemeral P-256 public point followed by 48 octets of
encrypted seed and GCM tag: **113 decoded octets / 151 unpadded base64url
characters**, formerly 125 / 167. The AES-GCM nonce is twelve implicit zero
octets, as for the ordinary envelope above. Each seal requires a fresh
ephemeral keypair, including rival seeds at the same coordinate. The raw
32-octet x-coordinate key, seed AAD, seed derivation, chain and period keys,
connectors and wire members are unchanged.

**Incompatibility:** publishers and issuers that selected content groups must
update together. The issuer requires exactly 113 octets and refuses the former
125-octet layout; there is no selector, fallback or retry. Republish retained
deliveries, or open them through a separately maintained old implementation.
Clients relay seed envelopes unchanged and never open them. Content-group seed
envelopes require ordinary ECDH; composition with compact ECDH remains undefined
and must be refused.

**Who updates:** content-group publishers and issuers. Baseline-only
implementations gain no duty.

Authority: [content groups](docs/spec-profile--content-groups.md#seed-envelope-and-issuer-custody).

### Breaking: content-group response member is contentGroupKeys

The optional content-groups response member is now `contentGroupKeys`, replacing
`contentGroups`. Its `contentKeys`, `periodKeys`, `chainKeys` and `errors`
remain beneath it, separate from ordinary `keys`. Issuers, clients, relays and
response-signing consumers that selected this profile must update the response
name together; the old spelling is not an alias. Publisher item configuration
`contentGroups`, request selectors and cryptographic derivation inputs retain
their names and meaning. Baseline-only implementations have no new duty.

Authority: [content groups](docs/spec-profile--content-groups.md#reading-the-key-records).

### Issuer response limits: overflow refuses the whole exchange

For selected chain-key or content-group behavior, exceeding the specified
response-output bounds for mandatory output refuses the whole exchange with
`too_many_entries`, including otherwise successful sibling keys. Issuers first
clamp their optional future horizon to remaining capacity, keeping each
coordinate's complete candidate set. They do not trim mandatory candidates or
silently omit mandatory families to fit the answer. Chain-projected output counts distinct
period-key candidates after duplicate-key removal; content-group bounds count
the candidate and error records their specification defines. Clients may need
bounded requests; no automatic retry or one-response success is promised.

Authority: [chain-key bounds](docs/spec-profile--chain-keys.md#221-protocol-maxima)
and [content-group response admission](docs/spec-profile--content-groups.md#direct-response-and-retention).

### Reference behavior: candidate recovery and input validation

The JavaScript reference now reserves mandatory and ordinary fallback candidates
before allocating optional chain horizons. It retains complete rival sets at a
coordinate and stops optional output at the existing limits; mandatory overflow
still refuses the whole exchange. Across successive renders, publisher
preparation safely handles inherited names such as `constructor` and preserves
own JSON members such as `__proto__` as data.

Recipient-grant clients try older candidates when a newer key fails body
authentication. Accepted content-group response candidates remain pending
independently of retained-rival and window capacities. Same-window pending
rivals do not each count as a window. The content-group client supplies
`maxResponseMembers` for both cache member bounds and `maxWindowsPerGroup` for
`maxWindowsPerFamily`. A failed recovery guess leaves an eligible unavailable-key
retry available. These changes preserve
existing authorization and wire formats. Custom period sources receive the
actual ordinary `periodKeyCount` and immutable `selectedCapabilities`; optional
production may explicitly return `{kind: "omitted"}`. See the
[period-source contract](js/PORTING.md#chain-key-request-relay) for composition
and budget ownership.

Content-group admission refuses explicit null collections where arrays or error
records are required. Opaque recipient grants validate content-name syntax;
the signed form's 64-name and distinct-array restrictions do not apply to local
opaque-store encoding. The exported RSA public-offer helper now projects only
admitted public fields and rejects private JWK input; the default client already
prevented private material from reaching an offer. Seed-envelope key type, curve
and private derivation-usage faults now remain configuration errors, producing
HTTP 500 at the issuer boundary. Wrong valid-key authentication remains a
uniform HTTP 400 refusal.

Browser HTTP handling now preserves CORS headers on POST refusals, admits media
type parameters under the specified grammar, and rejects unsupported preflight
schemes. A circuit-breaker-skipped issuer no longer establishes eligibility for
conditional fallback.
These are reference corrections, not new baseline or optional-profile duties.

### Design note: response nonce removal remains deferred

Issuer responses retain their transmitted nonces. A future construction could
derive a separate encryption key for each entry and use a fixed nonce. Group,
window and cutoff alone are insufficient: different candidate keys may share
those coordinates. A small entry number, unique within one fresh response
agreement and bound alongside the key kind and full semantic coordinates,
could distinguish them. Carrying that number with its entry would preserve
reordering and independent opening. Its exact encoding, tests and net wire
savings remain future work; this note introduces no field or requirement.

### Breaking: period-key wrap nonce is derived

Period-key wrap entries no longer carry `nonce`. An ordinary entry is
`{accessGroup, period, key}`; a marked omission entry also carries `bind`. Publisher and client
each derive the 12-octet wrap nonce as the first 12 octets of SHA-256 over a
domain string, a zero octet, the 16 decoded render-ID octets, and the
length-prefixed octets of the item name, access group, `t` and the selected
wrap AAD. The ordinary wrap AAD stays empty. AES-128-GCM, the 16-octet period
key, the 16-octet content key and the 32-octet `key` value are unchanged.
[PORTING.md](js/PORTING.md#derived-wrap-nonce) gives a byte vector.

The derivation relies on a fresh random render ID per render and one content
key per render and item, both already required. The aggregate ceiling of
`2^32` wraps per period-key bytes across all producers stays, as does the
recommendation to choose a lower local ceiling.

**Incompatibility:** there is no toggle, negotiation or fallback. A reader
built for the random wrap nonce cannot open new data, because new entries
carry no nonce for it to use. A new reader ignores a carried `nonce` and
derives its own, so it fails to open old data sealed with a random wrap nonce.
Regenerate old deliveries, or keep a separately selected old reader for them;
the presence of a wrap-entry `nonce` never selects one.

**Who updates:** period-key publishers and clients. Under the content-key seal
omission prototype, its issuer also derives the nonce and its forwarded
`boundCandidates` lose `nonce`. This wrap change leaves other issuer processing,
BIND, envelope nonce procedures and issuer responses unchanged. Period-key
support stays optional; every implementation that selects it uses this procedure.

Authority: [content protection](docs/spec--content-protection.md#41-wrap-nonce),
[data format](docs/spec--data-format.md#41-contentdata) and
[period keys](docs/spec-profile--period-keys.md#62-wrapping-and-rollover).

### Browser integration: denial caching is opt-in

[Browser-origin Section 2.6](docs/spec-profile--browser-origin.md#26-avoiding-repeated-denied-unlocks)
changes retention of denial scheduling hints from SHOULD to optional MAY.
This changes request scheduling, not issuer authorization or wire compatibility.

`createBrowserClient` now omits denial scheduling by default. Opt in with
`denialCache: new DeniedUnlockCache()`; period-key and chain-key retention
remain independent of that choice.

## v1.0.0-alpha.2 — 2026-10-20

These changes are compared with the last public working draft,
[publication commit a10164b](https://github.com/publishlab/delegated-content-access/commit/a10164beb34d72b96a7c7fa02a837c1577d85cee),
published on 21 September 2026 at 15:07 UTC. A README-only commit on
26 September is not a draft publication. These notes cover key-opening
compatibility; they do not claim a complete audit of every changed API or profile.

### JavaScript source directory

The JavaScript package and reference implementation moved from `js/v1/` to
[`js/`](js/README.md). Update repository imports, copied-source paths and
commands to use `js/`, including `pnpm --dir js test`. The repository gate
remains `sh js/check`.

This removes a source-directory level. DCA protocol v1 identifiers and the
versioned fixture/vector directories keep their versions. Git branches and
release tags identify complete release trees; package versions are independent
of the supported protocol version.

### Upgrade impact at a glance

The outer wire version is still `"1"`. It does not negotiate compatibility
between draft revisions. If you implemented the September draft, a current
publisher, issuer or client is not a drop-in replacement for every old peer.
If you used an intervening revision, compare its selected formats as well.

| Your implementation uses       | What to review                                                                                                            | Roles to coordinate                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Baseline item-key opening      | Implicit content nonce and derived AAD, issuer-envelope binding, trusted endpoint configuration, JSON carrier support and response admission | Publisher, issuer and client; each entry names the affected pair or role |
| Period keys                    | Minute-bearing labels; chain-only wire geometry; isolated `notDelivered` failures                                         | Publisher, issuer and client                                             |
| Chain keys                     | Renamed fields, changed derivation transcript and explicit requested article periods                                      | Publisher construction, issuer and any chain-deriving client             |
| Client-bound responses         | Changed transport contexts and per-key-kind binding                                                                       | Issuer and client                                                        |
| New compact ECDH profile       | Optional selector relay, matching sealing/opening and issuer key permissions                                              | Selecting publisher, client relay and issuer                             |
| Content-groups candidate       | Named connectors, scoped seeds and revised role APIs                                                                      | Only implementations evaluating this Proposal                            |
| JavaScript browser integration | Decision clearing versus full reader reset; cleanup duties for injected retaining owners                                  | The application integrating the reference client                         |

For already published content, decide how it remains readable before switching
formats: regenerate deliveries under the current format, or retain a matching
old-format reading and issuer path. There is no automatic September-format
compatibility mode in the current reference. A cache flush, field rename or
fresh unlock cannot repair a cryptographic transcript mismatch. This is separate
from ordinary reacquisition of newly generated period keys, described below.

### Reference corrections and content-group request alternatives

The JavaScript composition API now types the decoder's required output-budget
argument consistently with the opener. Issuer section policies receive the same
opaque principal/context objects as the base policy; denied source-only requests
reach policy before opening-key lookup. Key retirement and exchange-wide failure
remain enforced. Custom content-group chain caches must honor the shared finite
candidate-work counter described in [PORTING.md](js/PORTING.md).

Issuer response-section sources retain their original method receiver while
configuration metadata stays snapshotted. A content-key fallback's scope and
factory initialize once, only when an authorized item needs that fallback;
unused fallback setup no longer affects successful ordinary seals. Hosts needing
unconditional request side effects must perform them in their own lifecycle.
These are reference API changes; no wire or cryptographic transcript changes.

For the optional content-groups Proposal, a default request now offers one item
connector alongside its reusable group requests when the issuer holds the render
window's seed. The issuer still chooses what to grant. Explicit request-kind maps
preserve group-only or item-only selection. This adds request bytes per offered
item; publisher sizing uses the same projection. Malformed connector maps refuse
only their item's connector routes. Refused response members supply no keys or
routing permission, while independently admitted ordinary keys remain usable;
common response representation, association and transport checks still apply.
These changes add no baseline capability requirement or new wire member.

### Breaking: content nonce and AAD are implicit

Item records no longer carry `aad` or `nonce`. Publisher and client each build
content AAD as `LP(renderId) || LP(contentName)`, where `LP` prefixes UTF-8
octets with their four-octet big-endian length. There is no additional label,
JWT spelling, content type or encoding in this transcript. The content tag
binds the render ID and item name; it does not authenticate representation
metadata or other JWT claims.

Content encryption uses AES-128-GCM with an implicit twelve-zero-octet nonce.
Every encryption requires a fresh independent random 16-octet content key,
used for exactly one encryption. Producing another ciphertext requires a new
key, even if only the representation or AAD changes.

**Who updates:** publishers use this nonce and AAD procedure and omit both
item members; clients reconstruct the same inputs and ignore either carried
member regardless of its type. These are mandatory baseline changes. Old
ciphertext needs regeneration or a separately selected matching old reader;
there is no fallback or retry selected by carried fields. The content AAD
no longer depends on signing order. Issuer requests, responses, BIND, wrap AAD
and wrap or envelope nonces are unchanged.

Authority: [content protection](docs/spec--content-protection.md#32-content-aad),
[content encryption](docs/spec--content-protection.md#33-content-encryption)
and [data format](docs/spec--data-format.md).

### Breaking: unlock endpoints move to client integration

Publisher deliveries no longer carry `issuerData[issuerName].unlockUrl`.
The publisher sealer needs issuer identity, opening key and `keyId`, not an
endpoint URL. The installed client integration or explicit trusted client
configuration supplies that issuer's endpoint and any fallback routes.

**Who updates:** publisher writers omit the field; clients ignore any carried
value and supply trusted endpoint configuration for new unlocks. Without a configured
route, the client sends no request and does not enable conditional fallback. Cached usable
keys may still open content. Issuer request and response messages are unchanged.

**Action:** configure the issuer endpoint in the client integration. There is
no fallback to an article-carried URL. Updating issuer-supplied integration
routing can move endpoints without publisher edits or resealing articles;
integrations with fixed endpoint configuration still need an update.

Authority: [data format](docs/spec--data-format.md#42-issuerdata),
[core completeness](docs/spec--core-protocol.md#9-delegation-completeness) and
[HTTPS endpoint selection](docs/spec--http-binding.md#31-endpoint-and-channel).

### Breaking: the JSON document is the baseline carrier

The September baseline required publishers to emit the HTML markup carrier and
clients to read it; object delivery was optional. The baseline now requires the
JSON delivery document. HTML markup delivery is the optional
`dca-profile-html-carrier` profile. This carrier change does not change the
`dca-data` members or the sealed-content map.

**Who updates:** an HTML-only publisher also offers the JSON document when it
promises baseline-only clients. A markup-only client also reads the JSON document,
or relies on a publisher offering the HTML carrier profile. An HTML-only
publisher and a JSON-only client have no common required carrier; nor do a
JSON-only publisher and a September markup-only client. The JavaScript reference
supports both readers; independent implementations still need a common
supported carrier.

Authority: [baseline-only compatibility](docs/spec--profiles.md#36-compatibility-with-a-baseline-only-client).

### Breaking: issuer-sealed key envelopes for ckeys, pkeys and chains

The envelope binding prefix changed from `dca-bind-v1` to
`dca-bind-key-envelope`. It enters the cryptographic binding for all three
key kinds. The kind markers remain `c`, `p` and `pc`.

**Who updates:** publisher sealing and issuer opening code must agree on the
same binding bytes. An issuer using the September binding cannot open newly
sealed sources just by retrying. This is separate from client cache misses:
the client relays publisher-sealed sources; the issuer opens them.

**Action:** update the publisher and issuer together, or deliberately retain a
matching old-format route during transition. The current JavaScript reference does
not automatically translate old envelopes.

Authority: [sealed key envelopes](docs/spec--sealed-key-envelopes.md).

### Breaking: one shared period geometry

Publishers keep one configured period grid. Ordinary period-key-only deliveries
omit wire geometry because each wrap/envelope already names `t`. Selected
ordinary or content-group chain processing carries top-level `periodGeometry`
with both `periodMinutes` and `chainsPerDay`. Every group in one delivery uses the same pair; the former
`chainGeometry` member and per-family overrides are removed. A period-key-only
recipient still uses explicit `t` labels and does not derive chains. A baseline
content-key-only delivery needs no period geometry.

**Who updates:** publishers emit the new root member, relaying clients carry
it with selected chain sources and issuers validate the exact pair. Chain
responses do not echo geometry: clients admit and retain capabilities using the
immutable pair captured from that exact request, never response metadata. Old and new geometry values may coexist across retained
deliveries and caches. Ordinary Root/Step/Leaf bytes are unchanged for the same
pair, but the old carrier shape has no automatic alias.

Authority: [period keys](docs/spec-profile--period-keys.md),
[chain keys](docs/spec-profile--chain-keys.md).

### Breaking: chain fields in publisher, issuer and client

| Published field   | Current field    | Where used                                                                     |
| ----------------- | ---------------- | ------------------------------------------------------------------------------ |
| `periodChainKeys` | `chainKeys`      | Publisher sealed supply, unlock request sealed supply and unlock response keys |
| `periodChain`     | `periodGeometry` | Article and request geometry                                                   |

Ordinary `contentKeys` and `periodKeys` collection names remain unchanged.

**Who updates:** the publisher writer, client relay, issuer reader/writer and
client response reader must agree on these names. Unchanged September chain
code does not consume the current chain format.

**Action:** update the selected chain path across roles. Old code still cannot
read the new field names after a fresh unlock. There is no automatic old-name alias.

Authority: [chain keys](docs/spec-profile--chain-keys.md).

A selected chain relay must also send `requestedPeriodKeys` containing the
actual unresolved wrap labels. Omitting it requests no explicit article
coordinates; the issuer cannot infer them from `issuedAt`. Renaming fields
alone can therefore leave an old article closed when its needed periods are
outside the current/future periods the issuer otherwise answers. Other usable retained
keys or acquisition routes can still open it.

Authority: [requested article periods](docs/spec-profile--chain-keys.md#requested-article-periods).

### Breaking: period labels always carry minutes

The September grammar accepted two or four time digits, and its hourly
publisher emitted labels such as `251023T14`. Current labels always use
`YYMMDDTHHMM`: that example becomes `251023T1400`.

**Who updates:** publishers emit minute-bearing labels; issuer request readers
and client key readers use the current grammar. An invalid requested period
label makes the whole selected period request malformed before policy or key
opening. Clients discard malformed wrap labels and cached-key candidates.

**Action:** update label generation and readers together. Short-labelled cache
entries are not aliases for minute-labelled entries; obtain matching keys
under the new labels when needed.

Authority: [base period-key requirements](docs/spec-profile--period-keys.md#base-period-key-requirements).

### Breaking: method-only client-bound transport selection

A client-bound response now carries `transport.method` and its method-specific
members, without the redundant `transport.mode`. Direct responses still omit
`transport`. Clients require the known method they offered; missing, unknown or
mismatched methods never trigger direct fallback. Update issuer writers and
client readers together: older readers requiring `mode` refuse the new form.
Unknown extra transport members grant nothing. ECDH/RSA ciphertext transcripts,
key-kind binding, request association and endpoint agreements are unchanged.

### Breaking: `notDelivered` is a base result member with bounded reasons

September core allowed any non-empty `reason`, including `no_current_period`.
The current base result admits only `denied` and `unavailable`. No optional
profile selects this member. Issuers may omit it, but every client validates
the whole member and its association with the request before accepting its
status or stock period/chain grants. A malformed report now refuses only that
report and stock period/chain retention from the response; independently
admissible item grants and unrelated extension sections remain usable after
representation/transport admission. It gives no fallback or cached-denial signal.
Previously retained capability is unchanged.

**Action:** update issuers that emit reports and all client response readers.
Use `unavailable` for source unavailability previously described by
`no_current_period`; use `denied` for policy refusal. These reasons describe
different conditions and are not interchangeable. A chain family whose supplied
labels all fall off the selected time grid supplies no admitted key and does not
justify an `unavailable` report.

Authority: [family reports](docs/spec-profile--period-keys.md#family-reports-notdelivered).

### Breaking: chain derivation changes generated keys

The identifier inside Root, Step and Leaf derivation contexts changed from
`dca-period-chain-v1` to `dca-construction-chain-keys`. It is part of HKDF input,
not merely a display name or a JSON selector. Even with the same secret,
group, window and position, old and new constructions produce different keys.

The fundamental chain mechanics remain: 16-byte chain keys and period keys,
fixed windows, backward steps and a period-key derivation at each position.

**Who updates:** publisher construction and every issuer or client that derives
from chain keys must use the same construction transcript.

**Action:** switch to a new construction generation after the relevant code
supports it. Renaming JSON fields alone does not repair a derivation mismatch.
A client receiving ordinary pkeys need not implement chain derivation.

Authority: [chain-key construction](docs/spec-profile--chain-keys.md).

### Changed key material: random pkeys → derived pkeys

A simple publisher can continue generating random pkeys without chains. When
it enables chains, new renders use a new generation of derived pkeys. They
remain ordinary pkeys in usage, but the old cached bytes do not open new-generation
wraps at the same group and period coordinate.

**Action for a compatible client:** try retained candidates, unlock normally
when they fail, and retain the new key. Old keys remain useful for matching
old pages; no cache flush or extra seal linking old and new key material is required. This is
normal reacquisition, not wire incompatibility, and is not revocation.

This behavior does not make September-format issuers or chain clients
compatible with the breaking changes above.

### Added: staged chain activation and forward overlap

The publisher can supply both ordinary pkeys and chains. An ordinary route can
use the pkeys first; a later configured relay and issuer can use chain supply
from the same saved article. Chain input and chain output are separate choices:
an issuer can derive pkeys without returning chains to the client.

A forward overlap pkey comes from the selected construction and
keeps the same bytes when its coordinate becomes current. The publisher can
send one current-window chain plus an ordinary forward overlap pkey; no extra
next-window chain entry is required. An overlap wrap may instead remain cached-only when
another selected issuer route already completes the item and no separate
acquisition is promised.

**Action:** keep the pkey supply needed by each ordinary issuer route while
that route still relies on it. Reduce redundant supply after that route supports chain input.
Returning chains additionally requires a capable client. These are deployment
choices within the current format, not a bridge to the September format.

Details: [Starting with period keys and enabling chains later](docs/guide--chain-keys.md#starting-with-period-keys-and-enabling-chains-later).

### If using client-bound responses

The optional client-bound path also changed its crypto contexts. ECDH HKDF
info changed from `DCA-client-bound-transport` to
`dca-derivation-client-bound-transport`. Both ECDH and RSA-OAEP now bind each
response entry to its key kind using `dca-bind-client-bound-key-kind`, a zero
octet and `contentKey`, `periodKey` or `chainKey`.

**Action:** update issuer wrapping and client opening together. This affects
ckey, pkey and chain responses only when this transport is selected; ordinary
raw-key responses do not use these contexts.

Authority: [response binding](docs/spec--response-binding.md).

### Proposal documents adopted or deferred

The remove-wire-unlock-url proposal is adopted by the endpoint change above.
The integer-label proposal is now informative implementation guidance in
[guide--chain-keys--label-mapping.md](docs/guide--chain-keys--label-mapping.md).
It changes no wire label, coordinate or derived key.

The content-transforms proposal is replaced by the adopted `gzip` transform in
[content protection Section 8.2](docs/spec--content-protection.md#82-gzip-transform).
The host-custody, detached-content and detached-key-supply proposals are deferred
candidates and no longer appear in the public candidate set. Their removal does
not remove an adopted baseline capability or create a new supported transport.

### Renamed conformance identifiers

Conformance profile identifiers also changed:

| September identifier             | Current identifier or duty                       |
| -------------------------------- | ------------------------------------------------ |
| `dca-v1-direct-https`            | `dca-profile-baseline`                           |
| `dca-v1-exact-period`            | `dca-profile-period-keys`                        |
| `dca-v1-browser-origin`          | `dca-profile-browser-origin`                     |
| `dca-v1-client-bound-ecdh-p256`  | `dca-profile-client-bound-ecdh-p256`             |
| `dca-v1-client-bound-rsa-oaep`   | `dca-profile-client-bound-rsa-oaep`              |
| `dca-v1-content-representations` | `dca-profile-content-compression`                |
| `dca-period-chain-v1`            | `dca-profile-chain-keys`                         |
| `dca-v1-not-delivered-result`    | Retired profile; result admission is a base duty |

These are conformance identifiers, not wire values. The
[profile specification](docs/spec--profiles.md) defines current role duties.

### Added: optional compact ECDH envelopes

The [compact ECDH profile](docs/spec-profile--compact-ecdh.md) adds an optional
publisher-to-issuer envelope procedure. A publisher selects it per issuer block
with `"envelope": "compact-ecdh"`. It uses a fixed HPKE suite and compressed
P-256 point transport, saving 44 bytes per sealed value compared with ordinary
ECDH. The same issuer keypair and `keyId` can support both procedures.

**Action if selecting it:** confirm publisher, client relay and issuer support
before emitting compact envelopes. The relay preserves the selector; the issuer
explicitly permits the procedure for that keypair. Omission still means the
ordinary procedure, subject to its permission; a compact-only permission list
does not reinterpret omission. Support requires the specified bytes, not an
HPKE library dependency. Baseline deployments can keep ordinary envelopes.
This does not change content encryption or issuer-to-client response protection.

See the [extension setup and evidence](js/extensions/compact-ecdh/README.md).
A composing mechanism needs an explicitly defined payload/binding contract;
compact support does not imply support for every seed-based extension.

### Candidate: content groups with per-content-name seeds and connectors

The [content groups proposal](docs/spec-profile--content-groups.md) has a
public JavaScript extension,
[`js/extensions/content-groups/`](js/extensions/content-groups/README.md),
composed into the reference publisher, issuer and delivery client. The
publisher seals one 32-byte seed per content name and window to each issuer it
lists. The issuer derives group chain keys and period keys from it, or recovers
one item's content key through the item's 16-byte connector. Ordinary routes
coexist on the same page.

For implementations that tried an intervening candidate, the following changes
must be applied together; this candidate did not exist in the September draft.

Content-group chain response leaves now carry the key value directly, like
period-key leaves: `<contentName>.<group>.<cutoffLabel> = key`. The redundant
`{position, key}` wrapper is removed. Clients derive position from the cutoff
label and captured request geometry; cache identity, cryptographic bytes and
per-key-kind transport protection are unchanged. Candidate issuers and clients
must update together, including their composed-section descriptor; the former
wrapper has no compatibility alias.

The content groups proposal now uses root `renderPeriod` for the connector
coordinate, one named `connectors` map per item, and `contentGroups` in the
response. Its root `contentGroups` dictionary, indexed connector arrays,
delivery configuration wrapper, signed group dictionary and `generation` field
are removed. The seed derivation and envelope AAD bytes change; the candidate
section below lists the literals. Rotated retained-secret candidates
at the same group, geometry and window compete under bounded retention; a
higher cutoff does not prove that a different-secret lower key is obsolete.
Body authentication chooses the opening candidate. No generation hash, version
counter, cache duration or protocol-size ceiling replaces the removed field.
Publisher, issuer and client candidate implementations must update together.

- Literals: construction `dca-construction-content-groups`, seed salt
  `dca-construction-content-name-seeds`, seed AAD label
  `dca-bind-content-name-seed`, seed envelope `ecdh-p256-content-name-seed`.
  The item-pad derivation is unchanged.
- Wire: `issuerData.<issuer>.sealed.contentWindowSeeds.<contentName>.<windowStart>`,
  `contentData.<contentName>.connectors.<group>`, request
  `requestedContentGroups` and `requestedContentKeys`, response
  `contentGroups.chainKeys`, `contentGroups.periodKeys` and
  `contentGroups.contentKeys`.
- Removed the candidate's `contentKeyCommitments` claim and issuer digest check.
  Authorized item recovery returns the key candidate derived from the relayed
  connector; client body authentication decides whether it opens genuine content.
  The commitment-specific `policy.recovered` callback is removed. Candidate
  publisher and issuer implementations must update together: an older issuer
  requiring that claim refuses new deliveries. Baseline actors are unaffected.
- Client-bound transport wraps the content-group sections under two composed
  kinds, `contentGroupChainKey` and `contentGroupPeriodKey`. Both open to 16
  raw bytes. The host settles them with the transport's `settleKindDescriptors`.
- Reference API: `contentGroupsProfile` composes the roles, and its client
  bundle's `composeOptions` feeds `composeClient` or `createDeliveryClient`.
  The base client takes `recoverySources` and `responseSections`, a
  response-section consumer holds a recovered item key through
  `holdContentKey`, and plain `open()` and `openLocal()` recover item keys
  through recovery sources.
- Reference API, issuer: an `IssuerContribution` declares `responseSections`.
  `createIssuerCore` returns them as `responseSections` and refuses with
  `bad_config` a source member other than `periodGeometry` that no declared
  section starts at. The host passes `core.responseSections` to `KeyDelivery`
  as `composedSections`; the demo `IssuerServer` takes `responseSections` and
  `composedKinds`. In client-bound mode `KeyDelivery.prepare` refuses with
  `bad_config` an undeclared response member at any structural prefix of the
  declared section paths, before wrapping any key. Declaring one child does not
  permit an undeclared sibling to leave raw.
- Reference API, client: `ChainKeyCache` takes `maxMembersPerMessage` and
  `maxMembersPerFamily`, defaults 16 and 2. The content-group client passes
  `maxResponseMembers` and `maxWindowsPerGroup`.
- Removed: the publisher-wide seed form and its entries `publish`,
  `buildRequest`, `unlock`, `createClient`, `windowSeed`, `sealWindowSeed`,
  `openWindowSeed`, `seedAAD`, `inspectMirrors` and `inspectPage`, with the
  helpers only they used. No compatibility mode reads the old form.

**Who updates:** publisher, issuer and client candidate implementations update
together. Baseline implementers have no new requirement from this proposal.

This construction remains a Proposal. The reference extension is not an
adopted profile or a conformance claim.

### Candidate descriptions: opaque schema identifiers

The optional content-description Proposal now treats `schema` as a nonempty
Unicode scalar identifier within disclosed limits. Consumers compare it exactly
with trusted configuration; they no longer require absolute-URI syntax. Existing
URI identifiers remain valid. Producers using newly admitted names need a consumer
that accepts this revised candidate and explicitly supports that contract.
No normalization, automatic fetching or code loading is introduced; content
protection and baseline support requirements are unchanged.

### Reference behavior: chain routes and recipient grants

Chain relays now apply raw collection bounds before preserving selected sealed
values unchanged, including malformed values. Unchanged relay was already the
September behavior; issuer admission still decides their outcome.
The reference setup factories `issuerEngineFor` and `explicitIssuerEngineFor`
now refuse a conflicting construction or response representation;
`explicitIssuerEngineFor` pins `period-keys` instead of accepting chain output
accidentally.

**Action:** remove conflicting setup options rather than relying on silent
overrides. The JavaScript publisher's selected chain supply now defaults to
one item wrap at the render period. Set `chainItemSlots` explicitly for extra
period wraps; `chainWindows` independently controls publisher-to-issuer window
supply. Ordinary routes retain `period.slots`. A next-window key alone does not
open the old wrap: retain matching old capability, authorize recovery from the
old page's supply, or provide another complete route. This changes reference
authoring policy, not the wire grammar or issuer authorization.
`futurePeriodCount` does not limit independently authorized article targets.

The recipient-grant unlock profile and its reference extension are new since
September; there is no September recipient-grant implementation to update.
Verification entries must supply their issuing authority,
already required by the profile. Token `iss` remains optional. The reference
issuer passes one captured trusted instant through `grants.get(reference,
{nowMs})`; signed stores use it for time checks, while opaque stores may ignore
the extra argument. This adds no clock allowance. Encode opaque URL query values
so a literal `+` survives as `%2B`; valid bearer grammar is unchanged.

These reference behavior notes change no chain transcript or envelope bytes
beyond the changes described above. Details:
[chain keys](docs/spec-profile--chain-keys.md),
[chain reference setup](js/extensions/chain-keys/README.md) and
[recipient grants](docs/spec-profile--recipient-grant-unlock.md).

### Reference behavior: cross-extension composition repairs

These repairs change no chain, period-key or envelope transcript. One adds a
content-groups response member; the others change reference API behavior.

**Content-groups candidate** (publisher, issuer and client update together):

- A seed opening under a retired opening key no longer refuses the exchange.
  The issuer answers 200 and reports each authorized, attempted coordinate in
  `contentGroups.errors.{chainKeys,periodKeys,contentKeys}` with the fixed leaf
  `{"error":"key_retired"}`, beside base `key_retired` entries. The client admits
  the errors, files no key for them and reports them in the application's
  `errors`. Error entries count toward `maxResponseMembers`.
- The issuer policy input gains `request: {periodGeometry, renderPeriod}`. Both
  are unsigned request coordinates and grant nothing; render time still comes
  from the verified `issuedAt`.
- The publisher sizes each issuer's request with the client's own relay
  projection, and refuses a render whose promised connector keys at one issuer
  exceed `maxResponseMembers`. Alternative groups are choices, not promises, and
  are not counted.
- Local narrowing skips a content name outside the attempt before it looks for
  that name's connector or seed.
- The client bundle refuses at construction a cache without `attempted` or
  `clearReaderContext`.

**Reference API and composition:**

- Client: an admitted `unavailable` report keeps its conditional retry beside
  rejected key entries in the same response.
- Publisher: `CompressingSealer` carries every declared contributed item option
  and refuses an undeclared one with `unsupported_option`.
- Publisher: seal omission narrows `periodKeyDelivery` and `periodKeySourceTs`
  with the supplied access groups.
- Publisher: a page whose base geometry carries `periodMinutes` alone takes a
  contribution's complete pair with the same minutes; any other difference
  still refuses.
- Publisher: compact-envelope compatibility is checked per contributed issuer
  block when the render seals, not across the whole composition at
  construction.
- Publisher: the issuer request budget counts the block's `envelope` selector
  and each item preparation's `requestRelay`.
- Issuer: `createRecipientGrantIssuer(config, ...contributions)` accepts
  envelope contributions, such as compact ECDH, and refuses any other
  contribution.
- Issuer: a held opening-key entry whose `algorithm` is not `ecdh-p256` or
  `rsa-oaep` is a configuration fault, answered 500 before any opening.
- Issuer: when the host lists no `selectedExtensions`, `createIssuerCore` joins
  an injected engine's declared extensions with the contributions' names. A
  host-written list keeps its existing refusals.

### JavaScript integration: browser reader-context lifecycle

The reference client distinguishes `await client.clearAccessDecisions()` from
`await client.clearReaderContext()`. The first clears denial scheduling hints
while preserving delivered keys. The second retires old work and clears retained
capabilities and opening state; it does not revoke copies held outside that
client or replace the configured recipient wrapping keypair.

**Action for reference integrators:** use full reader reset for logout/account
switches, stop callbacks from the old session, and wait for cleanup before
starting the successor context. Injected retaining owners need the cleanup
contract documented in the [reader-context lifecycle](js/README.md#browser-reader-context-lifecycle).
These are reference API and application-integration changes, not new wire fields
or a requirement to use the reference implementation.

### Publication checkpoint

Both compared snapshots use outer wire version `"1"`. That value does not
identify which draft transcript a deployment supports. Do not infer
mixed-snapshot compatibility from that version alone. These entries were
checked against the September publication and the current source specifications.
The final publication review checks the exact outgoing snapshot before publication.
No old-format compatibility is claimed here.

## 1.0.0-alpha.1: 2026-09-21 public working draft

Published the DCA v1 working drafts and JavaScript reference implementation on
the public `draft` branch. Publication commit:
[a10164b](https://github.com/publishlab/delegated-content-access/commit/a10164beb34d72b96a7c7fa02a837c1577d85cee).
The retrospective annotated tag is `v1.0.0-alpha.1`. The publication date and
snapshot bytes remain unchanged. This alpha is the comparison baseline for the
next publication; it is not a release candidate.

## Release labels and snapshots

Pending changes appear under **Unreleased**. Each public working-draft,
pre-release or release-candidate publication moves them into a dated section
with its assigned release label, publication commit and previous publication
commit. A dated section describes an immutable snapshot; later changes appear
under the next Unreleased section.

Release labels follow [Semantic Versioning](https://semver.org/). The intended
sequence is `1.0.0-alpha.1` → `1.0.0-beta.1` → `1.0.0-rc.1` → `1.0.0`:

- **Alpha:** early drafts that may change substantially.
- **Beta:** more settled drafts being tested and refined.
- **RC (release candidate):** expected to be ready for stable release if no blockers are found.
- **Stable:** the released version, without a prerelease suffix.

Each stage can have any number of numbered publications: `alpha.1`, `alpha.2`,
and so on, including `alpha.99` and beyond. Beta and RC numbers restart at 1;
stages may be skipped. Git tags add a leading `v`, as in `v1.0.0-alpha.1`.
These labels identify specification and reference snapshots; the protocol's
wire version remains a separate identifier.
