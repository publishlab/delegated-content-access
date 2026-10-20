# Porting the JavaScript reference

A port implements the reference's exported behavior in another language. The
reference tests protocol ideas and supplies behavior that implementations can
follow and test against. Its APIs should therefore be clear in JavaScript and
practical across many languages. Prefer simple data when it expresses the
behavior; keep objects when state or composition is part of it.
Choose the API shape that ports and cross-language tests can use simply, even
when that shape is less idiomatic JavaScript. If a particular behavior warrants
a more complex shape, state that reason and test the behavior it preserves.

The reference implementation, its tests, and the test bridges form one porting
system. The main goal is to run the JavaScript reference tests as written
against a port, substituting target calls where possible. During porting, a
test may use both reference JavaScript and target code; evidence must say which
operations ran in each. Design all three parts together to extend that reach
across languages. An existing API or bridge limit is not fixed merely because
it came first, but change a reference test only for a clear portability or
behavioral gain. Preserve the behavior it is meant to distinguish. A simpler
portable API may be preferable to an idiomatic JavaScript API when both express
the same concept.

The target arrangement has four parts: reference implementation, each native
port, shared reference tests, and a generic test driver with one adapter per
language. A new port should not need a separate DCA-specific fixture library
beside its implementation merely to run those tests. A focused target fixture
may prove a crossing before the general route exists, but treat it as a
bounded exception: record why it is needed and whether a generic object or
callback route, a test adaptation, or a better reference API could remove it.
An explicit fixed instant or repeatable source in a composition API needs a
behavioral reason and a defined production default. Do not add arbitrary
test-only collaborator modes solely to eliminate fixture code.

The reference API must also port cleanly to long-running processes. A render
gets its own stateful Sealer and other per-render state; no correctness rule
depends on PHP ending a process after a request. A port may keep stateless
services alive and use its own DI scope, provided separate renders do not
share state that the reference keeps per render. Verify a stateful factory by
constructing two objects in one process, interleaving their operations and
checking that one object's fixed time, random draws and collected content do
not change the other's result. A process restart between the two objects is
not evidence of this property.

The shared bridge's wire schema, operation vocabulary, codecs, dispatch, and
proxy implementation describe language-neutral operations and values. They
contain no domain class names, fields, reconstruction rules, or protocol
behavior. Domain-to-native class and member mappings belong in target-supplied
declarations or target-specific test bindings, consumed as metadata. Generic
discovery messages may carry source-export names as data without defining
those names as protocol types. A proposed exception needs separate, repeated
review of why a generic operation cannot express the case and what every port
would have to implement; none is assumed here.

Each section below pairs what the JavaScript reference promises at its API
boundary with what a port does with that promise. A test bridge adapts values
and calls between them; its current limits do not decide the reference API.

The rules cover exported functions and the public methods of exported classes.
Internal code may use JavaScript language features; the behavior a port must
reproduce remains explicit at the API boundary and in tests.

Some exports predate these rules, for example the `DcaRequest` getters that
return `undefined`. They need migration; until then a port follows the
reference as it stands.

## Types

- **Reference:** every exported callable and public method of an exported
  class carries JSDoc parameter and return types, and `pnpm run check:types`
  checks its module through `jsconfig.json`. Exported values have declared
  shapes too.
- **Port:** expresses the same input and result contract with native types
  where possible, and a checked or reviewed declaration where the language
  version has no type syntax for it.

## Publisher render input

- **Reference:** `createPublisher().publish` takes a render record with own
  `resourceId`, `data` and `items` members. Every item has own `name` and
  `value` members and one of three shapes: a text string with `contentType`, a
  `Uint8Array` with `contentType`, or a representation descriptor in `value`
  with its own `bytes`, `contentType` and `contentEncodings`. A descriptor item
  has no sibling `contentType`. Optional `accessGroups` belongs to each item.
  With a period-key supply, one render may mix grouped and ungrouped items:
  grouped items are wrapped under their named groups; omitted or empty groups
  carry no `keys` member and need a complete item-content-key route in an
  issuer plan. With no period-key supply, the reference refuses an item that
  names a group. Each configured issuer needs a nonempty string `keyId`,
  checked when the publisher is constructed, and its opening key configuration.
  Publisher configuration needs no endpoint. Every emitted issuer block omits
  `unlockUrl`; complete issuer routes depend on suitable sealed material.
  Each issuer's `algorithm` is
  the envelope provisioning token `ecdh-p256` or `rsa-oaep` (sealed-key
  envelopes Section 2). The same lowercase token names an issuer opening-key
  entry's `algorithm`, the third argument of `keySealing.seal` and `open`, and
  a site plan issuer's `method`. Any other spelling, including the uppercase
  client-bound method names `ECDH-P256` and `RSA-OAEP`, is refused:
  `keySealing.seal` and `open` refuse it as `unsupported_algorithm` at the
  first seal or open, which covers a Sealer issuer's and an opening-key entry's
  `algorithm`; the site planner refuses it as `bad_config` at planning. No
  alias is taken. The token is configuration and
  never a wire member; WebCrypto algorithm names and client-bound methods keep
  their uppercase spellings. The
  Sealer also requires supplied period/family-plan labels to use canonical
  `YYMMDDTHHMM` spelling before acquiring key material at that label.
  The reference checks schema members as own
  members, refuses unsupported fields before sealing, and treats a present
  optional member whose value is `undefined` as malformed rather than omitted.
  The checked JS type excludes a valued sibling `contentType` on a descriptor;
  runtime validation also refuses an own sibling set to `undefined`.
- **Assignment and issuer supply:** the host computes each item's assignment
  from its own inputs and passes the result in that item. The same render
  assignments apply across issuers. The separate resource `data` member is
  signed metadata; assignment computation need not come from it or appear in
  the resource JWT. Each issuer's `issuerSupplyPlanFor` independently selects
  which item content keys or assigned groups it receives. An authored group
  wrap does not require an issuer to supply that group's period key when a
  complete item-content-key route exists.
- **Snapshot:** `publish` builds a fresh Sealer for each call. Resource data,
  item bytes, encoding lists and group lists are captured before the first
  asynchronous key-supply operation, so later host mutation and interleaved
  publishes do not mix render inputs. A port may use native record classes,
  arrays or other typed containers; preserve this own-field contract and
  per-render isolation without requiring JavaScript prototype behavior.
- **Content encryption:** the Sealer uses each fresh independent item key for
  one AES-128-GCM encryption with twelve zero nonce bytes and
  `LP(renderId) || LP(contentName)` as AAD (see
  [Derived content AAD](#derived-content-aad)). Its emitted item carries
  neither `aad` nor `nonce`. Type and encoding admission still rejects invalid
  handling values as `bad_config`; those values are outside content AAD.
- **Port:** maps these alternatives to native text, bytes and descriptor types.
  Keep the descriptor's content type and encoding list attached to its bytes;
  do not infer those values from arbitrary object shape or silently accept an
  unsupported field.

## Bytes

- **Reference:** byte values are `Uint8Array`. Where an API position declares
  bytes, the reference may also refuse a JavaScript string, because JavaScript
  could turn that text into other octets than the caller meant. Such a refusal
  is a JavaScript type guard. Its tests stay direct JavaScript tests and are not
  portable cases.
- **Port:** holds bytes in its language's byte type. PHP has none and uses a
  binary string, which is the native bytes value at a position that declares
  bytes. A PHP port need not tell a caller's text string apart from bytes
  there. At such a position a port uses the supplied octets unchanged and adds
  no text-encoding step: PHP takes `"key"` as the three octets `6b 65 79`. A
  refusal that depends on the octets stays portable, such as a 15-byte value
  where the position declares 16 bytes.
- **Delivery documents:** an adapter that crosses between roles produces or
  consumes bytes, not a native object. `writeJsonDelivery` returns the UTF-8
  octets of the data format's Section 6 document, and `JsonDeliveryReader`
  takes those octets with the publisher origin as separate host context. A
  port returns and accepts its byte type at the same positions. The reader's
  refusal of a JavaScript string is a type guard. Its refusal of malformed
  UTF-8 or a non-object document depends on the octets and is portable.
  [Data Format Section 2](../docs/spec--data-format.md#2-common-json-rules)
  requires a reader to ignore exactly one initial UTF-8 byte order mark
  (`EF BB BF` at byte offset zero). Producers still emit none. A repeated mark
  or one after whitespace is refused; U+FEFF inside a JSON string remains data.
  This applies to every binding that cites Data Format Section 2, unlock
  bodies included; it does not apply to opened item content. Strip the mark in
  one place: a decoder that drops one mark and a JSON parser that drops another
  admit `EF BB BF EF BB BF`. `parseDcaRequest` also takes decoded text; decode
  it with `ignoreBOM: true` or pass the bytes.
- **Chain derivations:** an empty salt and a salt of 32 zero octets give the
  same output under HMAC-SHA-256; a library that substitutes `HashLen` zero
  octets for an absent salt conforms to the selected empty-salt transcript.
  The reference refuses a forward or cross-window derivation request as a
  usability guard; the boundary itself comes from the transcript in
  [chain keys Section 6.6](../docs/spec-profile--chain-keys.md#66-operations).

## Open records

- **Reference:** an exported API that checks for unknown members of an open
  input record makes that refusal observable; it does not silently ignore
  those members.
- **Port:** preserves the refusal. A typed binder may reject an unknown
  member before calling product code and need not reproduce the reference's
  `unsupported_option` error code for that binder failure.

## Absent values

- **Reference:** no argument, record member, list element or value-bearing
  return carries `undefined`. An optional input is a member left out of an
  options record; a present member whose value is `undefined` does not count
  as left out. An empty value-bearing result is `null`; a function with no
  result declares `void` as below.
- **Port:** a left-out options member becomes an absent key or an omitted
  optional parameter, and `null` stays `null`.

## Functions that return nothing

- **Reference:** a function that returns nothing declares `@returns {void}` or
  `@returns {Promise<void>}`. Its API promises completion or an error, with no
  result value. JavaScript evaluates such a call to `undefined`.
- **Port:** declares its language's void. In PHP 7.1 and later that is
  `: void`, and a call yields `null`; the test bridge reads the reference
  return type and hands a JavaScript test `undefined`.

## Asynchronous functions

- **Reference:** an export may be `async` and return `Promise<T>`.
- **Port:** preserves the eventual value or error. A synchronous
  implementation can return `T` directly; another language may use its own
  asynchronous mechanism. When an unchanged JavaScript test expects a promise,
  the test bridge presents the port's value as a resolution and its error as a
  rejection. For an export the reference declares `async`, the supplied bridge
  does this for a synchronous port too, such as a PHP method that returns or
  throws.

## Unions

- **Reference:** alternatives with different observable behavior need a
  portable way to distinguish them, such as a discriminant in a record. An
  untagged union is acceptable when its alternatives have the same observable
  behavior after conversion or their distinction is clear across ports.
- **Port:** preserves the behavior of each alternative. If its native values
  collapse two alternatives with different behavior, it reports that boundary
  for design review rather than silently choosing one. Text that collapses
  with a declared byte type is not a union; [Bytes](#bytes) covers it.

## Classes

- **Reference:** a class may hold state and compose other objects. A data
  wrapper can expose a plain-data view, such as `DcaRequest.toObject` in
  `core-shared--client-issuer/DcaRequest.js`.
- **Port:** preserves the class's observable behavior using its language's
  native abstraction; its class and method names need not match JavaScript.
  The supplied bridge can route a named, claimed class constructor in a
  strict selection and keep the native instance behind a session handle.
  Other factory mappings need a decision for the concrete API.

An object under test is constructed and used in the port. A bridge may carry
its identity by a handle while the test holds a proxy; the supplied bridges do
so for an object a port returns from a class it claims, and the proxy calls
only the methods the port claims
([object handles](test-bridges/_shared/CONTRACT.md#object-handles)). An
object used only as test input may instead cross as data and be rebuilt in the
port. Choose either mapping for a concrete test; copying a reference
instance's data does not test the port's constructor or methods.

## Injected collaborators

The optional recipient-grant reference in
`extensions/recipient-grant/client.js` and `extensions/recipient-grant/issuer.js`
composes the baseline roles without changing their JSON members. The browser
client takes trusted issuer, publisher-origin and resource selection, an opaque
reference and a Fetch-compatible transport. The issuer takes its trusted
issuer identity, a reference-to-record lookup, the current access policy and
an optional clock; each unlock receives its publisher registration and HTTP
authorization field from the host. Grant records use epoch-millisecond bounds
and a named-item set. A port may use native HTTP, credential storage and
clock types while preserving sole-bearer carriage, admission order, current
policy intersection and content-key-only result admission. Grant issuance and
reference encoding are host concerns outside this reference API. The
`BrowserUnlockHttp` adapter's `authorization` option adds the explicit header
and preflight allowance without selecting ambient browser credentials; in that
mode every 401 carries a `WWW-Authenticate: Bearer` challenge. The adapter names
no challenge for a 401 without bearer mode.

- **Reference:** describe the behavior an exported object requires of a
  collaborator. For example, Sealer's clock has `now() → Date`; its contract
  does not require the demo `Clock` class or that class's `advance` and `set`
  methods. A test may supply a fixed clock so Sealer's time-dependent result
  is repeatable.
- **Port:** preserve the same behavior with a native callable, interface or
  object. A PHP Sealer can call a `now` callable that returns a
  `DateTimeImmutable`. The port need not reproduce a JavaScript test helper
  whose extra behavior is outside the exported contract.

For a composed, stateful object selected for cross-language reference tests,
the reference must expose a construction entry point that ports can map. It
provides normal runtime dependencies and accepts explicit setup values where
a test needs repeatable behavior. A simple value function needs no factory.
Nor does a class that the bridge can construct directly from data. Use one
mapped entry point for a composed object and extend its setup for further
tests of that object. Add another factory only for a distinct construction
boundary that direct construction or the existing entry point cannot express;
do not add one per method, collaborator or test.
For Sealer, a fixed instant can cross as a JavaScript `Date` and become a
native instant; the factory on each side then builds its own clock. An absent
fixed instant means that side uses its real clock. The shared test supplies
setup values to the same factory rather than assembling a second Sealer.
Production builds a native secure random source. A byte-exact
shared test can supply one random byte stream. The factory builds a native
reader that returns the next `n` bytes for each `bytes(n)` call and refuses a
read past the end, regardless of how a port splits its reads. The stream is
used for bytes the render draws itself, not library key generation or signing.
The test asserts every drawn value that reaches its result, through the last
byte it expects. The reader has no render-completion hook to refuse unused
bytes. The stream is trusted test setup, never publisher or request data, and
ports need not copy the reference test's seeded generator. A byte-exact case
still fixes the order of observable drawn values. The origin selection uses
known test key documents; the period-key selection also supplies fixed keys
for the periods it exercises.

The factory is test code. The reference keeps it and the strict fixed
period-key supply it composes in `core-publisher/testing/`, and a port ships
the pair as a testing module that no production code imports.
A port must map that construction export, but may implement it with a
function, a static method or its DI container's wiring. It must accept the
agreed setup and return a real native Sealer; it need not have a class named
Factory. The factory has no required singleton lifetime: a DI container may
share a stateless factory, while each call creates a fresh stateful Sealer and
random reader. The bridge discovers that callable through the port's export
metadata and holds the returned object by handle. Its language adapter
materializes each setup value in the native type the port declares, using
parameter types or explicit
mapping metadata where those types cannot express the conversion. A port may
define its own value or collaborator object when the language has no matching
built-in type; the shared bridge protocol still names no DCA class. A value
that cannot be materialized is a crossing failure, not a reference fallback.
Neither the shared bridge protocol nor the reference factory assumes PHP's
per-request process lifetime. A port in a long-running runtime constructs a
fresh stateful Sealer for each render.
The bridge carries no callbacks today. If setup data cannot express an input,
a generic route can be added when a shared test needs it. Do not put Sealer, Clock or their member
names into the shared bridge protocol. The `portable-sealer-*` selections prove
the mapped factory route for origin, period-key, issuer, refusal, content
descriptor and runtime-default cases; they do not cover every Sealer behavior.

## Role integration operations

The reference client does not verify `resourceJWT`. A client may perform a
local verification check, but baseline client conformance does not require it
and it never replaces the issuer's verification under
[core Section 4.2](../docs/spec--core-protocol.md#42-verification-and-registration).
Decoded but unverified claims establish no publisher authority.

`integration-client/createDeliveryClient.js` composes one captured delivery
from a reader exposing parsed `dcaData`, a trusted `publisherOrigin` and
`extract(contentName)`. Ports may use native carrier readers and HTTP clients.
`open` resolves retained capability, performs a single configured unlock when
needed, and returns a content name, handling media type and opened bytes.
The selected issuer's endpoint is an acquisition route, not a construction
precondition: the host's `unlockUrl` is admitted at construction if supplied.
The delivery supplies no endpoint, and any carried `unlockUrl` is ignored.
Missing trusted endpoint configuration refuses new acquisition, with no POST.
A delivery without usable sealed material for the configured issuer keeps
local opening and explicit route walks; that acquisition sends no request.
Capture trusted publisher context, endpoint and transport for the client;
issuer aliases never select credentials from another context. Hosts separate
retained capability namespaces when their authentication contexts differ.
Ordinary `open(name)` first runs pure used-item/representation admission before
its own cache lookup or acquisition, preserving original item exceptions and
running no decoder. This reference integration contract avoids acquiring for
an unusable requested item. It adds no baseline wire or issuer duty and no
privacy/no-acquisition promise: standalone `unlock` and independently scheduled
acquisitions remain separate. Valid content is decoded only after authenticated
opening. `openLocal` performs no issuer request. It runs the same pure version
and used-item admission as `open` before any key lookup, so a width-malformed
item gives `bad_page` whether or not a key is held, never `no_key`; valid
siblings still open. `unlockRoutes` takes explicit trusted
route records; conditional attempts retain the eligible coordinate scope of
the preceding outcome, while an independent attempt is separately selected.
Host-owned context lifetime and output eligibility apply across asynchronous
completion. None of these operations places content in a document. Ordinary `unlock` returns
an HTTP result `{status, body, application}` when transport occurred, or
`{skipped: 'no-eligible-route', application: null}` when no eligible coordinates
exist; a skipped operation invents no HTTP status or body.

`unlockRoutes` returns `{missing, attempts, failed}`. Known item-local
`bad_page` and `unsupported_encoding` preflight failures appear as
`failed: [{name, code}]`; those items are excluded from requests and `missing`,
while valid siblings continue. Global delivery admission, configuration,
storage and unexpected errors propagate. Preflight checks canonical
ciphertext encoding/width before acquiring keys; it invokes no decoder.

`attempts` lists the visited routes in route order, one
`{issuerName, outcome, status?}` record each. The walk skips a conditional
route that no earlier outcome made eligible, and stops once nothing is
missing; neither leaves a record. `outcome` is a finite reference API token,
not a wire value, and describes the attempt rather than any item:

- `not-on-page`: the delivery has no block for this issuer; no request.
- `unsupported-retry-projection`: a conditional retry could not be narrowed to
  its eligible identities; no request.
- `no-eligible-route`: the request would present no coordinate; no request.
- `indeterminate`: the transport could not observe the HTTP outcome.
- `offline`, `timeout`, `no_route`: the transport's typed local failure;
  `timeout` means a deadline known to fire before send.
- `unusable-response`: a 200 that is no usable DCA result, such as a non-JSON
  body or a whole-response refusal.
- `fault`: an HTTP status of 500 or above.
- `unavailable`: a 200 whose admitted `unavailable` report names a family a
  missing item still needs, on a route that set `retryUnavailable`.
- `answered`: every other HTTP answer, including denials and 200s that
  delivered no key.

An admitted `unavailable` report keeps its conditional retry when other entries
of the same response are rejected: a malformed or unsolicited key entry beside
the report does not suppress it (period keys Section 5.6). The retry still needs
`retryUnavailable` on the route and a family a missing item still needs. A
whole-response refusal admits no report, so it
makes no family eligible; a separately configured independent attempt still runs.

`status` is present exactly when the attempt received an HTTP answer, which
means on `unusable-response`, `fault`, `unavailable` and `answered`. An
`answered` attempt is not plaintext success. The walk's final disposition is
`missing`, the valid items still without an authenticated key, and `failed`,
the items that failed preflight. A port keeps the token set closed and maps
each case to the same token; it changes no retry rule by doing so.

`ContentRepresentationOpener.preflight({item})` synchronously validates the
captured item view's encoding list and resolves every encoding name against the
opener's captured decoder registry. It returns no value and runs
no decoder. The route walk uses this check before authenticating candidate key
bytes against the captured ciphertext; only a successful AEAD check counts as
opened coverage. A port preserves this ordering and side-effect boundary, and
does not run representation transforms during route selection. Normal
`open({item, ciphertext, resolveKey})` performs the same preflight before
resolving a key, then decrypts and runs the selected decoders in reverse order.
The exported `ContentDecoder` typedef in `core-client/ContentRepresentationOpener.js`
is also the composition option's callback contract. Each decoder receives
`decode(bytes, {maxOutputBytes})`, where the allowance is
the lesser of the per-layer limit and the remaining total output limit. A decoder
must enforce it while expanding output; zero permits an empty result, with normal
framing and integrity checks still required. The opener also checks the returned
type and size. Injected decoders are trusted code; the allowance does not sandbox
their other allocations or execution time.

`ContentKeyResolver.contentKeyForAuthenticatedItem(dcaData, contentName,
authenticate)` tries the held item key and then the existing cache-derived
wrapped-key alternative. The async `authenticate(candidate)` predicate answers
boolean and is a trusted, side-effect-free check. The first accepted candidate
is retained under that publisher, render and item, so a later ordinary
`contentKeyFor` call uses it. Predicate exceptions propagate. If every
candidate is refused, existing held-key state remains intact. The ordinary
`contentKeyFor` method keeps its established held-key-first acquisition
behavior. A port preserves candidate order, scoped retention and no-mutation
on refusal; it does not expose a candidate list or a general-purpose setter.
`resolveAuthenticated(dcaData, contentNames, authenticate, application?)` performs
that authenticated selection for all requested items under one captured response
application lease. Its predicate takes `(contentName, candidate)` and answers a
promise of boolean; the result is `{covered, missing, origins}` metadata.
A refused wrapped candidate does not stop later candidates or replace the held
key. Authentication precedes retaining a successful key. The three leased
entries, `contentKeyFor` with `contentKeyWithOriginFor`, `resolve` with
`resolveDetailed`, and `resolveAuthenticated`, complete the response attempt
when the operation ends by return or by fault. Completion runs once per lease,
waits for concurrent captured readers and files the response's private grants
for reuse, so a storage or predicate fault does not discard an obtained grant.
The operation's own fault reaches the caller; a completion fault behind it
does not replace it. Finite trial bounds are unchanged.
The route walk uses this operation directly after response
application; an ordinary held-key-first resolve must not consume its private
capability first. Injected resolvers need this method only for `unlockRoutes`;
the helper rejects its absence before preflight or transport.

`integration-issuer/createIssuerCore.js` accepts explicit selected capability
sources and encoders, or an already composed extension engine. An injected
engine owns its policy and engine configuration. When it declares
`selectedExtensions` or `capabilityEncoders`, the entry gives the processor
those declarations for each one the host leaves out; a host value stays, and
construction refuses it with `bad_config` when it drops a declared extension
or encoder kind. `notDeliveredReport` sets which `notDelivered` family reports
the engine discloses (period keys Section 5.6 makes the report optional):
`none`, the default, reports nothing; `partial` reports beside a result the
request earns anyway; `complete` also answers a complete denial with a no-key
report. `createIssuerCore` passes it to the base engine it builds, and
`chainKeyIssuerEngine` takes the same option for its own engine.
A contribution declares the key-bearing sections its `responseSectionSource`
writes as `responseSections`. `createIssuerCore` returns their union as
`responseSections` beside `engine`, `processor` and `endpoint`, and refuses
with `bad_config` a source member other than `periodGeometry` that no declared
section or error path starts at. The host passes `core.responseSections` to `KeyDelivery` as
`composedSections`; in client-bound mode `KeyDelivery.prepare` refuses with
`bad_config` a top-level body member outside `keys`, `errors`, `notDelivered`
and `periodGeometry` that no declared section starts at. A port keeps both
refusals, so an undeclared section never leaves unwrapped.
A section may declare an optional trusted `errorPath`: a non-base member path
that neither equals nor overlaps another declared path, where the issuer reports
a retired opening key per coordinate, nested at the section's `depth`. Each leaf
there is exactly `{ "error": "key_retired" }` (`isRetirementLeaf`).
`createIssuerCore` settles it with its section and returns it in
`core.responseSections`. In client-bound mode `KeyDelivery.prepare` passes those
leaves unwrapped, because an error record is never a key entry, and refuses with
`bad_config` any other leaf, a map not nested to the section's depth, or an
error map no section declares.

At construction, `IssuerEngine` copies and freezes each response source's
declared metadata and captures its `presented` and `respond` functions with the
original source object as their receiver. `createIssuerCore` uses that same
captured `presented` function for contribution admission. Later reassignment of
either source property does not replace the callback, and construction does not
freeze the caller's source object. A port preserves both callback identity and
receiver while keeping the copied metadata immutable.

A client consumer walks the map with `core-client/responseSectionEntries.js`
`composedSectionErrors`. `createBrowserIssuer` adds
HTTP admission for ordinary direct responses; `admitBrowserRequest` exposes
the admission step for host-owned response preparation and commit flows.
The raw request body is measured and parsed before asynchronous hooks, and its
parsed document remains immutable thereafter. Registration lookup and caller
authentication are host collaborators. A lookup that finds no registration for
the `kid` is the request's `unknown_publisher_key`. A registration the host
built wrong, without an opening-key store or with a verification key that is
not ES256, is an issuer fault answered 5xx, never the request's
`bad_signature`; a port checks its own runtime's key type. A registration
store, caller admission or opening-key store that throws is an issuer outage
answered 500 `internal_error`; a `code` on its error, such as `ECONNREFUSED`,
never becomes the request's refusal. A policy keeps its typed
`policy_unavailable` (503). Publisher verification and exact Origin
comparison precede policy or envelope opening.

A successful `checkEnvelopes` returns deeply immutable claims. Browser admission
may forward that original object as the host invocation's `verification`.
The engine consumes its private provenance once, bound to the same request
object, unchanged resource-token bytes, current publisher public-key object,
and development-origin mode. Copied, forged, consumed or mismatched claims
cause ordinary verification. The standalone engine verifies without a matching
result. Concurrent uses can consume it only once. Policy, operating-name checks
and envelope opening still run for each unlock; sources receive only their
ordinary captured-time context. A processor that projects a different request
also verifies independently.

This is local verification reuse, with no wire member or portable serialized
receipt. A port can use native identity and a private association whose lifetime
is bounded by the original claims, or simply retain independent verification.
It must preserve these bindings and immutable claims if it implements reuse.

`integration-publisher/createPublisher.js` accepts a selected envelope sealer
and one render-wide content-key wrap strategy. Its matching issuer supply
planner must satisfy the core's composition checks before entropy is drawn.
Ports preserve these collaborator contracts without importing optional
extension implementations into their baseline entry.

When contributions are supplied, `createPublisher(base, ...contributions)` uses
`core-publisher/publisherComposition.js::composePublisherConfig`. Without
contributions it keeps the existing publisher admission path. Each named
contribution declares only its supplied seams. `contentKeyWrapStrategy`,
`keySealing` and `periodKeySupply` each have at most one owner; a non-undefined
explicit base value is also an owner. Two owners fail with `bad_config` before
collaborator methods, clock or entropy run. Core defaults own no seam. A
supply-planner wrapper wraps the checked inner planner: for wrappers A then B,
B is outermost and calls run `B enter, A enter, base, A exit, B exit`.
Contribution names are unique and nonempty; an explicitly undefined
contribution or contribution member is refused. Omit an unused argument or
member instead.

`composePublisherConfig` returns frozen `{ config, owners, plannerOrder }`;
`plannerOrder` records wrapper contribution names in the supplied order.
Composed issuer configuration admits `ISSUER_CONFIG_MEMBERS` plus the selected
contributions' declared `issuerConfigMembers`; contribution-owned members are
removed before base Sealer admission. Each contribution validates its own
configuration values. A plain Sealer and the no-contribution entry retain their
existing open issuer-record admission.

Composition copies and freezes its configuration record, issuer list and issuer
records, plus the known ordinary nested containers `signingKeys`, `period` and
issuer `limits`. It preserves the signing map's own members and enumerability
for unchanged Sealer constructor admission. The publisher entry validates
first and then snapshots accepted own enumerable configuration members and
these supported containers, including when no contributions are supplied.
`signingKid` is a nonempty string, checked before the key lookup; a sole held
key under the empty name is refused the same way. The selected key is an own
entry of `signingKeys`, enumerable or not, and every runtime snapshot carries
it by name, so the plain Sealer, the entry and the composed entry sign with it;
an inherited entry is not a held key. When supplied, `period` is an options
object containing only `length` and `slots`, read as own members, enumerable or
not; the runtime snapshot copies both by name. Another shape, an unknown member
or an invalid explicit value is a configuration failure at construction;
defaults apply to omitted options and do not repair a malformed one.
CryptoKeys and injected collaborators retain identity; their internal behavior
is not snapshotted. Composition leaves non-record nested values as given for
normal Sealer admission. Rotating retained configuration requires another
publisher. The base entry imports no extension.

## Errors

- **Reference:** a protocol failure throws `DcaError` from
  `core-shared/errors.js`, and its `code` carries the failure as data.
- **Port:** throws its own error class with the same code.

## Source metadata

- **Reference:** none.
- **Port:** may supply test bridge metadata that maps native callables and
  classes to reference modules, exports and class methods. The PHP bridge reads single-line attributes,
  which PHP 7.3 reads as comments; product behavior does not read them. Product
  code handles its own language's values, without depending on bridge-only
  types. The current PHP bridge still passes a sentinel for `undefined` inputs
  and a byte object for explicitly `mixed` parameters. Those are limits to
  resolve at the boundary, not types for a port to adopt. The bridge side is in
  [test-bridges/_shared/CONTRACT.md](test-bridges/_shared/CONTRACT.md).

## Testing a port

Aim to run as much of the existing JavaScript reference suite against each
port as practical, with its tests and assertions intact. Start with native
scalars, records, lists and bytes. Support live target objects and local
composition when those are needed to route an existing test. A test can keep
JavaScript fixture objects and reference calls while selected operations run
in the target; the boundary must make that split visible.

When a JavaScript-specific fixture mechanism makes an otherwise portable
behavior inaccessible, examine the reference API, test, and bridge together.
A focused test adaptation or target-side fixture binding can be justified by
the additional behavior it lets ports test. Such a binding must construct and
call the real port objects. It must not perform the behavior under test,
correct invalid input, choose answers by case name, or manufacture observations
from expected results. Keep expected values and verdicts in JavaScript.
Preserve state and identity when the test observes them. Add session handles,
property routes, or reverse callbacks when they let shared tests observe
consequential port behavior. Keep extending bridge coverage where that is
practical, especially for the results and failures of real native object
composition; a higher replay count alone does not justify a mechanism. Native
tests complement bridged tests and can cover fine-grained callback, state or
identity behavior that is impractical to replay. They do not substitute for a
shared result or error assertion against a composed port when that crossing
is practical. Record which observable behavior the bridged tests cover, which
behavior native tests cover, and what remains uncovered. A native fixture may
use different machinery from the JavaScript fixture while checking the same
behavioral obligation.
Object proxies cannot transparently reproduce every JavaScript class feature:
private fields, borrowed methods, prototype mutation, and asynchronous
callbacks may need a supported mapping or a focused test change. A target
proxy must never run a reference method by accident. Ordinary copied records
also do not preserve identity or shared mutation; tests of those behaviors
need an explicit crossing that does.

A passing bridged test counts as port evidence only for behavior actually run
in the port. A reference constructor or method left running in JavaScript is
not coverage of its ported counterpart. State which calls ran in the target
and which remained in JavaScript, including local target-object calls that the
driver cannot see directly. A deliberately wrong port should fail a
meaningful assertion. If a value cannot cross, report that limit rather than
changing product code to accept a bridge value type.

A new port can start with native unit tests over recorded Sealer renders
before it has a bridge adapter. The fixture package
[`verification/fixtures/v1/reference/protocol-regressions/`](../verification/fixtures/v1/reference/protocol-regressions/README.md)
holds three records in format `sealer-factory-v3`: `seal-factory-content-key-only.json`,
`seal-factory-period-keys.json` and `seal-factory-mixed-issuers.json`, which
renders two items for an ECDH issuer and an RSA-OAEP issuer. Each holds the
factory setup, the calls of one render as data, `[member, args]`, and the
values the render must carry. Bytes and instants are tagged values at any
depth, in the layouts the bridge frames use
([CONTRACT.md](test-bridges/_shared/CONTRACT.md), "Value serialization"),
so one codec reads both records and frames. The test keys are PEM. The port
builds its Sealer through its mapped factory and makes the calls. It then
checks the signed resource and its signature, each drawn
value at its place on the wire, the plaintext each item opens to, and the key
each issuer envelope opens to. The record carries each issuer's private key for
that last check, outside the setup. The factory only ever gets the public key.
An RSA-OAEP envelope draws nothing from the stream, so it is opened, not pinned.
`seal-factory-refusals.json`, format `sealer-factory-refusal-v2`, holds the
refusals the bridged `portable-sealer-refusals` and
`portable-sealer-refusals-dynamic` cases make, each as a setup change and
calls with the DCA error code expected. It does not mark which selection a
case belongs to.
[test-vectors/sealer-factory-records.test.js](test-vectors/sealer-factory-records.test.js)
replays the records against the reference.

The bridged Sealer selections remain the full check. The records hold no two
renders interleaved in one process and no chain key. The refusal record
holds a read past the end of the stream, but it pins codes, not messages. The
records pin no ECDH ephemeral key, no RSA-OAEP ciphertext and no signature.

## Chain-key request relay

`ChainKeyRequestBuilder` preserves the selected publisher geometry representation
and applies the raw chain-member bounds before projection. When an admitted
family geometry resolves, it emits article-period hints only for canonical labels
on that family's grid. An off-grid item wrap supplies no hint and does not suppress
usable base material or on-grid siblings. An absent or malformed geometry is not
repaired by the relay; its existing issuer-family failure scope remains operative.
Issuer admission still refuses a directly authored off-grid hint for a valid family.
Ports preserve these selection and failure scopes without deriving or opening keys.

A relay-only composition also admits the ordinary period keys an issuer projects
from the presented chain reach. `ChainKeyRequestBuilder` exposes the synchronous
`acceptsPeriodKeyResponseCoordinate(accessGroup, t, request)` method, returning a
boolean. It uses the same canonical carrier and reach validator as the client
profile, without deriving keys or requiring a chain cache. The exported helper
module under the extension's `core-client/` directory shares this role logic; it
is not a separate integration entry.

`composeClient` wires that optional builder method into the resolver's
`periodKeyResponseCoordinate(accessGroup, t, request)` collaborator. The resolver
passes only the immutable `ResponseAssociation.request` snapshot. A supplied
`chainKeyProfile.acceptsPeriodKeyResponseCoordinate` takes precedence. A
non-function resolver collaborator or a non-boolean result fails `bad_config`.
An accepted coordinate still passes the ordinary transport, key-width and cache
admission rules. Directly presented period-key coordinates retain their base
admission even if the chain geometry is invalid. A bare resolver has no relay
validator by default: its host must supply one explicitly to admit projections.
Ports preserve this selection and snapshot boundary; a hint alone or later
mutation of the caller's request cannot enlarge the presented chain reach.

The reference defaults to 16 chain members per message. An explicit trusted
`maxChainMembersPerMessage` accepts a positive safe integer on the publisher's
issuer entry, `ChainKeyRequestBuilder`, chain carrier/request/response readers,
`chainKeyCapabilitySource` and `chainKeyIssuerEngine`. The client and cross-role
profile factories take the same setting in their optional second configuration
argument; a composed issuer refuses a conflicting capacity. Profile carrier
memoization is partitioned by capacity as well as request/response identity.
The client cache's existing `maxMembersPerMessage` must also admit the intended
response, and ordinary request byte/entry budgets remain independently active.

Values above 16 are an implementation capacity override for explicitly matched
peers and measurement. They exceed the current chain-key specification's bound;
they do not change that specification, profile identity, wire format or default
interoperability promise. The setting is never read from delivered data. The
two-members-per-family bound, geometry checks and authorization remain unchanged.
Ports preserve the default and explicit override separately, including failures
before the requested large carrier is projected to a smaller subset.

## Issuer version admission

- **Reference:** after raw body caps, JSON parsing and the non-array request
  carrier check, `IssuerProcessor.admit` calls the engine's synchronous pure
  `checkVersion(request)` guard, which returns void, before version-dependent
  member admission.
  `IssuerEngine` uses its captured `supportedVersions`; the chain composition
  forwards that guard. The guard performs no registration lookup, caller or
  signature work, policy or opening-key access. An injected unlock-only engine
  uses the baseline version guard; an engine with a different supported set
  provides its own pure guard. Version errors remain bounded `bad_version`
  refusals; other guard faults are not silently converted into that refusal.
  The request must contain its own `sealed.contentKeys` object, which may be
  empty beside a selected nonempty section. Optional omission of that member
  in a publisher delivery block does not waive the request requirement.
- **Port:** preserves the same carrier/version/member order and selected
  version-set ownership with native methods or functions. It admits one parsed
  request for later immutable snapshot and issuer processing; it does not use
  this early guard to waive later verification or authorization.

## Chain-derived period capability storage

For a window containing `N` periods, expanding one member (chain keys
Section 6.6) costs at most `N - 1` Step and `N` Leaf derivations, `2N - 1`
HKDF invocations. Repeating the walk from the
cutoff for every period key gives the same keys at quadratic cost; walk once.
Full expansion of one message costs at most
`maxChainMembersPerMessage × (2N - 1)` HKDF invocations, 9,200 at the v1
ceilings. The [chain-key bounds](../docs/spec-profile--chain-keys.md#221-protocol-maxima)
remain the protocol owner; this describes the reference's expansion work.

The reference `ChainKeyCache` keeps positioned chains under their admitted
construction/geometry/window/cutoff partition, but its bounded derived-period
view uses ordinary publisher, period profile, access group and coordinate
boundaries with any configured issuer partition. `periodCandidates(group, t,
context)` exposes that ordinary view without geometry. The injected chain
profile composes it with actual derivation; a later period-only render can use
a matching derived period key without chain metadata. Ordinary non-chain
clients need no new cache method or chain support.

The reference resolver composes the normal period cache and derived-period
view under one selected ordinary trial ceiling of four per wrap and a shared finite
64-trial budget per access group. The two physical views each retain at most four
ordinary rivals per coordinate (eight combined); merging selects at most four
for a wrap. The optional profile method
`periodCacheFor({cache})` exposes the ordinary derived-period view. Reference
`PeriodKeyCache.candidateEntriesAt` and
`ChainKeyCache.periodCandidateEntries` return `{key,pending,order}` records;
`order` uses the common realm-local filing sequence. Persisted orders advance
that sequence as before; it supplies no cross-tab atomicity or new reconciliation
policy. Operation-private candidates lead retained candidates, then newest
filing leads; repeated bytes/identical handles spend one trial. Actual chain
rivals additionally keep their existing finite bound and share the same trial
budget. When the profile exposes its ordinary view, the chain source reads
`candidates(...,{chainOnly:true})` so an ordinary
period memo excluded by the combined ceiling cannot re-enter as a chain trial.
A memo suppresses the walk of its retained chain source only when that memo is
offered for the same wrap: the ordinary source already tried its bytes, or the
read itself returns it. The chain source passes the bytes already tried as the
optional `triedPeriodKeys` array in the `candidates` context; the cache reads
it only and compares by bytes, and `triedPeriodKeys(budget, entry)` in
`core-client/periodKeyCandidateSource.js` produces it. A correct memo the
four-candidate ceiling left out therefore leaves its chain walk available
inside the existing chain rival bound and 64-trial budget. This is reference
availability under local caps, not a universal derivation or cache guarantee.
Legacy
chain adapters without a separately exposed ordinary view keep their previous
geometry-qualified `candidates` behavior; ports allowing chain-derived period keys to open later renders without
chain geometry must
expose the geometry-free period view. Only selected base-period or chain
suppliers for that family enter ordinary issuer eligibility; actual chain lookup uses chain suppliers only.

A content-group caller may pass `chainCandidateBudget: { remaining: number }`
in the `ChainKeyCache.candidates(group, t, context)` context. This is one trusted,
mutable, nonnegative safe-integer allowance shared across an item's routes and
cache sources. The cache decrements it before each selected chain derivation,
including derivations whose result is later deduplicated; zero performs no chain
derivation. Without this member, the ordinary four-chain default remains.
Content-groups also spends ordinary period candidates from that same item
allowance. Injected content-group chain-cache ports must honor and mutate the
shared counter. Retention limits and candidate-work limits remain independent;
raising retention does not override an intentionally smaller work allowance.

Existing non-chain injectable caches still need only `put`, `candidatesAt` and
`attempted`. Selecting two ordinary views requires both to expose
`candidateEntriesAt` at construction, even when one is empty. Missing methods
produce `bad_config` before cache reads. Method presence admits the adapter
shape; each custom adapter must supply comparable filing metadata with the
private-first/newest-filed meaning above. A lone legacy view preserves its
existing returned order and needs no new constructor method. These metadata methods do not change
which duplicate admission counts as a new filing.

A chain cache may expose `promote({lease})`, returning a joinable promise that retains operation-private material while
filing reusable material. `attempted({lease})` joins promotion and releases the
private copy. After successful promotion the resolver waits for captured
readers, ends the application's association, then releases private copies. A
failed promotion ends that association for new readers immediately; captured
readers still drain before terminal release, as the recovery contract below
requires. Custom chain caches exposing only `attempted` retain their existing
contract and must preserve first-use availability themselves. Storage/derivation
faults propagate; they are not candidate authentication misses. Retain/expand,
persistence and numeric retention capacity remain local choices. Reusable
capacity eviction cannot erase an obtaining operation's only applicable key
before that operation has attempted its items.

## Endpoint response agreement and client composition

`createDeliveryClient` checks the selected route after request projection and
response association, before calling transport. Endpoint permission to return
direct keys is separate from the resolver's ability to admit them and from key
custody. A contradictory composition fails `bad_config`; the client does not
enable broader response admission or raw-key retention automatically.

The two permissions have two owners:

- `acceptDirectResponse` is the selected route's agreement that its endpoint
  may answer in direct representation. The host sets it on the delivery client
  or browser client, or per route record in `unlockRoutes`.
  `ResponseAssociation` fixes it with the request before transport. Left out,
  it is `true` for a request without `clientPublicKey` and `false` for a
  request that offers a client-bound method.
- `acceptDirectFallback` is the resolver's admission of direct key entries.
  `persistRawPeriodKeys` separately lets raw period or chain keys from such a
  response enter the caches.

The response forms differ:

- A wholly direct response carries no `transport` and only string key entries.
  The client admits it only under the route's `acceptDirectResponse`. Without
  that agreement, any key section, base or extension, refuses the whole
  response as `invalid_transport` before any entry is opened or filed.
- One response never mixes forms. Direct string entries beside wrapped entries,
  or a direct entry beside `transport`, refuse the whole response as
  `invalid_transport`. A direct fallback is a whole response.

The pre-transport checks:

- A route that permits direct output requires effective `acceptDirectFallback`.
- When that projected request carries period-key or chain-key family entries,
  permitting direct output also requires effective `persistRawPeriodKeys`. A
  direct content-key-only request does not require reusable raw-key custody.
- A route that refuses direct output needs a client-bound method offer when
  the projected request contains eligible key coordinates. A strict route with
  a usable offer remains supported.

Without a client-bound capability, the ordinary defaults accept direct output
and raw reusable keys. Selecting a client-bound capability defaults both
permissions off. A deployment accepting direct fallback must explicitly select
the matching admission and, for reusable raw keys, custody. These are reference
composition requirements for the selected delivery forms; no additional wire
field or baseline client-bound support is required. Ports must preserve the
pre-transport refusal and the independent endpoint-agreement boundary.

## Extension recovery sources and response sections

`composeClient` and `createDeliveryClient` take two lists of extension owners,
`recoverySources` and `responseSections`, and hand both to the resolver
factory. Base registers none. `createBrowserClient` refuses an owner in either
list that has no `clearReaderContext`.

- A recovery source yields candidate item content keys from material it
  holds: `candidates(context)` is an async iterable of `{ contentKey, origin? }`
  and `maxTrialsPerItem` bounds its trials for one item. The resolver tries
  sources in order after the cached wrap paths, on authenticated calls only,
  authenticates each candidate against the item's ciphertext and holds the
  first that opens. The source calls `context.check()` after every await.
- A response-section consumer owns one top-level response member, `name`, and
  never a base member (`keys`, `transport`, `errors`, `notDelivered`,
  `periodGeometry`). `keyValues(section)` lists its key values synchronously,
  so the response-wide representation rules count them with the base
  sections. `admit(section, context)` opens keys through `context.openKey`,
  files what it accepts and answers `{ accepted, issues }`. It may add
  `errors`, one `{ error: "key_retired", ...coordinate }` record per own
  coordinate the issuer reported retired, with string coordinate members only.
  The resolver refuses any other record with `bad_config`, freezes each, adds
  `consumer: name` and appends it to the application's `errors` after the core
  `{ coordinate, error }` entries.
- `context.holdContentKey(contentName, key)` holds one item content key the
  consumer admitted, as base holds a `keys.contentKeys` entry: a later
  `contentKeyFor` finds it, and reader reset drops it. It takes only an item
  the page carries and either an AES-GCM `decrypt` handle or 16 key bytes;
  anything else is `bad_config`. It throws once the reader context retired.
- Owners join completion and reset through optional `promote`, `attempted` and
  `clearReaderContext`.

Plain `open()` recovers through these sources. A client composed with at least
one recovery source opens through authenticated selection in `open()` and
`openLocal()`, as `unlockRoutes` does. Example: a connector-only item
`bodytext` whose chain key sits in the content-group cache. `openLocal("bodytext")`
derives candidates, and the first that authenticates opens the item without a
request. With nothing held, `open("bodytext")` asks the selected issuer once and
selects under that response's lease, so a key the response files for reuse also
opens this item. A client without recovery sources keeps the held-key-first
path unchanged. A port keeps that split: a derived candidate is never used
before it authenticates.

Content-group chain responses put the delivered key value directly at
`contentGroups.chainKeys.<contentName>.<group>.<cutoffLabel>`, as period responses
do. The response descriptor keeps depth 3 and `contentGroupChainKey` with no
`leafKey`. Derive the internal position from the cutoff and captured request
geometry; retain it in staged capabilities and caches. No wire position or outer
key wrapper is interpreted. Both transport classification and key wrapping walk
the direct value under that same descriptor.

The chain generation API lives in
`extensions/chain-keys/core-shared--publisher-issuer/periodFamilyGeneration.js`;
its publisher adapter `periodKeySupplyFor` lives separately in
`extensions/chain-keys/core-publisher/periodKeySupplyFor.js`. The generator's
inputs, derived bytes and retained-generation behavior are unchanged by this
source split. A client-only slice imports neither implementation.

Content-group role entries use stock chain construction through their required
implementation dependency. Omitted `chain` configuration selects those stock
operations; explicit overrides remain for useful substitution/instrumentation.
The client still requires both cache factories, preserving host-controlled
storage, clocks and lifecycle. No new wire capability is selected by these
imports, and base role entries retain their existing injection seams.

`extensions/content-groups/referenceProfile.js` exports
`contentGroupsProfile`, one frozen object of the extension's role entries:
`publisherContribution`, `issuerContribution`, `client`, `responseSections`,
`kindDescriptors`, `keyDeliveryMembers(composedKinds)` and
`capabilityOptions(composedKinds)`. The client bundle's `composeOptions`
holds `requestBuilderFactory`, `recoverySources` and `responseSections`, ready
to spread into the composition options. The two kind members refuse with
`bad_config` a set that is not frozen or lacks either content-group kind; the
host settles it first with its transport's `settleKindDescriptors`. The
client passes `maxResponseMembers` and `maxWindowsPerGroup` to its
`ChainKeyCache` as `maxMembersPerMessage` and `maxMembersPerFamily`; a port's
chain cache takes these per-answer bounds from the composing profile, not the
chain-keys defaults of 16 and 2. The issuer and publisher zero the seed
handles' owned buffers when the exchange or publish ends and release the local
handles. A chain port owns cleanup of any further copies it makes; the stock
port releases its generation but does not explicitly overwrite its internal
copy. Do not infer complete memory erasure from the owned-buffer tests. The
retired publisher-wide entries have no compatibility mode, and a port drops
them: `publish`, `buildRequest`, `unlock`, `createClient`, `windowSeed`,
`sealWindowSeed`, `openWindowSeed`, `seedAAD`, `inspectMirrors`, `inspectPage`
and the helpers only they used.

## Response-private and wrapped capability admission

A storage-backed byte-string `PeriodKeyCache` retains an admitted opaque handle
under its obtaining lease without exporting or serializing it. Its trusted
caller supplies already-admitted period keys; the cache is a storage seam,
not a selected response-profile validator, and its lease is operation context,
not an authorization credential. It releases the
private handle when that operation completes; reusable opaque storage is an
optional adapter. An unleased opaque put into byte storage still fails
`bad_key`, and byte-storage faults remain visible. Wrapped content/period opener
outputs are non-extractable AES-128-GCM handles; extractable handles or raw bytes
are refused per entry. Direct byte delivery and chain-key byte recovery remain
separate admitted forms. A base-presented period coordinate is admissible even
when the selected extension answers false; an unsolicited derived coordinate
still requires its positive admission. Invalid wrap labels are skipped before
cache reads, without catching cache faults.

A storage-backed `PeriodKeyCache` instance runs its store read, change and
write-back one operation at a time, so two concurrent puts from one tab into one
family keep both coordinates and a storage fault still rejects its own call.
Two instances over one store can still lose a write; only a host store with an
atomic update closes that. A storage-backed cache with no `namespace` skips
every storage key whose remainder after `dca.periodKeys.` starts with a
base64url token and `.`, which is the shape of a namespaced client's key, and
refuses to file a family of that shape; an in-memory cache has no scan to
protect and files it. A publisher origin reaches `:` before any `.`, so a family
filed under one never has it.

`applyResponse` checks a `notDelivered` family against the response's key
entries and admitted errors only. A family has a key entry only when its key
section and its family are non-array objects and the family has an own
member; an empty, array or scalar container conflicts with nothing, and a
nonempty family conflicts before its labels or leaves are admitted
(response binding Section 3). Only an admitted period-coordinate error
conflicts with a family; a malformed, unsolicited or wrongly shaped error is
an issue of its own and never refuses the report. When the client-bound
transport is unusable, such as a missing, wrong or unknown method or malformed
transport members, every wrapped key entry is rejected with
`invalid_transport` and the otherwise admitted report and coordinate errors
stay. Error shape, request association and key/error conflict admission still
apply; an unusable transport neither authorizes a new error coordinate nor
removes a conflicting key entry. Nothing is retried as direct bytes. An
individual `unwrap_failed` entry also keeps the
report. Mixed direct and wrapped representations, a direct key-bearing answer
from a strict endpoint, or an unassociated response refuse the whole response;
a whole-response refusal admits no report. An invalid `notDelivered` report
instead yields a `malformed_response` issue scoped to `notDelivered`, no admitted
report and no stock period/chain retention from that response. Independent
item grants and unrelated extension sections still apply after representation
admission. Classify original entries before suppressing family grants. The walk
authenticates that item progress and gives the invalid report no conditional
retry or denial-cache meaning. Previously retained keys stay unchanged.
The mixed check classifies every entry in supported, admitted key-map containers
by JSON type before coordinate admission: a string is direct and a non-null,
non-array object is wrapped, so `{}` or `{"key": 7}` beside a string refuses
the response even at an unsolicited coordinate. An array, `null`, number or
boolean establishes no representation and fails only at its own entry.
Unsupported sections are discarded. This scan neither opens nor retains keys;
only entries that subsequently pass coordinate, request-association and geometry
admission can cause opener acquisition.

Chain response interpretation uses the immutable associated request's complete
`periodGeometry`, not a response echo. The portable helper is
`chainKeyResponseInput(response, request)`. Content-groups uses
`admitContentGroupResponse(section, request, options)`; its staged result includes
checked, frozen `periodGeometry`. Capture it before asynchronous opening and use
that same pair for retention. Retained chain records keep their full geometry
and construction identity; ordinary period-key records remain label-based.

Injected transports classify explicit `code` tags without requiring the local
DcaError class: `offline`, `timeout` and `no_route` describe locally attributable
outages; `timeout` is only for a deadline known to fire before send. Fetch
TypeError, opaqueredirect and a post-send deadline must use
`indeterminate_transport`, because the HTTP decision is unknown. That tag does not
permit conditional fallback; a separately selected independent route may run.
Unexpected untagged programming exceptions propagate and end the route walk.
An independent route can still run after a tagged indeterminate outcome.
`open()` maps every keyless result to `no_key`; inspect the `unlock()` attempt
when the host needs to tell denial from outage.

A client-bound profile supplied to `clientBoundKeyCapability` implements
synchronous `publicKeyForOffer(publicKey)`. The capability calls it once during
construction after common private-key safety checks and the selected profile's
key-pair validation, validates and recursively snapshots the returned
JSON-compatible public-JWK record, and captures a
detached offer for `capability.publicKey`. Reference ECDH-P256 emits only `kty`,
`crv`, `x`, and `y`, with canonical 32-byte coordinates; this checks wire shape
and encoding, not mathematical point validity or public/private pair equivalence.
Reference RSA-OAEP preserves its admitted compatible RSA JWK metadata. The
issuer-only seal profile contract is separate and does not require this client
offer hook. Custom client profiles own their synchronous public-offer
projection/schema; arbitrary METHOD values remain supported.

RSA-OAEP client opening checks that the canonical ciphertext decodes to exactly
`ceil(privateKey.algorithm.modulusLength / 8)` bytes before calling `unwrapKey`
or `decrypt`. A width mismatch is reported as `unwrap_failed` for that delivered
entry and does not trigger another key kind or method attempt.

An issuer `contentKeySource` receives an opener that separates authorization
from the envelope's BIND coordinate. For a direct content-key envelope, the
`contentName` in the binding coordinate names the granted item; the reference
normalizes that direct coordinate before opening. For an auxiliary envelope,
such as a period-key envelope used to reconstruct an already-granted item key,
the source passes the envelope's native binding coordinate and separately
passes `forContentName`, the final-granted item it serves. The engine checks
that name before opening and preserves the auxiliary coordinate unchanged.
Missing or denied item context fails `bad_config`; a direct content binding
whose name disagrees with `forContentName` also fails. Those are the engine's
common checks, together with registration-scoped key lookup, the verified
render, no source under a retired key and the bytes/miss/error answer shape.
The source is trusted issuer code. It selects auxiliary inputs only from
admitted presented coordinates or issuer-held material scoped to the verified
registration, and authorizes their use for the granted item under the selected
mechanism before requesting an opening. For each auxiliary envelope it supplies
the envelope's native kind and coordinate; the opener rebuilds BIND from that
trusted source context and the verified render, never from the authorized
result coordinate or caller-provided BIND. The source establishes, through the
mechanism's authenticated binding or trusted issuer-held information, that
returned bytes are the content key of the granted item and render. An unsigned
candidate label or a served content name alone establishes neither permission
nor result provenance. The engine does not validate auxiliary selection or
returned-key provenance; passing a granted `forContentName` proves neither.
An item grant never authorizes returning auxiliary period or chain bytes, so
the source keeps what it opens and returns only the item key. The normative
source contract remains in
[core Section 6.3](../docs/spec--core-protocol.md#63-opening-key-scope-and-bind).
This is a trust boundary for correct issuer code, not a sandbox for a hostile
source. The opening private key remains inside the engine, and the callback
remains scoped to this registration, verified render and unlock. The
content-key seal omission prototype in
`extensions/content-key-seal-omission/` shows one such source; it is not an
adopted profile.

The engine tries the ordinary content-key seal first. It selects the opaque
scope and calls `contentKeys(unlock)` only after an authorized ordinary seal
fails while the opening key is active, and does so once per unlock; the
returned lookup is asked about each failed granted name. A successful ordinary
open and a retired opening key do not start this fallback. Hosts that need
request-lifecycle setup or metering should place that work in their own request
lifecycle.

### Unicode resource identifiers and content AAD

`isUnicodeScalarString` checks a string without rewriting it. Resource identifiers
must be nonempty scalar strings, used as written; `|` is an ordinary character in
one, because no transcript or BIND grammar joins a resourceId. Verified issuer claims refuse unpaired surrogates as a
whole-request `bad_jwt`. Content AAD admits only the canonical render ID and
item name. Handling admission separately refuses unpaired surrogates in
`contentType` or an encoding as item-local `bad_page` before a representation
opener resolves its key. Supplementary scalar characters and
literal U+FFFD remain valid and unchanged. This is not a global restriction on
arbitrary application JSON.

### Derived content AAD

- **Reference:** `core-shared--client-publisher/contentAad.js` exports
  `contentAad({renderId, contentName})`, returning `LP(renderId) ||
  LP(contentName)` or `null` for non-scalar or excessive inputs. Callers
  separately admit canonical render ID and item-name grammar. `LP` uses a four-byte
  unsigned big-endian UTF-8 byte length followed by the UTF-8 bytes, without
  normalization. `CONTENT_AAD_LIMITS` is `{maxValueBytes: 65536}`, a local
  allocation limit rather than a wire limit. The former domain constant and
  `jwtSigningInput` exports are removed. There is no hash, label or nonce
  helper added to generic AEAD. Publisher failures are `bad_config`; client
  admission failures are item-local `bad_page`.
- **Capture:** `DcaData#contentItemFor(contentName)` returns a frozen view
  `{contentName, contentType, contentEncodings, contentAad}`, or `null` when
  the delivery declares no such item. It decodes and admits the delivery's
  `resourceJWT` render ID; the diagnostic mirror supplies no input. The
  reference refuses tokens longer than 1 MiB + 2 characters before splitting,
  decoding or parsing them, retaining its local input-resource bound.
  `ContentRepresentationOpener#open` and `preflight` read only the captured
  view. `openContent(contentKey, contentName, ciphertext, contentAad)` takes
  the view's AAD bytes and uses twelve zero nonce bytes internally at the
  content boundary. Capture available ciphertext before key acquisition too.
  Handoff uses captured type, encoding list and admitted description, with no
  mutable record reread after an await. Carried item `aad` and `nonce` members
  are ignored whatever their types and select no fallback.
- **Port:** preserve the two-field transcript, fresh independent 16-byte key
  used for exactly one encryption, implicit twelve-zero-byte nonce and 16-byte
  tag. Use finite limits before allocation. Capture before the first await and
  preserve handling admission, decoder selection and authenticate-before-decode
  order. Render/name relabeling fails even after cached period-key recovery;
  type, encodings and other token claims are outside the tag and can change
  processing without failing it. Decoding the render ID verifies no signature;
  issuer verification and authorization remain mandatory on unlock. Cached
  opening need not contact the issuer. This mandatory baseline procedure has
  no toggle or legacy retry; old random-content-nonce readers/deliveries need
  a separately selected old reader. Wrap and envelope nonces are unchanged.

### Recipient-grant bearer admission

The optional recipient-grant composition validates references using RFC6750
Section2.1 b64token. Its producer emits `Bearer` followed by one SP; its consumer
accepts scheme case variations and one or more SP characters. The reference
remains opaque and case-sensitive, including allowed trailing `=`; it is not
base64-decoded. Duplicate/combined credentials, auth parameters and embedded
whitespace are refused before grant lookup. Trusted endpoint selection precedes
credential lookup; credential-store probing does not select a binding.

Opening keypairs must be dedicated to DCA sealed envelopes. Provisioning code
must not expose the same private key to other protocol operations. A library
cannot establish that operational exclusivity by inspecting the supplied key.

### Publisher supply generation and namespace

The reference publisher intersects a standing per-issuer entrustment with each
render's authored names and groups. A standing entrustment may name items or
groups absent from one render without invalidating that render. Once formed,
a per-render selection that names an absent content name or access group is
refused as `bad_config`. Local configuration syntax is not prescribed by DCA
core; the per-delivery selection and absent-selection rejection duties remain
in [core Section 2.1](../docs/spec--core-protocol.md#21-publisher).

An issuer supply plan's optional `periodKeySourceTs` maps supplied access
groups to explicit subsets of the render's planned period-key labels. It
selects ordinary sealed period-key sources only, not item wraps, chain sources,
or reader entitlement. Omission for a group retains all its planned ordinary
sources. A selector requires that group's `period-keys` delivery mode;
unknown groups, duplicate or malformed labels and labels outside the planned
wrap coordinates are configuration failures.

The supply planner's `render.now` is a defensive Date copy of the publisher's
already-captured render instant. A planner selecting T1 uses that instant and
the configured geometry; it does not reread the clock. Mutating its copy must
not change another issuer's planning instant or the sealed render's labels.

For an extension supply with `familyPlan`, the fourth argument
`chainRequested` continues to report whether any selected issuer requests
chain material for the group, including dual routes. The supplier plans wrap
coordinates and chain sources independently. Sealer checks actual usable
opening routes; requesting a chain does not promise that it reaches every
overlap wrap. Each supplied chain label is a real UTC instant on the plan
geometry's grid, and a plan supplies at most one position per stationary
window, because an issuer refuses a family whose members share one. The Sealer
refuses a plan that breaks either rule before acquiring key material, whether
or not an issuer selects chain delivery for that group.

Before acquiring key material, drawing entropy or sealing, the publisher
checks every item has a complete issuer route: a supplied item content key,
or at least one offered period-key wrap reachable through that issuer's selected
ordinary or chain sources. Every `reachableContentNames` promise independently
requires a matching wrap through that issuer's supplied groups; another
issuer's source or an item-key alternative does not fulfil that group-route
promise. An overlap wrap may remain cached-only. An empty ordinary selection
is valid when the resulting item routes and explicit group-route promises
remain complete. Existing delivery modes keep their meaning: `chain-keys`
alone never silently adds ordinary period-key supply.

The reference `periodFamilySupply` uses `chainItemSlots` (a positive safe integer,
default one) to select the number of item-wrap periods only when chain supply is
selected for that group. Ordinary plans retain `period.slots`. `chainWindows`
independently selects publisher-to-issuer windows; it does not add item wraps.
An ordinary fallback sharing the group must supply a matching authored period;
requesting only a later period cannot open a render-period-only wrap.

For rollover, one current-window chain source and an ordinary next-window
overlap period key are sufficient where those selections cover the plan.
The next window's chain key is not supplied merely because its period key
appears in a wrap. Both period keys come from the same selected construction
generation, and the overlap key's bytes stay the same when that coordinate
becomes current. Private derivation of a next-window key does not imply
transmitting its chain capability.

A PeriodKeySupply, including a derive-only provider, serves every acquisition for
one access-group family/render from one immutable generation. Capture a rotating
provider's generation before any await. At every shared period coordinate, its
periodKeyAt must equal the period key derived there from the selected capability;
a chain capability's raw bytes need not equal that period key. Answers match the requested
publisher namespace, family, label and construction. The sealer checks structural
width, not cryptographic equivalence of separate provider answers. Content wraps
do not promise a new acquisition route; only configured issuer routes do.

periodFamilyGeneration consumes a secret already provisioned for one publisher
namespace. It neither scopes an unseparated master secret using an origin nor
adds a publisher field to Root. A caller with a master secret must supply its own
properly separated secret; ordinary provisioning uses independent secrets.

Trusted selected content/period sources admit their inputs and name metadata
before policy and opening. Names they present must follow the corresponding
contentName/accessGroup grammar; malformed trusted source output is bad_config,
not a reader-controlled grant. Grammar validity is not proof of entitlement.

### Terminal recovery after response promotion failure

Response completion attempts promotion once. A failure ends the application
association for new operations immediately; already captured readers retain their
obtaining lease until they finish. Both period and chain cache cleanup owners run
after the drain even when either fails. An operation's own fault wins over a
completion fault; otherwise the first completion fault is visible to joiners.

Terminal cleanup preserves already written reusable keys and held item keys,
clears private pending grants and promotion bookkeeping, and does not retry or
roll back partial retention. Completed chain leases cannot accept more grants.
A later call with the old application follows ordinary retained-key lookup or
misses; it does not replay that completion's rejection. Existing item-key
retention differences between resolve operations and plain contentKeyFor remain.

### Issuer engine versus admitted endpoint calls

`createIssuerCore` returns `{engine, processor, endpoint}` for compositions at
different boundaries. For an incoming serialized unlock document, use
`endpoint.handleDocument`; it admits through the configured processor before
engine processing. The processor owns body/entry limits, selected extension
admission, ordinary period-input activation (`periodKeyInput`, default false)
and period-label validation. `createBrowserIssuer` additionally composes trusted
HTTP/Origin and host caller admission; the document endpoint alone does not.

The exposed `engine.unlock` is a lower-level composition seam. A direct call
skips processor admission, including the processor's period-input opt-in. It is
not an equivalent public request boundary: its caller must perform the required
admission and pass the intended request/registration/policy invocation. The
engine still verifies resource claims, checks operating issuer scope, applies
policy, clamps grants to presented coordinates and opens only permitted values.
Presentation alone grants nothing. This seam does not create a new opt-in or
authorization control and does not make processor activation an entitlement.

### Issuer policy labels and operating-name scope

Ordinary issuer policy receives `requested.periodCoordinates`, a map from each
access group to the admitted labels in that request's ordinary sealed period-key
section. Extension family presence does not create ordinary labels. An ordinary
`periodGrant` names `{accessGroup, periods:[t,...]}`. The engine validates and
deduplicates these labels and intersects them with presented coordinates before
opening. Duplicate ordinary grants combine their explicit labels, not counts.
A well-formed unpresented label confers no output; malformed policy is bad_policy.
The former count-prefix ordinary API has no compatibility translation.

An independent selected chain grant instead carries `futurePeriodCount` and a
trusted `authorizePeriod(t)` decision. Its supplied chain BIND coordinate differs
from the periods it can derive. Do not mix the grant forms or treat a future count
as article permission. Ordinary selected routes and their returned period labels
remain limited to explicitly authorized ordinary coordinates.

IssuerEngine configuration requires a nonempty grammar-valid
`operatingIssuerNames` list. The ordinary endpoint configures one name; deliberate
shared authority may configure several. The engine's synchronous pure
`checkOperatingIssuerName(request)` guard enforces that trusted scope without
policy or private-key lookup. IssuerProcessor requires this guard from every
injected engine and calls it during admission, before a host may consult its
response cache. Engine unlock independently enforces the same scope for direct
callers. A selected custom engine owns the same guard duty and its policy/key-view
agreement; a method's presence does not prove its implementation is correct.

createIssuerCore forwards operating names when it constructs the ordinary engine.
An injected complete engine owns its scope itself. Opening-key lookup remains
within the authenticated publisher registration. A global unsigned-name key map
cannot combine another authority's key with this endpoint's weaker policy.

The retained omission prototype's `sourceGrants` uses explicit auxiliary labels,
clamped to its admitted sealed entries and forwarded candidates. Absent sourceGrants
may use validated ordinary grant labels before ordinary delivery's presentation
clamp; explicit empty authorizes none, malformed present input fails. Auxiliary
use remains distinct from item permission and reusable-key delivery. No chain
callback is implicitly converted to auxiliary labels, and this API reconciliation
does not adopt the omission prototype.

## Optional browser-integration contract

The [browser-integration proposal](../docs/spec-proposal--browser-integration.md)
defines a client-side composed handoff after opening and selected decoding.
Direct references and bytes are the ordinary setup; registry discovery and
context-source coordination are separately selected optional interfaces. The
account companion is separately selected. Baseline-only or server implementations
acquire no new interface requirement.

A connection retains its captured delivery, logical context and output ownership.
Its eligibility callback must not follow a replaceable current operation/context
reference. Retire and reconnect when that ownership changes; the provider and
host consumer may remain the same objects. Invocations preserve their own guard
lifetime and perform application mutations synchronously within the admitted
effect callback. Unknown suspends affected work; only positive confirmation of
unchanged association, revision, host generation and output lifetime permits
resumption. Retirement, disposal and stale outcomes remain final.

`experiments/browser-integration/implementation/` remains prototype reference
evidence for those interfaces. Proposal evaluation does not turn that directory
into a production package or a new public entrypoint. A standalone component
can describe a named interface/major; candidate browser-profile evidence covers
the composed integration and its configured host duties. No current DCA profile
conformance claim is established by this proposal. Neither source reuse nor
the experiment tests alone establish complete profile conformance, deployed
vendor compatibility or arbitrary asynchronous callback replacement safety.

### Expected transport failures

A composed `transport.post` must classify expected operational exchange failures.
An ordinary Fetch rejection must not escape as an unclassified exception and
cancel a valid configured independent route. Local configuration and programming
exceptions still propagate. An unobserved response does not authorize a
conditional fallback; explicit cancellation of the entire acquisition stops it.

`adapter-client/fetchTransport.js` provides `createFetchTransport({ fetch,
credentials, maxResponseBytes, signal })`. It defaults to omitted credentials,
manual redirects and no caching. Its signal cancels the entire acquisition;
a request-scoped abort from the supplied Fetch implementation remains
indeterminate when that shared signal is not aborted. Known non-200 status is
returned without reading diagnostic bodies. Successful bodies use strict UTF-8
and tolerate exactly one initial BOM. The configurable 1 MiB response bound is
a reference resource setting, not a DCA wire ceiling. Cookie sessions explicitly
select `credentials: "include"`; endpoints independently allow credentials.

## Reference request budgets

`core-shared/requestLimits.js` defines the reference deployment defaults:
`maxBodyBytes: 65536`, `maxEntries: 16`, and `maxEntriesPerGroup: 4`.
These are trusted host configuration, not protocol-wide interoperability floors.
The issuer processor counts raw sealed entries before signature verification,
policy or private-key work. Item content-key entries count toward the total;
period-key and chain-key entries share each group's limit. Oversized requests
are refused as `too_many_entries`; the body-byte admission has its own limit.
The chain profile's structural maxima do not override a smaller endpoint budget.

Publisher issuer configuration carries the matching `limits` and any required
additional request-byte allowance. `core-publisher/issuerRequestBudget.js`
checks the widest request a composed client sends to each issuer: the base
members, the block's `envelope` selector, and the members each selected item
preparation's `requestRelay(delivery, issuerName)` projects from the assembled
delivery. The content-groups preparation answers with the projection the
client's request builder uses, so no second request builder can drift.
`clientRequestExtraBytes` bounds client-added members such as a public key or
local narrowing. A deployment must align endpoint limits with its authored
memberships, period overlap and chain windows. These configuration limits
create no new wire members. Admission budgets are independent of authorized
grant counts and decoder output budgets. The content-groups publisher
separately counts the response members its promised routes need, one per
connector item at each issuer holding the render-window seed, against
`maxResponseMembers`; the groups and windows a request may ask are choices,
not promises, and are not counted.

## Browser denied-unlock scheduling

`createBrowserClient` installs `DeniedUnlockCache` unless `denialCache: false` is
selected. The default is ten minutes, 256 hints and in-memory storage. An injected
instance accepts `context`, `durationMs`, epoch-millisecond `now`, optional standard
`Storage`, `namespace` and `maxEntries`. `setContext(nonemptyString)` invalidates
hints and pending recordings; `invalidate()` does the same within a context.
Storage is optional scheduling persistence and may fail without failing access.
`denyContext({publisherOrigin,issuerName,unlockUrl})` is an asynchronous explicit
host declaration of no access for that route in the current context. It suppresses
different renders too, using the same configured TTL and bounded store. Only the
trusted host calls it; an individual response never implies it. Invalidation while
that declaration is pending prevents it from being filed after the context changes.

Browser cache injection is structural: `capture(input)` returns a promise of an
opaque attempt record with `retryAt` null or an epoch-millisecond deadline;
`deny(attempt)` records only an integration-established exact denial. The browser
also requires `denyContext(scope)`, `invalidate()` and `setContext(context)`. The
delivery entry needs only `capture` and `deny`. Custom implementations need no
subclass and preserve these scope, lifecycle and no-authority semantics.

The browser exposes its instance as `client.denialCache` (null when disabled).
The carrier-independent delivery entry accepts this collaborator only when
explicitly injected. Its default behavior is unchanged. An equivalent suppressed
unlock returns `{skipped:"cached-denial",retryAt,application:null}`, with an epoch-
millisecond deadline and no HTTP status or body. Route walks record outcome
`cached-denial` without a status and do not activate conditional fallback.

Automatic recording requires an admitted result with zero accepted keys, errors
or issues, no presented item-content-key coordinate, and an explicit denied report
for every presented ordinary period/chain family. Unknown sealed sections prevent
this classification. No other empty or partial result implies denial. Context,
trusted publisher origin, issuer name, endpoint and canonicalized requested
material partition hints; the ephemeral `clientPublicKey` offer does not. A changed
render or requested coordinate is a different request. Ports may use a native
stable fingerprint; fingerprint bytes are local storage detail, not DCA wire.

The reference persists an invalidation revision with the bounded snapshot. A live
instance reads a successful storage snapshot as authoritative, so an entry evicted
by another instance cannot reappear from stale memory. After any storage read/write fault it stops using persistence for that instance
and retains local memory only, so a later stale snapshot cannot undo local
invalidation. The host must still invalidate each live context instance when
storage cannot communicate a lifecycle change. This is best-effort scheduling storage, not an atomic cross-tab
state store or authorization boundary.

## Browser reader-context lifecycle

The reference client exposes two local operations returning `Promise<void>`.
`clearAccessDecisions()` invalidates the denial owner's hints and pending
recordings while preserving delivered capabilities, transport configuration and
backoff. It neither requests keys nor prevents an already pending valid grant.
`clearReaderContext()` includes that invalidation and retires item/period/chain
keys, derived memoization, pending promotions and response/custody sessions.
This creates no wire member, failure status or revocation mechanism.

Full reset synchronously retires the old generation on invocation. Each retaining
owner does the same before returning its cleanup promise. Every selected owner
is invoked before awaiting cleanup results, including when another owner throws.
Old operations must carry their original generation through nested calls and
check it after asynchronous reads, opening, derivation, storage, decoding and
before admission, promotion, fallback or positive result delivery. Old completion
bookkeeping must still settle; do not strand readers by deleting their waiters.
An arbitrary old network or crypto promise does not hold reset completion hostage.
Retirement checks reject with local `context_retired`, including for work
started during cleanup. An independently failing operation may retain its own
error; no old positive result may escape.

Storage cleanup drains issued store operations, including reads, and prevents old reads
or reconciliation from restoring a removed namespace. A never-settling store
operation holds reset pending and blocks successor work; arbitrary old network
or cryptographic promises do not. Successful completion
permits new work. A key/resolver cleanup failure rejects the operation and leaves the owner
and enclosing client detached from access work; repeated calls retain the
failure rather than report success after discarding a storage reference.
A decision-only cleanup failure during full reset instead rejects local
`access_decisions_clear_failed` with the original thrown value as `cause`,
including null or undefined. It does not latch the key generation: access work
may continue after all cleanups settle, while the host repairs or replaces the
decision owner before relying on cleared scheduling. Full success still means
all selected cleanup completed; custom decision-hook errors are never suppressed.
Concurrent resets share the complete public result, including advisory failures.
The stock denial owner retires local hints but retains unresolved persistence
faults; replacing only the outer client while reusing that owner does not repair
it. Use a new denial owner and successor context identifier when appropriate.
Direct `clearAccessDecisions()` preserves its original rejection behavior, and
legacy scheduling invalidation may remain best-effort.

Browser selection requires structural recursive `clearReaderContext()` support
from a custom resolver and its period/chain caches. Custom denial owners expose
`clearAccessDecisions()` or an invalidation fallback with equivalent pending-work
and failure semantics. Configured recipient wrapping keys and stateless profiles
remain configuration. A custom custody capability or chain profile retaining
extra delivered state implements the reset hook itself; no framework registration
is required. Lower-level delivery construction preserves its existing optional
collaborators; requesting full reset requires their applicable reset contract.
If key/resolver reset support is missing, full reset rejects `bad_config` after retirement and
detaches access work. A host may call a stock resolver's
`assertReaderContextReset()` during construction. Browser construction checks
its publicly composed caches even through a wrapper; custom resolvers keep the
recursive duty for hidden retaining owners without a mandatory assertion hook.

The host controls authentication changes, presentation eligibility, other live
instances and shared namespaces. Local reset cannot revoke copied capabilities
or plaintext, erase caller-owned keys, or guarantee cross-instance storage
coordination. Discard sibling cache instances over a namespace before reusing
it: their writes or reconciliation can restore old material. Host transports
must honor the [HTTP binding's no-store rule](../docs/spec--http-binding.md)
and must not share pending requests or retained responses across authenticated
reader contexts. Identical POST bodies can belong to different authenticated
readers.
Failure of `clearAccessDecisions()` preserves grants and access usability.
The host checks eligibility when actually presenting content, including plaintext
returned before reset but not yet displayed. Ports must state these limits and preserve configured transport
support when clearing reader capability.
