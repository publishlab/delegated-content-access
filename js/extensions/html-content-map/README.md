# HTML content map

Status: prototype of a proposed optional profile; implementation evidence, not protocol authority

This extension implements the embedded `contentMap` candidate in
[`spec-proposal--html-content-map.md`](../../../docs/spec-proposal--html-content-map.md).
The map is an optional member of the existing `dca-data` object:

```json
{
  "contentMap": {
    "version": "1",
    "rules": [
      { "item": "bodytext", "op": "fill", "target": "#article" },
      { "item": "bodytext", "op": "remove", "target": "#subscribe" }
    ]
  }
}
```

Rules name items in `contentData`; their existing `contentType` is authoritative.
Mapped items must be `text/html` or `text/plain`, with at least one fill per item.
There is no map type table or separate map script. Description support is optional
and independent; structured-data items can remain unmapped.

## Browser ownership

The ordinary browser integration hands opened content to the content owner's chosen
handler. That can be its own code, a CMS component or an issuer-supplied rendering
library. It can update framework state instead of manipulating DOM directly. The
issuer's access role does not choose the renderer.

The map provides independent reconstruction without requiring that code. A browser
host can explicitly select the map renderer for stable destinations it owns. It must
choose one placement owner per destination, and must not silently switch to map
execution after its chosen handler refuses. Base client source imports nothing from
this extension; map presence causes no automatic placement or script loading.

## Publisher

`adapter-publisher/writeMappedDelivery.js` accepts one render's `dcaData`,
`sealedContent`, `contentMap`, `items` (author-time text for every mapped item), and
`page` (a template function receiving the carrier markup). It embeds the map into a
copy of `dcaData`, writes the two base carrier blocks, then admits the resulting page.

Admission checks the map, declared items, types, ciphertext, limits and targets. It
also fills author-time content into a private parse and compares its serialized and
reparsed form, refusing unstable HTML or plain text with `map_item_delivered_form`.
The caller's delivery is not mutated. Admission must still run at the client because
the served page or client limits may differ.

## Explicit reconstruction

- `core-client/contentMapRun.js` exports `createContentMapSession(options)` and the
  one-shot `runContentMap(options)`. Options supply the tree, admitted delivery facts,
  key-client factory, optional limits and an optional host `isEligible` check.
  A session exposes `run()` for the first attempt or retry of locked items,
  `snapshot()` for checked output and `dispose()` to retire pending and future work.
- `integration-client/reconstructBrowserPage.js` supplies the DOM adapter and base
  client and requires `isEligible` for the captured article/context lifetime.
  Dispose it when that lifetime ends. Retain the browser session for retries on that delivery; completed fills
  must not run twice. Do not initialize another renderer over an already resolved
  document.
- `integration-client/createHtmlGateway.js` fetches a locked source and reconstructs
  on a private parse5 tree. Configuration supplies trusted `sources`, publisher
  `registrations`, `issuerName`, exact HTTPS `issuerEndpoint`, `admitCaller(scope)`,
  `fetch` and issuer `transport`. `reconstruct({url, callerContext})` returns the
  report, final source URL as `identity`, HTML or `null`, and target observations.
  `admitCaller({callerContext, registration})` must return true before any cache or
  key use, including on repeat calls. A caller-provided label alone is not admission.
- Source `fetch` uses manual redirects and a streaming `body.getReader()` interface;
  `arrayBuffer()` alone is insufficient. Each URL must be admitted. The adapter
  bounds bytes while reading. The final response must carry `text/html` with one
  UTF-8 charset parameter; the gateway fatal-decodes UTF-8, consumes one initial
  UTF-8 BOM and ignores in-document `meta` declarations for source admission.
  Publisher signature, final origin and caller policy are checked even when keys
  are cached. The configured trusted `issuerEndpoint` is the only unlock endpoint;
  a carried `unlockUrl` is ignored.
- Optional `capabilityCache` and `chainCache` providers receive one admitted
  `{callerContext, registration}` scope. Stateless `clientOptions` may select key
  extensions; cache, resolver and routing options owned by the gateway are refused.

A session retains the delivery carriers and completed-item state. It prepares an
item's fills before removing its prompts or lock classes. A later attempt handles
only locked items; external mutation or target replacement refuses the session.
`complete` means every mapped item and placement succeeded; `partial` contains only
opened and still-locked items. Defective items, aborted acquisition or placement
failure produce `failed`, with no reconstructed output claim.
An exhausted visible 5xx or an absent configured acquisition route with
unresolved items reports `key_acquisition_failed`; failed reports carry only
item states established independently of that acquisition failure. Usable
retained keys are still tried before unresolved acquisition makes the attempt
fail.

Output packaging belongs to the host. Serve reconstructed HTML with
`Content-Type: text/html; charset=utf-8`, and preserve the source URL, document and
report together; there is no required second JSON wire format. An exported partial
result is a terminal snapshot. A host serving raw HTML must preserve relative-URL meaning
and prevent its DCA initializer from reopening retained carriers. This extension
provides neither an HTTP serving policy nor a generic script-stripping algorithm.

## Implementation and evidence

Portable `core-*` modules contain admission, selector matching, source policy,
opening and lifecycle logic. Tree adapters provide DOM or parse5 operations; parse5
is a runtime dependency only of server and publisher adapters. The selector grammar
and finite limits are in `core-shared--client-publisher/contentMap.js` and
`selectors.js`. The `mapOctets` limit measures the serialized `contentMap` member,
while `documentOctets` measures the source document. JSON uses the common parser
policy, with no duplicate-key scanner.

Run from `js/`:

```sh
pnpm run test:reference:extension:html-content-map
node --test test-profiles/dca-profile-html-content-map.test.js
```

Tests cover publisher admission, type/carrier refusal, placement, partial grants,
continuation, stale targets, placement refusal, source/caller/endpoint boundaries,
and chain-key cache isolation. `../../test-extensions/content-description-html-map.test.js` opens real publisher
content through chosen HTML/data handlers without executing the map, then proves an
independent map client reconstructs the article without those handlers.

The Chromium oracle compares the browser, parse5 gateway and native DOM observations.
It skips if no executable is installed; `DCA_ORACLE_BROWSER` selects one. This evidence
covers those engines and declared operations, not arbitrary framework integrations,
script execution, production gateway deployment or complete profile conformance.

The reference oracle is a headless browser that loads the locked delivery as a
page served with `Content-Security-Policy: script-src 'none'`. The parser runs
with the scripting flag set and no page script runs. A harness applies the
rules from an isolated script context with `querySelectorAll`, the `innerHTML`
and `textContent` setters, `classList.remove` and `remove()`, serializes the
document, loads the text as a second page under the same policy and records
the observations of proposal Section 7.2. `DOMParser` is not a valid oracle:
it parses with scripting disabled, so `noscript` content becomes elements.
A parser change in a later browser version changes the recorded evidence;
it is not a silent pass.

For publisher signing-key rotation, load the new `kid` and verification key in
every participating verifier, including server gateways, before signing renders
with it. Keep the old verification entry while old renders remain supported.
