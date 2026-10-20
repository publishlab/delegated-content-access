# Browser integration reference implementation

Status: experimental reference implementation; not a published integration API.

This implementation evaluates the proposed decoded-content handoff in the
candidate `dca-profile-browser-integration` profile. The candidate depends on `dca-profile-baseline`; direct setup needs
no registry or context-source interface. Registry discovery and context observation are separate
optional capabilities. The account convention is a separately selected companion outside the
profile. The existing `contentType` remains required in each `contentData` record. Optional
`contentEncodings` stay with the client opener: callbacks receive bytes after applicable decoding.
Descriptions and interoperable reconstruction remain outside this implementation.

- `implementation/content-handler.js`: `createContentHandler`, `connect`,
  `handleContent`, `dispose`.
- `test/content-handler.test.js`: isolated value, lifecycle, effect and repeat cases.
- `test/exchange.test.js`: actual EC publisher/issuer/client, serialized UTF-8 JSON
  delivery, independent HTML/JSON/NDJSON callbacks and delayed destination reuse.
- `implementation/registry.js`: typed `installRegistry` and client-facing discovery.
- `test/registry.test.js`: installation, configured keys, replay and observer lifecycle.
- `test/registry-exchange.test.js`: independently installed participants, arrival orders
  and replacement over the real serialized exchange.
- `test-lib/registry-client.js`: checked host-side selection and provider admission.
- `test-lib/exchange.js`: real reference exchange setup; no cryptography substitute.
- `implementation/context-source.js`: typed synchronous observation, ordering, revision and end.
- `implementation/session-event-adapter.js`: one example translation from a synchronous session-change API.
- `implementation/authorization-feed-adapter.js`: a separate example translation from an asynchronous lease feed.
- `test-lib/context-host.js`: host capture, unknown waits and scoped retirement; no key store.
- `test/context-{source,host,exchange}.test.js`: source/host units and real request/key/output gates.
- `test/independent-provider-cooperation.test.js`: two independently implemented provider adapters, one stable
  content handler, serialized DCA, separate captured transport credentials and a delayed predecessor response.
- `implementation/account-source.js`, `test-lib/account-menu.js`, `test/account.test.js`: original
  freshness, optional synchronous action initiation and explicit local hint mapping.
- `test/browser{,-context}.test.js`: Chromium modules, WebCrypto, DOM reuse, context and real click.
- `types/{registry,content-handler,context-source,account-source}.d.ts`: emitted interface types.
- `test-lib/contract.js`, `test/contract.test.js`: reusable behavioral cases selecting factories.
- `test-lib/participant.ts`, `test/types.test.js`: an external typed participant and rejected shapes.

## Contract

```js
const connection = createContentHandler().connect({
  delivery, // captured JSON delivery, including contentData
  isEligible: () => applicationStillOwnsThisOutput(),
  values: { bodytext: "strictUTF8" }, // bytes by default
  targets: {
    async bodytext({ contentName, contentType, value, commit }) {
      if (contentType !== "text/html" || typeof value !== "string") return { status: "refused" };
      await prepareLayout();
      commit(() => renderIntoCapturedTarget(contentName, value));
      return { status: "handled" };
    },
  },
});
const outcomes = await connection.handleContent(openedBytesByName);
connection.dispose();
```

The application captures context, credential/cache ownership and output lifetime
before obtaining/opening bytes. `isEligible` refers to that capture. Before a successor
reuses a destination, the application ends the predecessor's eligibility. This
connection does not manage credentials or revoke previously delivered capabilities.

The callback receives the captured item type and bytes or strictly decoded text. Strict
UTF-8 preserves a leading byte-order mark as U+FEFF; interpretation policy can handle it
explicitly.
Media type supplies no application schema, destination or authority to execute HTML.
The callback implements the publisher's rendering/interpretation policy. No shared
schema identifier is fetched automatically, and no description member is required.

An asynchronous callback awaits outside `commit` and submits each actual synchronous
effect through it. `commit` returns false without invoking after invalidation or
operation expiry. A synchronous callback's guard expires at return; an asynchronous
callback's guard expires when the connection observes settlement. Callbacks complete
their agreed effects before settling rather than leave queued work behind. Saved guards
cannot extend that operation lifetime. A function
passed to `commit` must not start asynchronous mutations; such callback misuse is
reported as failure but cannot undo uncontrolled effects. Same-page scripts and
callbacks are trusted participants, not sandboxed by this helper.

Results per submitted name are `handled`, `refused`, `failed` or `stale`, with optional
diagnostic `reason`. Handled requires a completed guarded effect. Refusal after an
effect becomes failure. Lost eligibility retires the connection and reports stale for
that in-flight item and later submitted names; earlier effects and completed sibling
outcomes are preserved. No stale outcome promises rollback.

Overlap rejects before effects. Identical handled bytes report handled without another
effect; changed bytes are refused. Refused names may be explicitly retried. Failed names
are not executed again on this connection: the application reconciles partial effects
before constructing replacement work. Disposal releases retained repeat bookkeeping.

## Optional registry

`installRegistry(host = globalThis)` creates or reuses
`host.DelegatedContentAccess.clientRegistry` with `apiMajor: 1`. Independently supplied
participants retain that returned reference; unrelated namespace members are preserved.
An incompatible installation is refused. `RegistryKey` explicitly configures
`{ interface, major, name }`, for example
`{ interface: "dca.content-handler", major: 1, name: "article" }`.

`ClientRegistry` exposes `register`, `lookup`, `observe` and diagnostic `keys`.
Keys have only those three own members, nonempty strings and a positive safe integer
major. Admission copies them. Providers are objects or functions; callers validate
the selected interface before use. Lookup returns null while that configured provider
is absent. Another name or major never substitutes for it.

Observation synchronously replays `{ provider, registration }` before returning.
Both are null when absent; each new registration has a fresh opaque identity.
The callback receives the same idempotent stop function returned by `observe`.
Reentrant presence changes queue in order; stopping prevents further callbacks and
one listener exception cannot disrupt others. An observer created during notification
replays current presence and receives only subsequent changes.

Duplicate registration refuses rather than replacing. Dispose the old registration,
then register its replacement. An old disposer cannot remove its successor. Discovery
removal affects new connections; an already captured content-handler connection
continues under its own host-controlled eligibility until retired or disposed.
The registry authenticates no provider and does not expose a client key store.

## Verification

From `js/`:

```sh
node --test experiments/browser-integration/test/*.test.js
pnpm run check:types
pnpm run test:experiments
```

The experiment inventory selects all twelve entrypoints. The implementation is admitted to
checked JavaScript; standard runtime, reference exports and baseline tests do not
import it. Baseline behavior remains usable when experiments are omitted.

The exchange uses real ECDH envelopes and signed publisher claims, genuine issuer
admission/authorization and associated client responses. A copied serialized delivery
crosses to a JSON-only client. Tests exercise ordinary HTML, known-schema JSON/NDJSON,
malformed UTF-8 isolation, delayed A losing its target to B, repeats, gzip decoding and
an unsupported-encoding refusal without passing intermediate bytes to a callback.
An early-check-only control reproduces the successor mutation the final guard prevents.

Chromium tests load actual ES modules in provider/client orders, fetch serialized JSON, obtain keys
from the real Node issuer and open with browser WebCrypto before applying captured DOM effects.
Source tests gate dispatch, retained-key use, opening and handling across unknown, resume and
replacement. A real click starts `window.open` while transient activation is present; it does not
claim that login completed. The controlled account clock proves expiry without an observation.

Browser tests require installed Chromium and fail if absent; `DCA_ORACLE_BROWSER` and
`DCA_ORACLE_BROWSER_LIBS` can select its executable and local libraries. Product-specific
publisher integration is out of scope here.

All browser routes are intercepted locally. Evidence covers one Chromium, same-realm callbacks,
a permissive reference issuer policy; it does not establish
production credential binding, HTTPS/CORS transport, every browser or vendor behavior.
It proves neither all browser interfaces nor complete independent DCA conformance.
The proposal defines the candidate browser-integration contract. Its interfaces are not a
current DCA v1 profile, and these experiments establish no browser-profile conformance claim. The implemented interfaces follow
[`docs/spec-proposal--browser-integration.md`](../../../docs/spec-proposal--browser-integration.md). The
content-description behavior remains separately specified and selected.

## Independent provider replacement example

`session-event-adapter.js` reads an event-based session API with an account reference, credential reference and bearer
value. `authorization-feed-adapter.js` instead reads a provider lease asynchronously after change notifications and
ignores lookup results that arrive after a newer read began. A notification makes the prior lease unknown before
the read settles; a failed read leaves it unknown without reusing the old credential. A later read after a failure
or overlapping notifications starts a fresh revision even when its handles match, because the skipped transition
cannot confirm continuity. One successful, non-overlapping refresh with the same association may resume suspended
work under this example's upstream contract: the account/key handle pair remains stable for one continuing context
and is not reused after an actual context replacement. A changed pair advances the revision. Each adapter translates its own
provider representation into the optional context-source contract. The test application performs the small
provider-specific credential extraction:
one adapter returns a bearer header, while the other exposes a lease which the application turns into that header.
Both adapters compare handles as pairs and copy the credential fields they admit, so a caller's later mutation of
the input object cannot silently change the credential exposed under a published revision. An integration whose
upstream service reuses handles after a context replacement must supply a stronger context identity or retire work
on each notification. These examples do not detect changes that the upstream service never reports, and cross-tab
coordination and ambient cookie changes remain host responsibilities.

The consumer and content-handler provider remain the same objects while the host retires A's
connection and creates B's connection for B's captured delivery and output lifetime.
It waits for unknown startup, captures A's credential for A's request, changes A's account while that response is
pending, waits for B's first lease read, then opens B's real serialized DCA delivery. The application creates a separate
client/resolver for each captured operation and binds its response-admission guard to that operation's captured work.
Releasing A's delayed response after B has written stops before A's resolver applies the response: A records zero
response applications and holds no item key. B records one application, retains its own key and writes once through
its own content-handler connection. Cleanup stops both provider subscriptions and the active consumer connection; retired
work cannot dispatch another unlock. This is explicit application context ownership and cancellation wiring, not
automatic client-state migration or erasure of keys an eligible operation already obtained.

The credential is passed to the test transport separately from the serialized DCA request. It does not appear in the
publisher delivery or request JSON. This example does not define how a production application selects, refreshes or
stores credentials, bind those credentials to an issuer, or transfer state between provider implementations. The host
still owns those choices, the request transport and the governed article lifetime. The fixture issuer does not vary
authorization by credential, so this proves capture and transport separation, not credential-dependent issuer policy.
The delayed stage here is the response; the destination callback commits synchronously, so arbitrary asynchronous
callback replacement schedules are outside this proof. The adapters and replacement proof are
experimental reference evidence; no live vendor integration or automatic state migration is claimed.

## Context and account wiring

`createContextSource(initial)` returns `{ provider, publish, end }`; consumers receive only the
provider's `subscribe`. Startup unknown confirms no context: the host waits to capture. Still-live
work can resume only when source association, revision, host generation and output lifetime are
unchanged and the adapter confirms continuity. Another revision or association replacement retires it even when public account labels match. End sends
an ordinary next-sequence unknown, then stops; the host explicitly ends its association. Source
revisions are page-local generations, not persistent identity or account keys.

The checked host helper scopes routes and returns captured work with `isEligible`,
`waitUntilKnown` and `dispose`. Application code invokes each request, capability/opening operation
and handling call inside a gate that rechecks eligibility after waits. The handler separately
checks every actual effect. A handler that observes false becomes terminal stale; an idle
connection need not retire merely because it experienced an unknown interval without a check.
Reconcile earlier effects and successful names before replacement handling.

`createAccountSource` returns a separate provider with `subscribe` and nested optional `actions`.
The menu derives unknown outside the original `[observedAt, validUntil)` interval on each read,
timer/resume; replay never renews times. Invoke a present, ready action inside the click, not after
a queued wait. Its promise reports initiation only. A redirect can unload the observer. The
explicit `accountFromLocal` maps the deployment hint without coupling it to context ownership.

## Types and reusable checks

Import the layer-specific types without importing the reference runtime implementation:

```ts
import type { ContextSourceProvider } from "./types/context-source.js";
import type { ContentHandler } from "./types/content-handler.js";
import type { ClientRegistry } from "./types/registry.js";
```

Plain JavaScript uses the same modules through JSDoc `import(...)`. Numeric types do not themselves
enforce safe integers, freshness or lifetime; behavioral checks supply those distinctions.
Generic registry lookup types express the caller's selected interface, not provider authentication
or runtime validation. `test-lib/registry-client.js` validates its selected handler before use.

`registerContracts(factories)` registers ten selected behavioral cases without importing the
reference implementation modules. A new adapter supplies source test-driver operations and host/menu factories;
`test/contract.test.js` shows that wiring. The cases are reusable evidence, not a complete profile
conformance oracle or proof of a second implementation. No npm package or new standard export is
published by this experiment.

## Accepted experimental scope

The implementation and finite R4/Cookiebot reconciliation were accepted in
October 2026. The replacement proof uses separately written event/lease adapters,
a stable consumer, captured transport credentials, separate context clients and
response-application guards. A retired predecessor applies no response and holds
no delivered key; the eligible successor applies once and completes one effect.
Suppressing only the stale destination effect would not preserve that custody.

These are bounded experimental results, including the separately described
Chromium and native publisher crossings. They establish no live vendor adoption,
production token validity or credential-dependent issuer policy, ambient-cookie
continuity, arbitrary asynchronous callback schedule, automatic state transfer or
reduced customer integration cost. Historical broad gate counts do not prove a
current whole-tree or complete independent-profile conformance result.

The operator returned browser integration to Proposal status on October 14.
That decision supersedes the earlier adoption language without removing the
candidate contract or accepted implementation. The specification maintainers
decide any later adoption; the integrating application owner selects product
deployment validation. Publication remains separately held.
No repeat synthetic replacement proof or catalogue survey is needed.
