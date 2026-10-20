# Evaluating the proposed browser integration

Status: Informative Draft

This guide explains the [browser-integration proposal](spec-proposal--browser-integration.md),
its rationale and examples for evaluation. The proposed handoffs are not adopted
DCA requirements or a recommendation that existing integrations migrate. Registry,
context-source and account-menu support are separately optional within the proposal.

The proposal defines the candidate interface names and behavior. The examples' host
helpers are illustrative; experimental reference modules and runnable tests live under
`js/experiments/browser-integration/`, not a published runtime API. Here the **host**
is the embedding page or application that composes the DCA client with other components.

## What is being evaluated

The candidate provides small common handoffs for independently supplied components
around protected content, session observations and application effects. Each solution
can keep its larger API and dependency wiring. For example, one supplier could provide
a context source, the publisher a content handler, and another supplier an account
menu, with one integrator configuring their connections.

When one party supplies everything, these interfaces mainly organize its own
integration. Whether they reduce repeated integration work between suppliers remains
unproven. Candidate tests check mechanics; practical evaluation also needs independently
supplied components and replacement without disrupting neighbouring consumers.
Application wiring, credentials, retained state and content policy still need owners.

## What each party supplies

- **Publisher or integrator:** the delivery, the selected components, the destination for each
  content name and the rendering policy.
- **Application session code:** the lifetime binding for each operation. When independently loaded
  components need a shared view of login, logout and account switches, an auth adapter supplies it as
  a context source.
- **DCA client:** key acquisition and authenticated content opening and decoding.
- **Content handler:** the component that applies opened content, by rendering it into the page or
  passing it to the application, and reports what happened for each content name. A presenter is a
  content handler that renders.
- **Issuer:** authorization and key delivery. It does not choose destinations.

For article placement, use the [article placement guide](guide--browser-content-presentation.md)
for template-owned targets, full-body replacement, lock/prompt handling and independent
reconstruction. The ordinary browser handler can be supplied by the issuer's vendor when the
content owner chooses it. Publishing `contentMap` does not replace that handler or execute a
second renderer. Independent map clients reconstruct without requiring that vendor's scripts.

## Why separate these handoffs?

An account menu needs display hints and actions. Pending DCA work needs to know
whether its captured context is still current. A content handler needs the item and
its destination or consumer. These responsibilities have different lifetimes even
when one supplier implements all three. An unchanged signed-in label can conceal
an account switch; the issuer still authorizes every request independently.

## Choose the handoffs your integration needs

The publisher or content owner appoints the party that wires the integration. It can be a solution
vendor, the publisher's application team or its content-template scripts. Agree who supplies each
handoff and who owns its lifetime before choosing how the components find each other.

Start with direct references when one application supplies the components. Add registry discovery
when scripts load independently and need to find a provider selected by the integrator. Add a
context source when those components need a shared observation of the session that governs their
requests. An account menu is a separate choice. These additions do not require every vendor SDK
on the page to implement DCA interfaces.

The common interfaces let participating solutions cooperate without adopting one another's full
APIs. A solution can keep its own dependency wiring or registry and supply an adapter at the shared
handoff. Use the specified registry for the selected connections that need it; registering all
services on the page is not a prerequisite.

Stable handoffs also help when changing suppliers or reorganizing the integration. Select a
replacement that implements the agreed contract and update its wiring and configuration. Plan what
happens to credentials, retained state and in-flight work. Check that existing consumers still work
and that delayed predecessor work cannot reach a successor's output. Registry replacement follows
the connection and source-association lifetime rules below; it is not a state-transfer mechanism.

Agree on the following before writing an adapter:

| Question                            | Agreement and owner                                                                                                                                                            |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Who selects components?             | The integrator selects an exact interface, major and name, or supplies a direct reference. A vendor package registers its provider; registration order does not choose it.     |
| Which session governs a request?    | The application identifies the issuer route and the credentials used by that route. Its session adapter explains what establishes and changes that association.                |
| Who owns retained keys?             | The application chooses the retention domain and isolates mutually untrusted contexts. A registry name or account-menu label is not a cache partition.                         |
| Where does opened content go?       | The integrator configures each delivery's content names, destinations or consumers, expected types and application schemas. The handler captures that setup.                   |
| Which content can clients decode?   | The publisher and client integration agree on the emitted `contentEncodings` sequences and the receiving clients' supported inverses and decoding budgets before publication. |
| Who controls consent?               | The application's consent integration decides which scripts and effects may run. Registry presence and a successful opening grant no consent permission.                       |
| Who tells the reader what happened? | The configured caller relays issuer/opening results and handling outcomes to the relevant UI. It keeps denial, unavailable keys, decoding failure and failed effects distinct. |
| Who cleans up?                      | The component owner disposes its registration. The application retires source associations and connections when their session or output lifetime ends.                         |

One provider can serve several article connections. Each connection captures its own delivery and
destination. Several issuer routes can share one context source when their credential ownership
agrees; routes using different sessions need separate associations. These choices belong in the
application's wiring, rather than in another page-wide status variable.

For example, a browser integration may declare support for unencoded items and
the single `["gzip"]` sequence of the
[`dca-profile-content-compression` profile](spec--profiles.md#6-dca-profile-content-compression-profile).
Record the client's configured maximum representation-layer count, bytes fed
to and returned from each decoder, total decoded bytes, and aggregate work or
time budget. Check the publisher's intended items against those budgets and
exercise a boundary-sized item before promising that publication to those
clients. The limits are deployment facts, not universal DCA values: profile
support does not promise that every valid gzip member fits a recipient's
resources. An unsupported sequence or exceeded limit fails that item before
content reaches the handler, without a raw-byte fallback
([content protection Section 8.1](spec--content-protection.md#81-ordered-representation-layers)).

## Map upstream observations by meaning

Document the upstream API path and version used by each adapter. An event name alone is not a
mapping: state what the event establishes, what remains uncertain and what the consumer does next.

| Upstream observation                                                                       | Use in this integration                                                                                                                                                 |
| ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SDK initialized or registry provider arrived                                               | The component can be inspected or called. Confirm request context separately before starting affected DCA work.                                                         |
| Current selected account or a successful sign-in                                           | Supply the account hint when the provider establishes it. Confirm which request credentials belong to that session before reporting a known access context.             |
| Cached account, token, visitor ID or tracking ID                                           | Presence alone establishes neither a current session nor ownership of the next request's credentials. Follow the upstream validity and confirmation contract.           |
| Null, false, timeout or failed session check                                               | Report unknown when the API cannot distinguish a failed check from no session. A completed authoritative no-session check can support a signed-out hint.                |
| Token refreshed for the same session                                                       | Preserve the context revision only when credential ownership and continuity remain established. A refresh may overlap other activity.                                   |
| Actual change in the governed account/credential association, or replacement of its source | Retire the old association before capturing successor work, even if both account hints say signed in. An unrelated SDK selection event does not reset this association. |
| Purchase or entitlement-change notification                                                | Prompt an explicit new issuer-authorized attempt for still-needed items when appropriate. The notification itself grants no key and need not imply an account switch.   |
| Consent service ready or consent choice changed                                            | Apply the consent policy to the scripts and effects it governs. Neither observation establishes DCA entitlement or credential continuity.                               |

The context revision is an opaque generation of the adapter's confirmed association. Keep raw
account identifiers and tokens out of it. For a token-authenticated route, the application can bind
the credential selected for that operation to its captured context. For an ambient-cookie route,
the adapter needs an upstream guarantee or authoritative check that connects the observed session
to the cookies used by requests. It documents any remaining detection gap; a signed-in menu does
not close that gap. A session service may establish a known context for a reader without an account;
the application still binds that context's credentials and retention explicitly.

Each adapter's integration notes describe startup confirmation, negative answers versus errors,
refresh and account-switch behavior, token or observation expiry, detection delay, cross-tab
changes, source replacement/end, cached bootstrap freshness and captured versus ambient
credentials. They also say which observations cause suspension or retirement and how the host
treats unresolved uncertainty. Record unsupported observations as limitations instead of inventing
them. Additional vendor activity or product states can stay local when no shared consumer needs
them.

A completed read of a provider's authoritative local session store can support a signed-out hint
for that local session. It need not establish logout at a remote identity provider, and it says
nothing by itself about ambient request cookies. State that scope explicitly.

## Restoring an article

A publisher can leave an introduction visible and seal the remaining HTML as
`bodytext`. The client opens the item after authorized key acquisition, then a
content handler restores it in the article destination captured by the page setup.
The issuer decides access; it does not choose that destination.

```text
publisher: visible introduction + encrypted HTML bodytext + page setup
                                  |
client and issuer: authorized key acquisition, content opening and decoding
                                  |
content handler: render the fragment in the captured article destination
```

A protected item can be a fragment, almost all of a resource or the whole resource.
A fragment can rely on its public surroundings; a whole resource need not have
placement instructions merely because fragments do. The same resource can also
supply JSON to a nonvisual consumer under an agreed application schema.

## One article, wired directly

The integrator supplies a DCA client and a content handler directly. The application's existing
code binds their work to its context and output lifetime. This setup needs no registry,
context-source object or account menu.

```js
// captureWork, openFor and articleView are local application helpers, not reference-client exports.
const work = captureWork(articleDelivery, selectedIssuerRoute);
const connection = contentHandler.connect({
  delivery: work.delivery,
  isEligible: work.isOutputEligible,
  values: { bodytext: "strictUTF8" },
  targets: {
    bodytext: ({ value, contentType, commit }) => {
      if (contentType !== "text/html" || typeof value !== "string")
        return { status: "refused" };
      commit(() => articleView.renderBodytext(value));
      return { status: "handled" };
    },
  },
});

const opened = await openFor(work); // request, retained keys and result stay bound to work
const outcomes = await connection.handleContent(opened.content);
// outcomes.bodytext.status is handled, refused, failed or stale
```

`captureWork` binds this article's context, request credentials, retention and output lifetime
before the request goes out. The application's session code ends that eligibility on logout, an
account switch or navigation. `openFor` keeps the request, retained keys and result with the captured
work.

`articleView.renderBodytext` is the application's existing rendering operation, here synchronous. It
receives the opened HTML fragment and updates this article under the publisher's rendering policy.
Any HTML sanitization belongs to that policy; the example requires no particular sanitizer. The
connection converts `bodytext` to text. The callback's `commit` checks eligibility
immediately before the synchronous rendering effect. An asynchronous renderer awaits outside
`commit`, then passes each synchronous mutation through it. A synchronous callback's guard expires
when it returns; an asynchronous callback's guard expires when its settlement is observed.
The callback completes its effects before settling and does not leave queued work behind. A consent
queue or remote send that returns immediately has not proved later rendering complete. Any later
rescan or activation has its own consent and lifetime duties. The reference tests exercise these
contracts; this guide does not claim that a particular deployment conforms.

Keep the connection while the same article may continue. Call `connection.dispose()` when its output
lifetime ends, before the destination is reused for another article or context. Disposal does not
remove content already shown; the application chooses whether to remove it.

## Two items and two articles

Article A has `bodytext` and `graphData`. Configure `bodytext` for strict UTF-8 and rendering.
Configure `graphData` for an agreed JSON schema and an application callback. A handled `bodytext`
stays handled when `graphData` is refused. If `graphData` fails after a partial application update,
the application reconciles that update before creating a new connection to retry it. A connection
does not execute a failed name again on the same connection.

Article B may also name its fragment `bodytext`. B gets its own connection, bound to B's delivery and
destination. A content name means something only within its captured delivery, so a page-wide
`targets.bodytext` table must not send A's delayed output into B. Before B reuses A's DOM node, the
application ends A's eligibility for that node.

## A schema-aware nonvisual consumer

`graphData` contains JSON such as `{ "unit": "EUR", "points": [12, 15, 14] }`. An application
agreement defines the unit, the order of the points and what each value means. The consumer receives
the decoded bytes, parses the JSON, validates it against that agreement and passes the values to the
analysis application. It needs no visual destination and no article DOM. Another JSON object with the
same media type does not establish that agreement.

The content handler reports `handled` when the agreed effect, such as storing the values in the
analysis model, has completed; only queueing them is not handled. It refuses unknown or invalid data
before any effect, and reports `failed` if an effect already happened.

## Independently loaded scripts

When the client, the auth adapter and the content handler load as separate scripts, each obtains the
compatible registry at `globalThis.DelegatedContentAccess.clientRegistry`. The publisher's
configuration selects exact keys, such as
`{ interface: "dca.content-handler", major: 1, name: "article" }`. Observe the selected key to handle
a provider that arrives late. Never pick whichever provider registered last.

The proposed registry discovers the configured provider; it neither chooses nor
authenticates one. It is not a security boundary against other scripts in the page.

Absence of a configured provider leaves the work pending; the application decides how long to wait
and what to tell the reader, and never falls back to another provider or treats the reader as
anonymous. A shared context source carries the session observations; bind it separately from any
account-menu provider; a missing menu provider does not block the content path.
[Browser-integration Sections 2, 3, 4.2, 4.3 and 5.4](spec-proposal--browser-integration.md#3-registry) define
registration tokens, suspension on an unknown snapshot, when suspended work may resume, retirement on
source replacement even at the same revision, and when a connection becomes stale. The adapter
documents what it can detect, including ambient-cookie and cross-tab limits. Consent policy may block
a provider indefinitely. See [client context lifetime](guide--deployment-patterns.md#client-context-lifetime).

## Replace one component at a time

The integrator decides which connections finish under their old provider and which are retired.
Replacing a provider is distinct from reusing an article destination or changing credential
ownership; those changes can require retirement even when the provider itself stays the same.

| Replacement             | Handover                                                                                                                                                                                                                                                                              |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Context source A to B   | Retire A's governed association and affected work before associating B with its routes, credentials and retention. Capture new work once B confirms its context. The handler provider and menu can remain, but a connection bound to retired work cannot become B's connection.       |
| Content handler A to B  | Select B for new connections. Existing A connections can finish while their captured context and destinations remain eligible, or the integrator can dispose them. End A's eligibility before B reuses the same destination; reconcile prior effects rather than replaying all names. |
| Account provider A to B | Stop observing A and use B's own observations, freshness and supported actions. Replace the account UI binding without inferring a credential change from that alone. If the same supplier also provides the governed session source, coordinate that separate handover.              |

The owner that shuts down a context source also arranges the end of its host association. With
registry wiring, removal of the selected registration can drive that retirement; with direct
wiring, the application explicitly ends the association. The source's final unknown observation
alone does not distinguish shutdown from temporary uncertainty, so it cannot complete the handover.

These contracts describe replacement at their particular handoffs. Replacing an entire identity
service or DCA client can also require credential, endpoint, storage or application API changes.
Those dependencies belong in the integration's migration plan; matching a registry key does not
establish compatibility for them.

## An optional account menu

Select the account provider separately from the context source. Recompute freshness on display, on
a timer and on resume. A signed-in label grants no access and detects no account switch; `started`
means initiation, not a completed login.
[Browser-integration Section 7](spec-proposal--browser-integration.md#7-companion-account-convention) defines
freshness, readiness and click-time invocation. Invoke an action directly in the click handler so
popup-sensitive upstream code starts synchronously. A redirect can unload the page before it
observes the promise result. A vendor-owned button is not automatically an implementation of this
convention.

## Handle results without guessing

Check each name separately:

- Keep handled items, even when a sibling is refused or fails.
- Resubmit a refused item explicitly once its cause is fixed, for example after adding a missing
  destination.
- Reconcile a failed item's partial effects before any resubmission. Nothing retries automatically.
- End stale work; a later call on that connection changes nothing.
- An identical repeat of a handled item has no new effect; changed bytes for it are refused.

The party who can fix a failure acts on it: the publisher corrects a missing or malformed item
record; the deployer supplies a client that supports the named `contentEncodings`, or the publisher
a representation the client supports; the integrator supplies a handler or schema agreement for the
media; the host repairs a missing destination and resubmits explicitly.

The [content-handler contract](spec-proposal--browser-integration.md#5-content-handler) defines the
four statuses, overlap and repeat behavior. Missing opened content is not itself a denial: use the
scoped opening or issuer result. Optional diagnostic strings are not access decisions either.

The configured caller can relay these results to an article prompt or purchase widget. Keep opening
and handling results distinct: an authorized item can still fail decoding or presentation. The
profile leaves that relay to explicit application wiring and defines no shared observer interface.

After a purchase signal, coalesce duplicate notifications and request still-needed items again under
the same confirmed context when appropriate. The issuer authorizes the new attempt; delayed
entitlement propagation can still leave an item unavailable. Do not create an automatic retry loop.
Credential, isolation or host-policy changes can instead require retirement even while the displayed
account remains signed in. Delivered keys and plaintext are not cryptographically revoked.

## Rendering and other consumers

"Content handler" covers both rendering and nonvisual application effects; a
presenter is a handler that renders. The candidate interface is `dca.content-handler`,
its operation is `handleContent` and success is `handled`. That outcome means the
agreed effect completed, not that access was granted or the reader saw the result.

A content handler can insert text, parse and schema-check JSON, construct a Blob or update
application state. No DOM operation is required. Publisher-registered activation can run after the
content is handled; opening content does not instruct the client to execute it. Rendering HTML or
running application behavior stays subject to the publisher's CSP, sanitization and lifecycle policy.

## What travels, and what stays local?

The outer `contentType` and optional `contentEncodings` describe representation.
Application meaning comes from the authored resource or an agreed schema. Placement
or use comes from the integrator's setup, or a separately selected description or
map contract. Context can come from the public resource, local configuration or
protected application data, as agreed with the consumer. These are separate facts;
a media type does not supply all of them.

This example relies on publisher setup. A consumer that must reconstruct content without that setup
can select the [HTML content-map proposal](spec-proposal--html-content-map.md) for HTML slots.
A description is optional and does not define placement; see
[content description and placement](spec-proposal--content-description-and-placement.md). A
separate-origin frame also needs its own custody and messaging agreement, which
DCA does not specify.

The discovery and function contracts here are same-realm. Cross-frame rendering requires receiver
lifetime checks and completion acknowledgement; enqueueing a message proves neither. Persistent
context identity and vendor adapters remain outside the first shared contract.

## Runnable evidence

Before using a new adapter, exercise the ordinary article path and the transitions its integration
claims to support. Check late provider arrival, an account switch that remains signed in, a failed
session check, expiry without an event, source replacement and navigation while opening is pending.
For each case, observe request dispatch, retained-key use and the actual application effect;
checking only the menu label misses the ownership boundary. Also check one successful item beside
one refused or failed item, and an explicit retry after the application reconciles its result.
When an upstream API cannot expose one of these transitions, record the limit and the application's
response. Do not report the unsupported case as tested.

The [reference README](../js/experiments/browser-integration/README.md) identifies checked type
modules, reusable contract cases and focused tests.
Node exchanges pass serialized UTF-8 JSON between real publisher, issuer and client roles. Chromium
tests load actual modules, open with browser WebCrypto and update a captured DOM destination; they
also test replacement, unknown/resume and popup initiation from a real click.

The shared reference handler and source remain shared implementations even when
tests supply callbacks and participants independently. A second implementation would
provide stronger interoperability evidence. A shared result observer remains a
separate future candidate requiring attempt identity, partial-update and stale-result
rules; this proposal does not supply one.

These are local reference proofs. They do not cover production configuration storage, real customer
deployment, every browser or independently implemented complete protocol
conformance. The Chromium run uses one cached browser and intercepted local routes; it does not show
production credential binding, TLS, CORS or cache deployment, or vendor adoption. The optional
description and HTML content-map decisions are made separately.

## Questions for reviewer feedback

1. Can your ordinary integration supply an article destination and the actual access-context
   transitions, including an account switch that keeps a signed-in label? Where does your binding of
   request credentials have limits?
2. Do you consume opened content without rendering it? Does the content-handler vocabulary describe
   that handoff, or does your use suggest a better one?
3. Do your consumers know item meaning and placement through setup, or must they interpret deliveries
   independently? Which knowledge must exist before opening?
4. Can your application tell a refusal with no effect from a failure with partial effects, and
   reconcile the failure before it retries explicitly?

These questions test the proposed handoffs. The type-information choices in the description proposal
remain a separate decision; reviewer feedback does not adopt them.

## Evaluation criteria

Evaluate fragments that need their surrounding resource, whole resources,
and independently useful protected data. Name the usable
outcome before choosing fields or interfaces: restoring a fragment, supplying
an article to an agent, or passing JSON to an agreed nonvisual consumer.
Successful decryption and a media-type label alone establish none of those
application outcomes. Public material can remain public.

| Question | Design responsibility |
| --- | --- |
| What context does the opened item need? | State whether the delivery, protected payload or application supplies it. A fragment need not become self-contained. |
| What does the content mean? | Separate media type from schema and application semantics. An arbitrary JSON wrapper needs its own parsing agreement. |
| Where is it used? | Distinguish placement from description; a data consumer needs no dummy DOM target. |
| Who must know? | Separate knowledge that exists somewhere, information that travels, and duties every selected participant implements. |
| What interoperates? | State the baseline promise, optional dependencies, configured defaults and excluded consumers. Conformance is not universal deployment compatibility. |
| What does the simple consumer pay? | Count description/placement bytes, required capabilities and private setup against the actual promised use. |

A deliberately closed integration can rely on application knowledge where its
selected contract permits it; it still supplies required wire members. Direct
wiring remains sufficient where it serves the use. A compatible provider
replacement should preserve neighbouring consumers, but credentials, retained
state and pending work require explicit application ownership. Shared interfaces
neither migrate that state nor appoint an issuer.

The specification maintainers decide candidate adoption; the integrating
application owner selects real deployment validation. This guide creates
no browser baseline duty or new implementation release.
