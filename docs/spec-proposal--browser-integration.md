# Proposal: DCA v1 browser integration

Status: Proposal

## Abstract

This proposal defines a candidate optional `dca-profile-browser-integration` profile: same-realm
JavaScript interfaces through which a directly wired page hands opened content to a content handler
bound to the work that produced it. Registry discovery and context-source observation are optional
additions; the account convention is a separately selected companion with no DCA authority. The
profile depends on `dca-profile-baseline` and changes no wire member or issuer authorization.

## 1. Introduction

The candidate profile would add duties to participating browser components, not to baseline-only
clients or server implementations. It is not adopted into DCA v1 and establishes no current
DCA profile conformance claim. It changes no wire member, issuer authorization or key-delivery rule.
Current core requirements, including logical-client-context ownership, apply unchanged.

The interfaces are same-realm JavaScript; their implementer is a page integrator or component
supplier, not a protocol porter. This document does not define how a consumer interprets or places
content without the integrator's setup, description validation, integrity or independent delivery
(see [content description and placement](spec-proposal--content-description-and-placement.md)),
or a shared result-observation contract, entitlement list, automatic retry or event bus.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document are to be
interpreted as described in BCP 14 when, and only when, they appear in all capitals.

The proposed interface contracts in Sections 3 through 7 use normative wording, including
requirements stated in the indicative. Definitions in Section 2 determine their
terms. Duties apply to the participants and selected capabilities in Section 9.

In this document the **host** is the embedding page or application that composes the DCA client
with other components. It is not an HTTP server or another protocol role. Where a sentence
concerns one part of the host, it names that part: the integrator, the application or a
component.

### 1.1. Participating components

- The **integrator**, usually the publisher or its page developer, selects the components, the
  destinations for opened content and the lifetime policy.
- The **DCA client** obtains authorized keys, opens items and preserves the captured ownership of
  each operation, as [core Section 2.2.1](spec--core-protocol.md#221-logical-client-contexts-and-pending-work)
  requires.
- A **content handler** performs the application effect for opened content: it renders an article
  fragment, updates application state or passes data to an analysis application. A **presenter**
  is a content handler whose effect is rendering.
- A **context source**, when the integration uses one, reports actual access-context transitions
  that its upstream session service can observe.
- An **account provider**, when a menu uses one, reports account hints and starts account actions.
- The **issuer** authorizes and returns keys under the existing protocol.

## 2. Lifetime terms

These terms apply to every interface below.

- **Captured work** is one operation together with the logical client context, publisher delivery,
  issuer route, request credentials, retention domain and output lifetime the host bound to it
  before the request or cache use began.
- **Eligible** means the captured work may still use retained capability and perform output. The
  host decides eligibility; the client and the content handler preserve and check it.
- **Suspended** work is waiting on an unknown context; Section 4.2 states what it may not do and
  when it resumes.
- **Retired** work has lost eligibility permanently: the host disposed its binding, replaced its
  source association, observed a different context revision or reused its destination. Nothing
  revives retired work, including a later observation that repeats the old revision.
- **Stale** is the content-handler outcome when the handler observes lost eligibility. It ends the
  connection. It does not undo effects that completed earlier.
- **Handled** means the agreed application effect for one content name completed. It does not mean
  the issuer granted access, the reader saw the content or a downstream application finished later
  work. A handler that only queues content for a later effect has not handled it.

A host may wait for suspended work to resume before calling the content handler; such a wait is
local policy, and retirement ends it without a call. An idle connection survives an unknown interval
when no eligibility check runs during it.

## 3. Registry

The registry is optional. A component that already holds its dependencies uses them directly.

The shared location is `globalThis.DelegatedContentAccess.clientRegistry`. Any participant can
install it compatibly. Registry `apiMajor` is 1; a registered interface's `major` is a separate
version axis. Discovery and direct function handoffs are same-realm.

The host and namespace may be objects or functions; they need not be plain objects. Installation
creates absent own members, preserves an existing namespace and its unrelated members, and reuses a
registry only when it has `apiMajor: 1` and callable `register`, `lookup`, `observe` and `keys`.
Present null or undefined members are incompatible installations. Failure to
write the host is a setup failure. Load order is independent among
compatible participants; it is not a guarantee for incompatible registry APIs.

```text
key = { interface, major, name }
register(key, provider) -> dispose
lookup(key) -> provider | null
observe(key, (entry, stop) => ...) -> stop
keys() -> keys                         // diagnostics only
entry = { provider, registration }     // both null when absent
```

Keys have exactly three own members: nonempty string `interface` and `name`, and positive safe
integer `major`. Admission copies the key. Providers are objects or functions; the registry does
not validate their interface. A selected consumer validates it before use. Invalid keys/providers,
duplicates and incompatible installation throw synchronously; observation exceptions are isolated.

The integrator configures exact keys, for example
`{ interface: "dca.content-handler", major: 1, name: "article" }`. A component never selects
whichever provider happened to register last, and `keys()` serves diagnostics, never selection.

Replacement disposes the old registration, then registers the new one. Matching keys do not prove
that different provider objects are equivalent or permit adoption of another owner's registration.
Each registration gets a fresh opaque token, even when the provider object is reused. A disposer
cannot remove a successor registration.

`observe` replays the current entry synchronously before it returns, then delivers presence changes
in order. Reentrant mutations queue; a new subscription still replays the current entry synchronously
and receives only later mutations. The callback receives the same idempotent stop function that
`observe` returns, and stopping during replay works. One listener's exception does not stop the
others, even if error reporting also throws. No callback runs after its stop.

A configured provider that has not arrived is pending. The application does not substitute another
provider and does not treat an absent context source as an anonymous reader. Another provider major
is diagnostic information, not an error proving the configured major will never arrive.
A missing configuration is a setup error.

Replacing or removing a registration changes discovery for new connections only. An existing
content-handler connection keeps its captured lifetime: removal neither rebinds nor revokes it.

## 4. Context source

A context source is optional. The integration uses it when independently supplied components need
one shared observation of context transitions.

### 4.1. Observations

A provider under `dca.access-context` exposes `subscribe(listener) -> stop`, with the synchronous
replay, idempotent stop, mutation ordering and listener/error-reporter isolation of registry
observation (Section 3).

```text
snapshot = { sequence, contextKnown, contextRevision }
```

The record has exactly these three own members. `sequence` is a nonnegative safe integer (0 to
2^53 - 1), `contextKnown` is boolean, and `contextRevision` is a string, finite number, boolean or
null. Snapshots are copied and immutable. Sequence increases within one source association;
consumers ignore older or equal observations. Invalid producer input throws before publication.

`contextRevision` is an opaque source-local value compared for equality: values are equal only when
they have the same scalar type and value; numeric positive and negative zero are equal. A new
revision denotes an actual context change within the source association, including a switch between
two accounts whose menu labels both say signed in. It is not an account identifier and not a
retention namespace: a restarted source may repeat an earlier revision. An unknown snapshot still
carries a revision. Within an association, a revision cannot be reused after a different revision.

A consumer MUST admit every nonnegative safe integer, including
`Number.MAX_SAFE_INTEGER`, as an ordinary sequence value; it is not a special
end marker.

### 4.2. Unknown and suspension

While a configured source reports `contextKnown: false`, the host dispatches no new unlock request
for affected work and performs no affected output or retained-capability use. An unlock request
already sent keeps its captured ownership through the gap.

A later known snapshot with the same revision resumes suspended work only when the source
association, the host's context generation and the output lifetime are all unchanged and the adapter
confirms continuity of the previously established context. Absence of an observed change is
insufficient. Startup unknown establishes no confirmed context; the host can wait to capture work
until known. Use a fresh revision on first confirmation when continuity is not established.

Unknown is uncertainty, not a signed-out reader. An SDK error or deadline does not establish
anonymity. An explicitly anonymous mode configures its own request credentials and isolated
retention.

### 4.3. Association, replacement and end

The host associates each source with the issuer routes, request credentials, retention and output
it governs. One association may cover several routes that share credentials. A delivery whose
routes authenticate differently associates each route with its own source. An unrelated source or
independently live context is not reset.

When the source is removed, restarted or replaced, the host retires the old association before
establishing the new one. A replacement that reports the same revision does not keep old work
eligible. When its observation service ends, the source sends each subscriber a final unknown
snapshot, with the next sequence, and stops. A producer MUST keep every nonterminal sequence
below `Number.MAX_SAFE_INTEGER`, so that one sequence is left for that final observation. Late
subscribers replay that final unknown and stop. This is an ordinary unknown observation, not a
separate end signal. The host still ends the association explicitly; a lost final snapshot never
keeps old work eligible. Stopping a subscription invalidates its consumer's pending work.

### 4.4. Limits of observation

A source reports the transitions its upstream service can observe. It cannot guarantee that ambient
request credentials, such as cookies, did not change between observations. The adapter states the
gap between an upstream transition and the credential change it can see. Request credential
ownership must agree with the captured context; the integration documents the limits of that
binding. For each adapter, document startup confirmation, ambiguous/error states,
observed transitions, detection delay and refresh triggers, cross-tab limits,
source replacement/end, cached bootstrap freshness, and captured versus ambient
credentials. State how the host treats unresolved uncertainty. If the SDK reports
the same state for an error and a sign-out, the adapter seeks an authoritative
check or reports unknown and records the limitation. No runtime limits schema
or persistent context-key agreement is added here; persistent partitions and
cross-tab coordination remain host responsibilities.

## 5. Content handler

### 5.1. Connection

A provider under `dca.content-handler` exposes `connect(setup) -> connection`. The setup binds one
captured delivery, an output-eligibility check and the destination or application callback for each
content name. The connection exposes `handleContent(map) -> Promise<outcomes>` and `dispose()`.

The setup is a plain object (an object literal or null-prototype record), with only:

```text
{
  delivery: { contentData: [{ contentName, contentType, ... }, ...], ... },
  isEligible: () -> boolean,
  targets: { [name]: callback },
  values?: { [name]: "bytes" | "strictUTF8" }
}
```

`delivery.contentData` is an admitted array of named item records; `targets` and supplied `values`
are plain records. Every target is callable;
each value-mode entry names a target. Omitted modes mean bytes. Setup errors throw synchronously.
The connection captures item types, callbacks and modes, so later caller mutation does not retarget
it. Missing/invalid item types remain an item refusal; the handler does not replace client admission.

A connection MUST remain bound to the captured delivery and logical-context/output ownership
established for that connection. Its `isEligible` predicate MUST check that captured ownership and
MUST NOT be redirected to successor work by changing a current-context reference. When that
ownership changes, the host MUST retire the old connection and create a new connection before
successor effects. The content-handler provider and host consumer MAY remain the same objects.

`handleContent` accepts a plain map of own enumerable names to `Uint8Array` values and copies bytes
before its first await. Invalid values refuse their own item. Invalid map admission or snapshotting,
including a throwing getter, rejects the promised result before callbacks run. A connection handles
submitted names one at a time; their order and unrelated diagnostic/refusal precedence are not
standardized. Disposal is idempotent, ends eligibility and releases bookkeeping.

The content handler owns its destinations. A content name is meaningful only within the captured
delivery: two deliveries that both name `bodytext` get distinct connections, and a page-wide table
of names must not retarget delayed output from one delivery to the other. Before a successor reuses
a destination, the host ends the predecessor's eligibility for it.

This contract concerns delivery-bound application effects. It does not standardize every pure
decoding or transformation function as a stateful content handler.

### 5.2. Values

Each input value is the item's bytes after any applicable content decoding. For a content name
configured as `strictUTF8`, the connection MUST decode the bytes as strict UTF-8 before the callback
runs and MUST refuse malformed UTF-8 before any effect. It MUST preserve a leading byte-order mark
as U+FEFF text rather than silently dropping it; the application's interpretation policy may handle
it explicitly. Other values stay bytes. This setting selects no media type, HTML execution or
schema fetch.

### 5.3. Outcomes

`handleContent` resolves one outcome `{ status, reason? }` for each submitted name:

- `handled`: the agreed application effect for that item completed.
- `refused`: no effect occurred for that item. Retrying may need changed setup.
- `failed`: effects for that item may be partial. No automatic retry follows.
- `stale`: the connection's work is retired, and the connection ends.

A missing destination before any effect yields `refused`. A refused or failed item does not change
its siblings' `handled` outcomes.

`reason` is an optional provider-defined diagnostic string. It is neither a portable access
decision nor a retry instruction. Generic callers branch on status.

### 5.4. Effects and eligibility

For each submitted item that reaches its configured callback, the content handler MUST supply a
record containing:

```text
{ contentName, contentType, value, commit }
commit(effect: () -> void) -> boolean
```

`contentType` is captured from the required item member. `value` is the decoded bytes or
strict UTF-8 text selected in setup. `commit` MUST check captured eligibility immediately before
one synchronous application effect. The callback MAY await preparation outside `commit`,
then call it for each effect. A synchronous callback's guard expires when it returns; an
asynchronous callback's guard expires when the connection observes its settlement.
`commit` returns false without invoking after expiry or retirement. The callback MUST
complete its agreed effects before settling; saving a guard or queueing work does not
extend this operation's lifetime.
An effect passed to `commit` MUST itself be synchronous; starting an asynchronous effect
violates this contract and cannot promise that later mutations are guarded.

The callback returns a handled, refused or failed outcome. Handled requires a completed
guarded effect. A refusal after an effect becomes failed. Lost eligibility retires the
connection and makes the in-flight item stale; already completed sibling outcomes remain
handled. Exceptions or malformed callback results fail that item.

`commit` MUST propagate an exception thrown by its effect. An effect that throws
fails that item even if the callback catches the exception and completes another
effect; the handler cannot establish that the earlier effect left no partial changes.

A callback outcome is a record with only `status` and optional string `reason`. A callback cannot
report `stale` itself. Eligibility MUST return true to permit an effect; false retires the connection.
A throwing eligibility check is an implementation failure: the current item is failed and the
connection retires, so subsequent items are stale. Failure does not assert that an effect occurred.
Eligibility is checked before invoking a callback, at each `commit`, at observed settlement and
before an identical repeat can report handled. Other incidental check ordering is unconstrained.
Disposal prevents later guarded effects but does not promptly settle an arbitrarily hung callback;
its caller may still be waiting for that callback.

`postMessage` enqueue supplies no receiver-side lifetime enforcement or completion acknowledgement;
cross-frame rendering needs a separate protocol, outside this same-realm handoff.

### 5.5. Repeats and overlap

Only one call may be active per connection. An overlapping call rejects before any effect. An
identical repeat of a handled name has no new effect and reports `handled`. Changed bytes for a
handled name are refused without effects. After `stale` or `dispose()`, every later call resolves
each submitted name `stale` without effects.

The caller continues by submitting only the remaining names. It may resubmit a refused name
explicitly. After a name fails, the connection MUST refuse another submission of that name without
invoking its callback. Before submitting that name on replacement work, the caller MUST reconcile
its possible partial effects. After `stale`, the caller reconciles earlier
effects and handled names before creating replacement handling, and submits
only the names that still need handling.

Whether to remove content already shown is the application's policy.

## 6. Failure and recovery

A failure is reported where it occurs. An item admission failure, a decoding, schema or
placement failure, a missing opened name or a handler `reason` is not a refusal of access; the
scoped issuer or opening result describes an unresolved coordinate. Item admission
([content protection Section 5.1](spec--content-protection.md#51-item-admission)) and content
transforms ([Section 8.1](spec--content-protection.md#81-ordered-representation-layers)) define the
client's item failures; Section 5.3 defines the handler outcomes.

Unsupported media handling or an unsupported application schema yields a handler
refusal before any effect and a failed item after an effect.

## 7. Companion account convention

The separately selected `dca-companion.account` provider has its own version and subscription.
Account hints stay separate from context revisions.

Its shared key uses the distinct `dca-companion.account` identifier and configured major/name;
custom interfaces use an owner-controlled identifier rather than claiming the `dca` or
`dca-companion` names. The provider exposes `subscribe(listener) -> stop` and nested `actions`:

```text
snapshot = {
  sequence, observedAt, validUntil, signedIn,
  actionReady: { signIn, signOut, openAccount }
}
actions = { signIn?, signOut?, openAccount? }
action() -> Promise<"started" | "unsupported" | "failed">
```

Snapshots have exactly those five own members; readiness has exactly the three boolean members.
Sequence and times are nonnegative safe integers, and `validUntil >= observedAt`. `signedIn` is
`yes`, `no` or `unknown`. Sequence, replay, ordering, stop, end and exception isolation follow the
context source (Sections 4.1 and 4.3); the final unknown has all actions unready and keeps the
original times. Times use the page's epoch-millisecond clock. A menu reads a hint only while
`observedAt <= now < validUntil`; future, expired or invalid clock readings are unknown. The menu recomputes
freshness on display, timer and resume. Expiry
produces unknown without an event, and replay does not refresh the original times. Missing or
failed observation is unknown, not signed out.

Unsupported actions are omitted. A menu enables a present action only with a fresh true readiness
observation. The method invokes upstream code synchronously before returning its promise;
exceptions, rejections or invalid upstream answers report failed. The menu invokes a
popup-sensitive action during the reader's click; it does not queue the click until the SDK becomes
ready. `started` is not a successful login. Readiness is independent of `signedIn`. Account
observations grant no entitlement and do not replace context transitions. A vendor-owned button
that cannot expose an initiation method is outside this convention unless an explicit adapter
supplies that contract.

A claim MUST NOT infer account identity or access authority from these observations.

## 8. Security considerations

Registry membership authenticates no provider and isolates no page script. A content handler
receives plaintext, and so does any substituted provider; same-page script access lies within the
[security model's](spec--security-model.md#what-dca-does-not-protect-against) accepted exposure.
Context retirement governs honest integration behavior; it cannot revoke delivered keys or copied
content. The issuer authorizes from verified resource claims and issuer-held policy, never from a
menu hint, a context snapshot or a handler outcome.

## 9. Conformance

The candidate depends only on `dca-profile-baseline`. It does not select browser-Origin
admission, HTML carriage, content-map placement, compression, period/chain keys or
client-bound responses. Those mechanisms retain their own selection and dependency rules.
A deployment would record `discovery` and `contextSource` selection for its
handling-integration scope; these declarations require no user-facing feature switches.

If adopted, the following conformance rules would apply. The candidate profile is not in the
current DCA profile catalogue. Prototype tests evaluate this proposal only.

The DCA profile catalogue defines only its existing DCA roles; this browser profile adds no host,
provider or consumer role. A claim to implement this profile is a baseline client claim together
with the applicable composed client-side integration duties in this document. It MUST identify
which optional registry, context-source and account-companion capabilities it supports or selects,
and MUST implement the duties attached to each declared selection: Section 3 for every registry
participant, Section 4 for the source provider, host and consumer, and Section 7 for the account
companion. A standalone claim for a registry, context-source or content-handler interface names
that interface and major only; it does not claim this browser profile, complete baseline-client
conformance or its host's compliance. A publisher and consumer claiming interoperable use MUST
select matching interface majors and agree on the application's handling of delivered values;
registry presence establishes no carrier, decoding or application handling.

The direct content-handler path is the required browser-integration capability; it needs no
registry, context-source object or account menu.

Support for an optional interface does not select its use. Registry and
context-source duties apply to an integration operation when that capability is
explicitly selected for its handling-integration scope. The account convention
is a separately selected companion.

## 10. Normative References

- [BCP 14](https://www.rfc-editor.org/info/bcp14): requirements language.
- [Core protocol](spec--core-protocol.md) and [profiles](spec--profiles.md): operative requirements.
- [Content protection](spec--content-protection.md): item admission and opening.
- [Security model](spec--security-model.md): trust and exposure boundaries.

## 11. Informative References

- [Deployment patterns](guide--deployment-patterns.md#client-context-lifetime): context lifetime.
- [Proposal evaluation guide](guide--browser-integration.md): rationale and illustrative use.
- [Content description and placement](spec-proposal--content-description-and-placement.md):
  information a consumer needs after opening.
