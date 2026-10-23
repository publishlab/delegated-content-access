# Proposal: protected-HTML content map

Status: Proposal
Target: [profile specification](spec--profiles.md)

## Abstract

This proposal defines a candidate optional `dca-profile-html-content-map` profile. A
publisher adds one content map to a locked HTML delivery. The map declares
rules that put opened items, using their existing item media types, into the
page. A browser client or a server-side client that selects the profile
rebuilds the same protected slots from the same locked delivery, without
publisher-specific script. The map grants no access and enters no
cryptographic transcript; DCA Core still treats item bytes as opaque and
still owns key acquisition.

## 1. Introduction

A DCA client ends content opening with authenticated octets for each item
([content protection §5.4](spec--content-protection.md#54-content-opening-and-containment)).
Without this profile, the publisher's own page code decides what those octets
are and where they go. That code serves one publisher's page in a browser. It
does not let an independent server-side client, such as a representation
gateway that returns HTML to a caller without DCA support, rebuild the page.

This profile expresses that decision as declarative data the publisher authors
with the page, so an independent client can reconstruct the page without running
publisher code. The ordinary browser integration keeps the content owner's
chosen handler; Section 2 gives each destination one placement owner.

The profile defines:

- the map carrier and the map grammar;
- item types, target selection and three placement operations;
- processing order, partial entitlement and failure states;
- the observations on which a browser and a server-side client agree; and
- the source provenance a server-side client needs before placing anything.

It does not define reader or bot identity, payment, cache routing, a
gateway's caller authorization, a gateway's HTTP response, or the execution
of page scripts. A deployment-specific page presenter remains valid outside
this profile but does not claim its interoperability.

The key words **MUST**, **MUST NOT**, **SHOULD** and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## 2. Profile and roles

`dca-profile-html-content-map` is an optional profile with the direct dependency
`dca-profile-html-carrier`. The identifier is a conformance name, not a DCA wire
value. A client claiming this profile MUST
support extraction from the HTML carrier. Carrying the optional map through
an object/API adapter does not remove that support duty or provide a host document.

The profile assigns duties to three roles:

- a **publisher** authors one map per locked HTML delivery;
- an explicitly selected **browser map client** places opened items into host-owned
  destinations reserved for that renderer; and
- a **server-side client** fetches a locked delivery, places opened items
  and emits the resulting HTML. A representation gateway is a deployment of
  this role.

The issuer has no duty under this profile. It receives an ordinary unlock
request and decides access as it does without the profile. A vendor may supply both
issuer and rendering components, but choosing one does not require choosing the other.
A browser integration MUST NOT run the map renderer and another content handler over
the same destinations as competing placement owners. The host selects one owner; it
MUST NOT silently fall back to map execution after its chosen handler refuses.

Selection follows the states of
[profiles §2](spec--profiles.md#2-mechanism-selection-states). The publisher
**authors** the map by emitting its carrier. The client's trusted deployment
configuration **selects** the profile, for example a gateway configured to
return reconstructed HTML. A map carrier on a page selects nothing by its
presence: a client that has not selected the profile ignores it, and a
client that has selected it requires it. The selection scope is one locked
delivery, and the client selects before it derives any unlock request for
that delivery.

## 3. Map carrier

`contentMap` is a declarative placement recipe: it names the protected item,
the destination and the operation to perform after that item opens successfully
and passes the selected renderer's interpretation and placement policy. It is
not executable publisher code and does not select a renderer by its presence.
An ordinary integration may instead supply destinations through its own handler
configuration; that integration needs no shared recipe.

A publisher selecting this profile MUST supply one optional own member named
`contentMap` in the delivery object. For HTML it is inside the existing
`script.dca-data` JSON value, under the element and serialization rules of
[data-format §3](spec--data-format.md#3-markup-delivery). The publisher combines
template-authored rules and sealer-authored item records before serializing
that delivery. `contentMap` is not sent to an issuer.

```json
{
  "contentMap": {
    "version": "1",
    "rules": [
      { "item": "bodytext", "op": "fill", "target": "#article-body" },
      { "item": "bodytext", "op": "remove", "target": "#subscribe-prompt" }
    ]
  }
}
```

In this recipe, successful handling of `bodytext` fills `#article-body` and
removes `#subscribe-prompt`. The recipe does not replace key acquisition or
renderer policy. [Section 6](#6-processing) specifies operation sequencing,
completion and placement failures, including its lack of a rollback guarantee.

This is a member excerpt, not a complete delivery. The full delivery still
has its required `version`, `resourceJWT`, `contentData` and `issuerData`.
The containing object associates the map with that delivery; nesting adds no
authentication. An object/API delivery carries the same member unchanged.
Its adapter MUST supply the HTML document and delivery from the same admitted
source response before reconstruction. A map without that document is data
to carry, not a runnable reconstruction or a JSON placement map.

A selected client reports `map_absent` for an absent member and `map_malformed`
for a non-object member. A separate `dca-content-map` element is not an
alternative carrier: a selected client MUST refuse a document
containing that class token with `map_malformed`, including when the embedded
member is present. There is no precedence or merge rule. A base client ignores
the optional member under the ordinary unknown-member rules.

## 4. Map object

### 4.1. Members

The map is a JSON object. The common JSON and own-member rules of
[data-format §2](spec--data-format.md#2-common-json-rules) apply, including
its duplicate-member rule.

Unlike base objects, a version-1 map or rule with an unknown member is
`map_malformed`. A client MUST NOT skip an unknown operation or field and
claim reconstructed content. Another grammar uses another `version` value.

The map object has exactly these members:

- `version`: a string, exactly `"1"`; and
- `rules`: a non-empty array of rule objects.

A `version` value other than `"1"` is `map_version_unsupported`. A missing
member or a member of the wrong type is `map_malformed`.

The version applies to the map grammar and behavior independently of the
delivery version and any `contentDescription.version`. There is no type
table. The mapped-item set is the distinct `item` strings in `rules`.

Each rule is an object with these members:

- `item`: a string satisfying the `contentName` grammar of data-format Section 2.1;
- `op`: the string `"fill"`, `"remove"` or `"removeClass"`;
- `target`: a selector string under [Section 5.1](#51-selector-grammar); and
- `class`: a string holding one `ident` under Section 5.1, present exactly
  when `op` is `"removeClass"`.

A rule whose `item` violates that grammar, whose `op` has another value, or
whose `class` is absent, present for another operation or not an `ident` is
`map_malformed`.

### 4.2. Item admission

Every mapped item MUST be read by at least one `fill` rule. A `remove` or
`removeClass` rule gates on an item that some `fill` rule also places; an
item used only as a gate would open, place nothing and count toward
`complete`. A violation is `map_malformed`.

Every mapped item MUST name an item that `contentData` declares; otherwise
`map_item_undeclared`. The delivery MUST carry that item's ciphertext in
`dca-sealed-content` (or its object-adapter `sealedContent`); otherwise
`map_item_no_ciphertext`. A map that points
at an item the render did not deliver is a defective render, not partial
entitlement.

An item that `contentData` declares and the map does not name is outside this
profile. The client MAY open it and hand it to a host as it would without the
profile. Nothing in this profile applies to that host's handling.

### 4.3. Types

The client MUST read the required `contentType` from the `contentData` record
whose `contentName` names the mapped item.
Its value MUST be exactly `"text/html"` or `"text/plain"`, with no parameters
or case variation; another string produces `map_type_unsupported`. A malformed
required item record is an item failure and never supplies placeable bytes.
Neither a map nor a description supplies an alternative media type.

Both types are UTF-8 text. After opening, and after reversing any
`contentEncodings` ([content protection §8](spec--content-protection.md#8-content-representations-and-extension-profiles)),
the client MUST decode the octets with
[UTF-8 decode without BOM or fail](https://encoding.spec.whatwg.org/#utf-8-decode-without-bom-or-fail).
A malformed sequence is an item failure. Octets that begin with `EF BB BF` are
also an item failure, because engines disagree on whether to strip a byte
order mark.

- `text/html` is an HTML fragment, parsed in its target's context.
- `text/plain` is character data placed as one text node.

An item that a host consumes as data, such as JSON, is not a map item.

## 5. Targets

### 5.1. Selector grammar

A `target` is one selector from this subset of
[Selectors Level 4](https://www.w3.org/TR/selectors-4/), in ASCII:

```text
selector    = compound *( combinator compound )
combinator  = 1*SP / *SP ">" *SP
compound    = type-name *qualifier / 1*qualifier
qualifier   = "#" ident / "." ident / "[" attr-name [ "=" dq-string ] "]"
type-name   = LOWER *( LOWER / DIGIT / "-" )
attr-name   = "slot" / "itemprop" / "role" / data-name
data-name   = "data-" 1*( LOWER / DIGIT / "-" )
ident       = [ "-" ] ( ALPHA / "_" ) *( ALPHA / DIGIT / "_" / "-" )
dq-string   = DQUOTE *( %x20-21 / %x23-5B / %x5D-7E ) DQUOTE
LOWER       = %x61-7A
```

`SP`, `ALPHA`, `DIGIT` and `DQUOTE` are the ABNF core rules of
[RFC 5234](https://www.rfc-editor.org/rfc/rfc5234). A selector has no leading
or trailing space. A value outside this grammar is
`map_selector_unsupported`.

The grammar excludes selector lists, the universal selector,
pseudo-classes, pseudo-elements, namespaces, sibling combinators, attribute
operators other than `=`, attribute flags, escapes and non-ASCII names. A
multi-placement uses one rule per target. The attribute names are closed.
HTML compares the values of another set of attributes ASCII-case-insensitively
in selectors, among them `type`, `lang` and `rel`
([HTML, case-sensitivity of
selectors](https://html.spec.whatwg.org/multipage/semantics-other.html#case-sensitivity-of-selectors)).
The listed names are outside that set, so an attribute value always compares
byte for byte.

### 5.2. Locked document

A client reading source octets MUST refuse invalid UTF-8 with `source_refused`.
The client MUST parse the locked delivery with the
[HTML parsing algorithm](https://html.spec.whatwg.org/multipage/parsing.html)
with the scripting flag set, as a browser does for a page with scripting
enabled. A document in quirks mode is `map_document_quirks`, because there
class and id selectors match case-insensitively. Limited-quirks mode matches
as no-quirks mode does and is admitted. A publisher SHOULD begin the document
with `<!DOCTYPE html>`.

A browser integration MUST provide a stable publisher-delivered document for
target admission. It captures the target identities, paths and relevant content
and attributes before key acquisition. Application changes are not silently
treated as a new source document during the run; Section 6.3 defines stale-target
refusal. The HTML source and mapped text MUST be UTF-8. A server-side client
MUST obtain the final source response with a valid `Content-Type: text/html`
field containing exactly one unambiguous charset parameter naming UTF-8
(case-insensitive `utf-8` or `utf8`). Missing, repeated or conflicting charset
parameters, another media type or another charset are `source_refused`.
It MUST refuse a UTF-16 BOM, consume at most one initial UTF-8 BOM, and
fatal-decode the remaining source as UTF-8 rather than replacement-decode it.
The admitted transport charset establishes the source encoding; in-document
`meta` declarations do not independently affect admission. This server contract
requires HTTP metadata, rather than HTML encoding sniffing or locale guessing.
A host serving reconstructed HTML MUST also supply `text/html; charset=utf-8`.
A browser map client MUST reject a document whose selected `characterSet` is not
UTF-8 before map execution. Its already-decoded DOM cannot establish whether the
original octets contained malformed sequences; source-octet validation belongs to
the source-reading adapter, while the publisher and browser host are responsible
for providing a UTF-8 delivery. The browser client need not refetch the document.

### 5.3. Matching

The client MUST resolve every rule's target once, on the locked document,
before it applies any rule and before it sends any unlock request. Each
selector MUST match exactly one element of the document tree; zero or more
than one is `map_target_count`. No rule is optional. Elements in a `template`
element's contents are not in the document tree.

The resolved targets MUST satisfy all of these, or the client refuses the
delivery with the code shown:

- **Disjoint tree changes** (`map_target_overlap`). No element is the target
  of two `fill` or `remove` rules, and no `fill` or `remove` target is an
  ancestor of another.
- **Class changes on surviving elements** (`map_target_overlap`). A
  `removeClass` target is not a descendant of a `fill` target, and is neither
  a `remove` target nor a descendant of one. It MAY be a `fill` target or an
  ancestor of one. One element and class token pair appears in at most one
  rule.
- **Placeable** (`map_target_unplaceable`). Every target is an element in the
  HTML namespace that is not a descendant of a `select`, `datalist` or
  `noscript` element. A `fill` or `remove` target is not `html`, `head` or
  `body`. A `fill` target is also not:
  - a [void element](https://html.spec.whatwg.org/multipage/syntax.html#void-elements)
    or `template`;
  - a raw text or escapable raw text element, or `xmp`, `iframe`, `noembed`,
    `noframes`, `plaintext` or `noscript`, whose content the parser reads as
    text; or
  - `table`, `thead`, `tbody`, `tfoot`, `tr`, `colgroup`, `select`, `option`,
    `optgroup` or `datalist`, whose parsing contexts differ between current
    engines.
- **Carriers untouched** (`map_target_carrier`). No `fill` or `remove` target
  is or contains a `dca-data` or `dca-sealed-content`
  element. A `removeClass` target MAY contain one; `body` always does.
- **Class present** (`map_class_absent`). The token a `removeClass` rule names
  is present in its target's `class` attribute in the locked document.

Because targets are fixed on the locked document, tree changes are disjoint
and class changes touch only surviving elements, the rules commute. No rule
can match content another rule inserted.

### 5.4. Limits

A client MUST enforce and disclose finite limits on the delivery's octet length, the
number of rules, each selector's length and number of compounds, and the size
of the locked document it parses. Exceeding one is `map_limit`. The limits
are implementation or deployment choices and must be recorded in interoperability
evidence. A fetcher MUST enforce its input bound while reading the response,
before buffering unbounded input. A server-side client runs this
admission on a page from any origin its source policy admits, before any
issuer contact, so the limits bound the work such a page can cause.

## 6. Processing

### 6.1. Order

A client that selected the profile processes one locked delivery in this
order:

1. For a server-side client, obtain the delivery and verify its publisher
   assertion under [Section 8](#8-server-side-source-provenance).
2. Parse the document and apply the base structural processing of
   [data-format §7](spec--data-format.md#7-structural-processing).
3. Read `contentMap`, admit the map object under Section 4, and resolve
   and admit every target under Section 5.
4. Obtain keys for the map items under the core protocol and any selected
   key-acquisition profile, and open each item under content protection.
5. Decode each opened map item under Section 4.3, prepare its fills, and apply
   its rules under Section 6.3. Record item placement completion separately
   from key acquisition and opening.
6. Return the document, source URL and report; retain the map and per-item
   completion state in this live reconstruction session under Section 6.5.

A failure in steps 1 to 3 is a **map failure**. On a map failure the client
MUST NOT send an unlock request for the delivery under this profile, MUST NOT
emit a reconstructed document, and MUST report outcome `failed` with the
failure code. A failure of the base structural processing in step 2 uses
`delivery_refused`; a client MUST NOT expose its implementation-specific
base parser error code as the profile report code. It MAY return the locked
document unchanged, marked as not reconstructed. A delivery refused before
key acquisition therefore spends no issuer decision or meter.

Opening the same delivery afterwards without this profile is a separate run.
Its host types opened octets from its own knowledge, and it claims nothing
under this profile.

### 6.2. Item states

After the selected key-acquisition attempts for a delivery finish, each map
item ends in exactly one observable state:

- `opened`: the item opened and decoded;
- `locked`: key acquisition completed without a key that opens the item, and
  its rules leave the locked targets in place; or
- `failed`: the delivery is defective, through an item record failure, an
  AEAD failure, a representation failure or text that does not decode.

`locked` states no cause: core Section 7.1 and period keys Section 5.6 give no item-level reason,
and a family report does not decide an independent item path. The profile
therefore MUST NOT turn an omitted key,
silent family or whole-request refusal into an item-level policy or
availability claim. A consumer that caches a reconstructed page MUST use
its own caller and entitlement context; `locked` is not proof of denial.

### 6.3. Operations

A rule applies only when its item is `opened`. A rule whose item is in any
other state changes nothing: the locked target keeps its teaser, a gated
element stays, and a lock class stays. The map is the same for every reader,
and partial entitlement needs no rule of its own.

- **`fill`** replaces all children of the target. For `text/html`, the client
  parses the decoded string with the
  [HTML fragment parsing algorithm](https://html.spec.whatwg.org/multipage/parsing.html#parsing-html-fragments),
  with the target as the context element and the scripting flag set, and
  appends the resulting nodes, as the `innerHTML` setter does. For
  `text/plain`, it appends one text node whose data is the decoded string, as
  the `textContent` setter does; an empty string leaves no children.
- **`remove`** removes the target and its subtree from the document.
- **`removeClass`** removes the named token from the target's `class`
  attribute with the
  [`DOMTokenList`](https://dom.spec.whatwg.org/#interface-domtokenlist)
  `remove` steps: the value becomes the remaining tokens as an ordered set,
  without duplicates, joined by single spaces.

For each newly opened item, the client MUST complete all of its fills before
removing its prompts or lock classes. If a fill cannot be prepared under the host's
rendering policy, those prompts and locks MUST remain. Implementations may prepare
fragments on a detached tree or use another strategy with these observable guarantees;
this profile prescribes no DOM transaction mechanism or framework architecture.

The client MUST place into the targets admitted before acquisition, accounting for
its own earlier fills and removals. A changed or replaced target produces
`map_target_stale`; the client MUST NOT resolve the selector again and silently
place into a replacement. An integration unable to maintain that placement boundary
MUST refuse with `map_placement_refused`. This duty applies when the host selects
map execution, not to every browser content handler.

The browser host MUST retire pending placement when the captured article or
logical client context ends. The client MUST check that lifetime at each live
effect, including after asynchronous work and synchronous host callbacks.
Unrelated content or attribute changes caused during placement MUST NOT be
absorbed as the client's own expected output. A stale lifetime or destination
produces `map_target_stale`; this does not require rollback of effects already made.

A CSP, Trusted Types, parsing or DOM-operation refusal MUST yield
`map_placement_refused`, never an unreported exception or `complete`. The
integration uses a policy authorized by its host; it MUST NOT install a
permissive policy to get around a refusal. If a failure occurs after live
mutations began, the client reports failure and MUST NOT export a claimed
reconstruction. It need not claim rollback of browser side effects. The host
discards or reloads that failed view before a new attempt. Server clients
prepare a detached result and publish it only after successful placement.

A browser client that inserts a fragment through the `innerHTML` setter does
not run a `script` element inside it. Event handler attributes in the
fragment behave as they would on the full page.

### 6.4. Report

The client reports one outcome:

- `complete`: every mapped item is `opened` and every rule applied;
- `partial`: at least one mapped item is `locked`, no item failed, and every
  opened item's rules applied; or
- `failed`: an item failure or a Section 9 failure. No reconstructed document
  is claimed, even if some earlier live mutations succeeded.

A `partial` document is a valid profile output only together with its report.
A conformance run records the report in this form; it is not a DCA wire
member:

```text
{ "outcome": "partial",
  "items": { "bodytext": "locked", "factbox": "opened" } }
{ "outcome": "failed", "failure": "map_target_count" }
{ "outcome": "failed", "failure": "item_failed",
  "items": { "bodytext": "failed", "factbox": "opened" } }
```

For `complete` or `partial`, `items` contains exactly the mapped-item set.
For `failed`, `failure` is required and `items` is optional; if present it
contains only known item states. A well-formed issuer refusal or omitted key
can leave an item `locked`. An aborted acquisition, an unclassified transport
exception, or an observable `5xx` that still leaves a required item unresolved
after the configured fallback attempts is `key_acquisition_failed`, not
`locked`; an earlier failure that fallback or cached keys resolve fails nothing.
A failed report MUST NOT list speculative item states
seeded before acquisition; it may retain states established independently.

### 6.5. Continuation and export

The live client MUST NOT remove the map as its completion signal. A later
attempt in the
same session handles only items still locked; completed placements are not
repeated and their original lock-class preconditions are not checked again.
The integration MUST reuse this session when it rediscovers that delivery.
A replaced source document or failed session requires fresh admission of a
fresh locked delivery.

An exported result MUST be distinguishable from a locked DCA delivery and carry
its source URL and report. Its packaging is an integration choice: a document object,
an HTML response with associated metadata, or a JSON record can satisfy this duty.
The report describes application output, not an issuer response or an
authenticated publisher claim. The receiving integration MUST treat it as a terminal
snapshot, including a partial snapshot. It MUST NOT start a fresh unlock merely
because original `dca-data` or ciphertext remains inside the HTML. To continue after
export, retrieve a fresh locked delivery and begin a new session. A service serving
raw HTML establishes resolved-output mode through its host integration and prevents
automatic DCA initialization. There is no generic script-removal or script-activation
algorithm in this profile.

Before returning or serializing a successful result, the client MUST validate
that the document being handed off still represents the reported placement and
capture that document with its report as one consistent result. This check includes
completed fills, removed targets, class effects and unaffected source content.
An out-of-session mutation produces `map_target_stale`; a retained successful
report MUST NOT be attached to a subsequently changed document. Alternatively,
the client MAY export a frozen snapshot captured at a previously successful
check, with that snapshot's own report. A live document reference is valid only
at its checked handoff; a later export needs this same check or frozen snapshot.

## 7. Output and observations

### 7.1. Delivered form

A server-side client emits its document serialized with the
[HTML fragment serialization algorithm](https://html.spec.whatwg.org/multipage/parsing.html#serialising-html-fragments)
applied to the document. That algorithm writes a carriage return unescaped,
and the receiving parser turns it into a line feed, as a browser's own round
trip does; a serializer that writes `&#13;` keeps the carriage return and
changes the text.

The **delivered form** of a result is the tree that the HTML parsing
algorithm, with the scripting flag set, builds from that serialization. The
profile's result is the delivered form, for browser and server-side clients
alike. Some trees that the `innerHTML` setter builds have no serialization
that parses back to them: `<div>x</div>` filled into a `p` element gives a
`div` inside the `p` in a live DOM, and the serialized page parses as an
empty `p`, the `div` and another empty `p`.

Define normalization `N` as one HTML serialization and document parse with
the scripting flag set. Apply `N` to both the logical reconstructed tree and
the unchanged source used for comparison. It accounts for representation
effects such as CR-to-LF normalization in both HTML and plain-text fills;
these effects do not authorize unrelated DOM edits.

A publisher claiming this profile MUST check each authored fill, including
plain text, in its actual target context. After text line-ending normalization,
the live placed tree and delivered form MUST agree structurally. A block
fragment belongs in a `div`, `section` or `article` target, not a `p`. A client
that detects a violated stability precondition reports `map_output_unstable`;
passing client admission alone never proves the publisher's author-time duty.

### 7.2. Observations

Two implementations produce the same result when these observations of their
delivered forms are equal:

1. the report outcome and item states of Section 6.4; for refused inputs,
   any applicable Section 9 code is accepted rather than imposing validator order;
2. for each rule, its target, identified by the path of element-child
   indexes from the document element in the locked document;
3. for each applied `fill`, the target's child tree: for each node its kind,
   an element's local name and namespace, its attributes as a set of
   name-value pairs, and text and comment data;
4. for each applied `removeClass`, the target's `class` value;
5. for each applied `remove`, the absence of the target; and
6. every unaffected node compared with `N` of the locked input, rather than
   with an unnormalized live tree. The map and original carriers may remain.

Serialization octets and attribute order are not observations. Script
execution is not an observation. A server-side client's output runs a `script`
element inside a filled fragment when a browser loads it, which a browser
client's insertion does not; a publisher claiming this profile does not rely
on a `script` element inside protected HTML.

### 7.3. Source URL and serving

The result retains the final source URL under Section 6.5. Relative URLs keep
their meaning under that document URL and any publisher-authored `base` element
([HTML document base URLs](https://html.spec.whatwg.org/multipage/urls-and-fetching.html#document-base-urls)).
A host presenting the output elsewhere MUST preserve that meaning, or identify
its rewritten output as an adapted representation outside the equality claim.
Adding a `base` element alone is not a complete adaptation contract for scripts,
CSS, fragments and application behavior. The associated source URL supplies context;
it does not implement a gateway, URL rewriter or serving policy.

## 8. Server-side source provenance

For a client selecting reconstruction, the map supplies the publisher's placement
instructions. In a browser it arrives with
the page from the publisher's origin, the same authority that serves the
page's markup and scripts. A server-side client's output can reach other
readers and caches, so the client MUST establish that the map came from the
publisher before it places anything.

Two attacks show why. A caller submits its own HTML carrying a genuine
`resourceJWT`, `dca-data` and ciphertext copied from a real article plus its own
map; the issuer grants the identical key request, and a gateway caching under
the article URL serves every later reader the caller's page around the
publisher's content (items 1 to 3 stop this). Or a caller names a page on its
own origin with an unsigned token claiming that origin and wraps copied from a
real article; the fetched origin equals the claimed origin and a gateway's
cached period key opens the wraps with no issuer contact (item 4 stops this).

A server-side client MUST:

1. select the source URL under trusted publisher-source configuration. A
   caller MAY name a URL; the configuration decides whether it is admitted;
2. fetch the locked delivery itself over HTTPS and admit each redirect under
   the same source policy, refusing any redirect to a URL the policy does not
   admit or to a scheme other than `https`; admit the final response's media
   type, UTF-8 charset and source bytes under Section 5.2;
3. never treat caller-submitted HTML as the delivery or the map;
4. verify the delivery's `resourceJWT` under trusted publisher-registration
   verification keys, as
   [core §4.2](spec--core-protocol.md#42-verification-and-registration)
   defines verification, and require the final URL's origin to equal the
   verified `origin` claim, before it places any item. The verification is
   required even when a cached or derived capability opens the item without
   issuer contact
   ([content protection §5.2](spec--content-protection.md#52-resolving-a-content-key));
5. read the map, `dca-data` and ciphertext from that one response; and
6. attribute and cache a reconstruction only under the fetched final URL,
   never under an identity read from the page, such as `resourceId`,
   `renderId` or a canonical link.

A failure of items 1, 2 or 4 is the map failure `source_refused`.

The client MUST select each issuer endpoint from trusted deployment
configuration, scoped to the admitted publisher and issuer alias, as
[HTTPS binding Section 3.1](spec--http-binding.md#31-endpoint-and-channel)
requires. It MUST ignore any carried `unlockUrl`; that field cannot select a
route and does not itself cause a refusal. A configured endpoint that trusted
route policy refuses is `source_refused` before issuer contact. A missing route
sends no request for that issuer and does not refuse an item that a held
capability can open ([core Section 9](spec--core-protocol.md#9-delegation-completeness)).
Before signing with a new publisher key, the publisher MUST ensure every
participating verifier, including a server gateway, has its active verification
entry and trusted registration mapping.

The host MUST assign an admitted logical client context before using any cached
capability or opened output, and enforce its release policy for every recipient
of the result. Ordinary setup is one configured trusted client context. A
multi-caller host must independently admit each caller and isolate mutually
untrusted contexts; a caller-provided cache label alone is not admission. It
may use issuer-recognized caller credentials or its own explicit authorization
policy, but this profile defines neither scheme and promises no per-reader
entitlement from cache partitioning. If the host cannot supply that boundary,
it MUST refuse the operation with `source_refused`.

A server-side client MUST keep each cached capability within its ordinary
scope ([period keys](spec-profile--period-keys.md)): its publisher, family and
coordinate, and the logical client context of the caller that obtained it.
Origin equality alone does not partition capabilities between registered
publishers that serve from one origin. A capability obtained for one caller
MUST NOT open an item for another caller whose context is mutually untrusted.

With these rules, a placed item came from a page served over HTTPS by the
origin the publisher signed, and the publisher is trusted
([security model](spec--security-model.md#trust-assumptions)). Placement
provenance is per origin, not per article: on an origin that hosts several
tenants, or pages whose HTML users write, any page can carry a copied
delivery with its own map, and the client accepts it for that page's URL.
Such an origin is one placement authority, as it is one origin for the
browser-origin check. The final-URL cache identity keeps that result on the
page that carried it.

This profile does not claim reconstruction of a delivery served from an
origin other than the one the publisher signed, such as a syndication
partner, an archive or a mail copy. Such a claim needs a publisher-signed
binding of the map, which this profile does not define.

## 9. Failure codes

Failures end the run. Admission failures prevent issuer contact under Section 6.1;
failures discovered after opening or during placement prevent a successful output
claim but do not undo a grant already made:

- `source_refused`: a server-side source, redirect, assertion or origin check
  of Section 8 failed.
- `delivery_refused`: the base structural processing of Section 6.1 step 2
  refused the locked delivery.
- `map_absent`: no `contentMap` member.
- `map_malformed`: carrier, JSON, member, rejected duplicate-name, rule or item-use
  violation.
- `map_limit`: a Section 5.4 limit exceeded.
- `map_version_unsupported`: `version` other than `"1"`.
- `map_type_unsupported`: an item type other than the two defined.
- `map_item_undeclared`: a map item absent from `contentData`.
- `map_item_no_ciphertext`: a map item without ciphertext in the delivery.
- `map_selector_unsupported`: a target outside the Section 5.1 grammar.
- `map_document_quirks`: the locked document is in quirks mode.
- `map_target_count`: a target matching zero or several elements.
- `map_target_overlap`: a Section 5.3 overlap rule violated.
- `map_target_unplaceable`: a target outside the placeable set.
- `map_target_carrier`: a `fill` or `remove` target that is or contains a
  carrier.
- `map_class_absent`: a `removeClass` token absent from its target.
- `map_target_stale`: an admitted target or document changed before placement.
- `map_placement_refused`: the host policy or commit operation refused placement.
- `map_output_unstable`: a detected live/delivered-form stability violation.
- `key_acquisition_failed`: key acquisition did not complete under its selected contract.
- `item_failed`: a mapped item failed record admission, authenticated opening,
  inverse representation processing or text decoding.

When several checks fail, a client MAY report any one of them.

## 10. Item-record `contentType`

The required item-record `contentType` is the sole media-type declaration.
The profile consumes it after successful content opening and inverse transforms;
it does not suspend or override the base field. A publisher MUST NOT put a second
type table in `contentMap`. Optional `contentDescription` supplies application
meaning under its own contract and cannot change the media type. An HTML map
needs no description or schema lookup to place `text/html` or `text/plain`.

## 11. Composition

- **Period keys, chain keys, client-bound custody.** These change how a
  client obtains keys. The map changes no key derivation or cryptographic
  transcript. Source checks, logical-client isolation and capability scope still
  apply when cached or derived keys avoid an issuer request.
- **Browser origin.** A browser client composes without interaction. A
  server-side client is not a browser and cannot present an honest `Origin`.
  On a route that selects browser-origin admission it needs the separate
  authenticated binding that the
  [security model](spec--security-model.md#enforcement-boundary) requires for
  non-browser callers; this profile does not define it.
- **Content representations.** The item-record type describes the octets after the
  client reverses `contentEncodings`. An item places only after complete
  inverse processing, so a represented or partial form never reaches a
  target.

A delivery without `contentMap` is a base delivery, and a client that has
not selected the profile opens it as before. The profile removes no base
route.

## 12. Conformance

### 12.1. Claims

A claim names its roles:

- A publisher claims that its maps pass Sections 3 to 5 against its own
  locked deliveries, that all mapped items meet the Section 7.1 duty,
  and that it meets the Section 10 duty.
- A browser client claims Sections 3 to 7 and 9 to 11.
- A server-side client claims Sections 3 to 11.

A claim records the requested and resolved profiles under
[profiles §2.1](spec--profiles.md#21-practical-selection-scopes), and the
oracle version its evidence came from. The claim does not cover script
execution, gateway caller authorization, a gateway's HTTP response or
off-origin reconstruction.

### 12.2. Oracle

A server-side implementation run on the same delivery with the same fixture
issuer decisions MUST produce the Section 7.2 observations that a browser
produces from that delivery with no page script running. Evidence records the
browser and version. The [extension
README](../js/extensions/html-content-map/README.md) describes the reference
oracle.

### 12.3. Example: multi-placement

A locked delivery declares `bodytext` and `factbox` in `contentData` and
carries both ciphertexts. Its body contains, among other markup:

```html
<body class="article blur-content">
  <div class="paywallTeaser">Subscribe to read on</div>
  <section class="main" id="main">
    <div class="bodytext lab-paywall-locked teaserContent">
      <p>The first lines of the story…</p>
    </div>
    <div id="factbox-inline"></div>
  </section>
  <aside><div id="factbox-aside"></div></aside>
</body>
```

Both items declare `contentType: "text/html"` in `contentData`. The following
member is inside the same delivery's `dca-data` object:

```json
{
  "contentMap": {
    "version": "1",
    "rules": [
      { "item": "bodytext", "op": "fill", "target": "#main .bodytext" },
      { "item": "bodytext", "op": "removeClass", "target": "#main .bodytext",
        "class": "lab-paywall-locked" },
      { "item": "bodytext", "op": "removeClass", "target": "#main .bodytext",
        "class": "teaserContent" },
      { "item": "bodytext", "op": "removeClass", "target": "body",
        "class": "blur-content" },
      { "item": "bodytext", "op": "remove", "target": ".paywallTeaser" },
      { "item": "factbox", "op": "fill", "target": "#factbox-inline" },
      { "item": "factbox", "op": "fill", "target": "#factbox-aside" }
    ]
  }
}
```

`factbox` fills two targets. Each selector matches one element, the two
`fill` targets of `factbox` are disjoint, and the `removeClass` target `body`
contains the carriers, which Section 5.3 permits.

When the issuer grants both items, every client reports `complete`. The
observations show:

- `#main .bodytext` holding the full body and the class value `bodytext`;
- `body` with the class value `article`;
- no `.paywallTeaser` element; and
- equal child trees in `#factbox-inline` and `#factbox-aside`.

When the issuer grants `factbox` and does not deliver a key that opens
`bodytext`, every client reports `partial` with `bodytext` `locked`, whether
the issuer named a reason or stayed silent. The body element keeps its teaser
and both lock tokens, `body` keeps `blur-content`, the prompt stays, and both
factbox targets are filled.

### 12.4. Example: fatal cardinality

A second template for the same article prints nested body elements:

```html
<section class="main" id="main">
  <div class="bodytext">
    <div class="bodytext intro"><p>The first lines…</p></div>
    <div class="bodytext content-text"></div>
  </div>
</section>
```

With the map of Section 12.3, `#main .bodytext` matches three elements. Every
client reports `failed` with `map_target_count`, emits no reconstructed
document and sends no unlock request. Without this refusal a client would put
the paid body into whichever match its engine lists first.

## 13. Security considerations

The map grants nothing. It names which items a client requests and where
opened items go. Client relay selection is not authorization, and the issuer
decides every grant from verified claims and its own state
([security model](spec--security-model.md#enforcement-boundary)). A reader
who edits the map in its own browser misplaces content in its own view.

Content AAD binds render ID and item name; it does not authenticate
`contentType`, encodings, the map or page placement ([content protection §9](spec--content-protection.md#9-security-considerations)).
A browser client places items on the authority of the page's origin. Anyone
who can change the map in a delivered page can inject markup into it. Under a
policy that blocks inline script that may be only an inert JSON block, but the
same injection can already deface the page. A server-side client places
items on the authority established under Section 8.

A server-side client's output contains publisher markup and scripts. Serving
it from any origin other than the publisher's gives that content the serving
origin's authority: its cookies, storage and same-origin access. A
server-side client MUST NOT serve the output from an origin whose state or
same-origin access it has to protect from publisher content, unless it
isolates the output, for example with `Content-Security-Policy: sandbox`.
Script execution and caller authorization stay outside the placement claim.

## 14. Normative references

- [BCP 14: RFC 2119 and RFC 8174](https://www.rfc-editor.org/info/bcp14)
- [RFC 5234: ABNF](https://www.rfc-editor.org/rfc/rfc5234)
- [RFC 8259: JSON](https://www.rfc-editor.org/rfc/rfc8259)
- [HTML Standard](https://html.spec.whatwg.org/multipage/)
- [DOM Standard](https://dom.spec.whatwg.org/)
- [Encoding Standard](https://encoding.spec.whatwg.org/)
- [Selectors Level 4](https://www.w3.org/TR/selectors-4/)
- [DCA core protocol](spec--core-protocol.md)
- [DCA data format](spec--data-format.md)
- [DCA content protection](spec--content-protection.md)
- [DCA period-key capabilities](spec-profile--period-keys.md)
- [DCA conformance profiles](spec--profiles.md)
- [DCA security model](spec--security-model.md)

## 15. Informative references

- [DCA browser opened-content presentation](guide--browser-content-presentation.md)
- [DCA HTTPS endpoint binding](spec--http-binding.md)
